/**
 * Multi-framework ("schema 2") behaviour of the Action: ruleset retrieval with
 * fallback to an old server, independent per-framework scanning, `fail-on`,
 * advisory check runs, and the verdict post (schema 2 with a legacy fallback).
 *
 * The fallback tests are the point of the file: this Action runs against
 * PRODUCTION edge functions that may not have been redeployed yet (our own PR CI
 * does exactly that), and an old Action must keep working against a new server.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchRulesets, RulesetFetchError } from '../ruleset.js';
import { DEFAULT_FRAMEWORK, FRAMEWORK_INFO, FRAMEWORKS, POST_LIMITS, parseFailOn } from '../frameworks.js';
import { scanFrameworks, failingFrameworks, primaryOutcome } from '../orchestrate.js';
import { buildLegacyPayload, buildSchema2Payload, postResults } from '../report.js';
import { buildSummary, checkRunConclusion, publishCheckRun } from '../checkRun.js';
import type { FrameworkRuleset, Rule, ScanResult } from '../types.js';

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);
const EMPTY_ALLOWLIST = { emails: [], names: [], domains: [], ip_ranges: [], ibans: [] };
const EMPTY_SIGNATURES = { 'telemetry-sdks': [], 'pii-datastore-credentials': [], 'processor-jurisdiction': [] };

const iban = (): Rule => ({
  id: 'dc-pii-iban', name: 'IBAN', gdpr_article: ['Art 32'], action: 'block', tier: 1,
  detect: { method: 'checksum', target: 'diff', diff_side: 'added', validator: ['iban'], mask: 'IBAN (masked)' },
});

const aiRule = (over: Partial<Rule> = {}): Rule => ({
  id: 'eaa-ci-endpoint', name: 'Hosted model endpoint', articles: ['Art. 15'], relevance: ['control'], action: 'review', tier: 2,
  detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: 'api\\.openai\\.com', mask: 'Model endpoint' },
  ...over,
});

const dcRuleset = (rules: Rule[] = [iban()]): FrameworkRuleset => ({
  framework: 'Data Compliance', ruleset_version: 3, ruleset_hash: HASH_A, rules,
  allowlist: EMPTY_ALLOWLIST, signatures: EMPTY_SIGNATURES, dropped_rules: [],
});
const aiRuleset = (rules: Rule[] = [aiRule()]): FrameworkRuleset => ({
  framework: 'EU AI Act', ruleset_version: 1, ruleset_hash: HASH_B, rules,
  allowlist: EMPTY_ALLOWLIST, signatures: {}, dropped_rules: [],
});

const diffOf = (...added: string[]) =>
  ['diff --git a/src/a.ts b/src/a.ts', '--- a/src/a.ts', '+++ b/src/a.ts', `@@ -1,1 +1,${added.length + 1} @@`, ' ctx', ...added.map((l) => `+${l}`)].join('\n');

const IBAN_LINE = 'const iban = "DE89370400440532013000";';
const ENDPOINT_LINE = 'const url = "https://api.openai.com/v1/chat";';

// ── fetch stub ────────────────────────────────────────────────────────────
function stubFetch(handler: (url: string, init?: RequestInit) => { status?: number; body?: unknown; throws?: Error; badJson?: boolean }) {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    const r = handler(url, init);
    if (r.throws) throw r.throws;
    const status = r.status ?? 200;
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => { if (r.badJson) throw new Error('bad json'); return r.body; },
    } as unknown as Response;
  }));
  return calls;
}
afterEach(() => vi.unstubAllGlobals());

const legacyBody = { ruleset_version: 3, ruleset_hash: HASH_A, rules: [iban()], allowlist: EMPTY_ALLOWLIST, signatures: EMPTY_SIGNATURES };
const schema2Body = (rulesets: unknown[]) => ({ schema: 2, rulesets });
const wire = (rs: FrameworkRuleset) => ({ framework: rs.framework, ruleset_version: rs.ruleset_version, ruleset_hash: rs.ruleset_hash, rules: rs.rules, allowlist: rs.allowlist, signatures: rs.signatures, dropped_rules: [] });

describe('frameworks', () => {
  it('defaults to the original GDPR stream and keeps its check name and GDPR column unchanged', () => {
    expect(DEFAULT_FRAMEWORK).toBe('Data Compliance');
    expect(FRAMEWORK_INFO['Data Compliance'].checkRunName).toBe('Data Compliance Gate');
    expect(FRAMEWORK_INFO['Data Compliance'].articlesLabel).toBe('GDPR');
    expect(FRAMEWORKS).toContain('EU AI Act');
  });

  describe('parseFailOn', () => {
    it('defaults to Data Compliance only', () => {
      expect(parseFailOn(undefined)).toEqual({ failOn: ['Data Compliance'], unknown: [] });
      expect(parseFailOn('')).toEqual({ failOn: ['Data Compliance'], unknown: [] });
      expect(parseFailOn('   ')).toEqual({ failOn: ['Data Compliance'], unknown: [] });
    });

    it('takes a comma list, case-insensitively, de-duplicated, in registry order', () => {
      expect(parseFailOn('eu ai act, data compliance, EU AI Act').failOn).toEqual(['Data Compliance', 'EU AI Act']);
    });

    it('reports unknown names instead of silently ignoring a typo', () => {
      expect(parseFailOn('Data Compliance, Bogus')).toEqual({ failOn: ['Data Compliance'], unknown: ['Bogus'] });
    });

    it('"none" means no framework fails the step', () => {
      expect(parseFailOn('none')).toEqual({ failOn: [], unknown: [] });
    });

    it('a list of only unknown names does NOT silently disable failing: it falls back to the default', () => {
      expect(parseFailOn('Bogus')).toEqual({ failOn: ['Data Compliance'], unknown: ['Bogus'] });
    });
  });
});

describe('fetchRulesets', () => {
  it('asks for schema 2 and sends the token', async () => {
    const calls = stubFetch(() => ({ body: schema2Body([wire(dcRuleset())]) }));
    await fetchRulesets('https://pc.example/', 'ci_live_x');
    expect(calls[0].url).toBe('https://pc.example/functions/v1/ci-ruleset?schema=2&caps=context');
    expect((calls[0].init?.headers as Record<string, string>).Authorization).toBe('Bearer ci_live_x');
  });

  it('announces the capabilities it supports, and none by default', async () => {
    const calls = stubFetch(() => ({ body: schema2Body([wire(dcRuleset())]) }));
    await fetchRulesets('https://pc.example', 't', ['context', 'file_path']);
    expect(calls[0].url).toBe('https://pc.example/functions/v1/ci-ruleset?schema=2&caps=context%2Cfile_path');
  });

  it('reads a schema-2 body into one ruleset per framework, in order', async () => {
    stubFetch(() => ({ body: schema2Body([wire(dcRuleset()), wire(aiRuleset())]) }));
    const out = await fetchRulesets('https://pc.example', 't');
    expect(out.shape).toBe('schema2');
    expect(out.rulesets.map((r) => r.framework)).toEqual(['Data Compliance', 'EU AI Act']);
    expect(out.rulesets[1].ruleset_hash).toBe(HASH_B);
  });

  it('FALLBACK: an OLD server ignores ?schema=2 and returns the legacy body; that is one Data Compliance ruleset', async () => {
    stubFetch(() => ({ body: legacyBody }));
    const out = await fetchRulesets('https://pc.example', 't');
    expect(out.shape).toBe('legacy');
    expect(out.rulesets).toHaveLength(1);
    expect(out.rulesets[0]).toMatchObject({ framework: 'Data Compliance', ruleset_version: 3, ruleset_hash: HASH_A });
    expect(out.rulesets[0].rules).toHaveLength(1);
  });

  it('skips a framework this Action does not know (a newer server) and keeps the rest', async () => {
    stubFetch(() => ({ body: schema2Body([wire(dcRuleset()), { ...wire(aiRuleset()), framework: 'Future Act' }]) }));
    const out = await fetchRulesets('https://pc.example', 't');
    expect(out.rulesets.map((r) => r.framework)).toEqual(['Data Compliance']);
  });

  it.each([
    ['an empty rulesets list', schema2Body([])],
    ['only unknown frameworks', schema2Body([{ ...wire(aiRuleset()), framework: 'Future Act' }])],
    ['a ruleset without a hash', schema2Body([{ ...wire(dcRuleset()), ruleset_hash: undefined }])],
    ['a ruleset whose rules are not a list', schema2Body([{ ...wire(dcRuleset()), rules: 'x' }])],
    ['a non-object body', 'nope'],
    ['a legacy-looking body without a version', { ruleset_hash: HASH_A, rules: [] }],
  ])('rejects %s', async (_name, body) => {
    stubFetch(() => ({ body }));
    await expect(fetchRulesets('https://pc.example', 't')).rejects.toBeInstanceOf(RulesetFetchError);
  });

  it('turns an HTTP error, a network error and bad JSON into RulesetFetchError (never a silent pass)', async () => {
    stubFetch(() => ({ status: 500, body: {} }));
    await expect(fetchRulesets('https://pc.example', 't')).rejects.toMatchObject({ name: 'RulesetFetchError', status: 500 });
    stubFetch(() => ({ throws: new Error('boom') }));
    await expect(fetchRulesets('https://pc.example', 't')).rejects.toBeInstanceOf(RulesetFetchError);
    stubFetch(() => ({ badJson: true }));
    await expect(fetchRulesets('https://pc.example', 't')).rejects.toBeInstanceOf(RulesetFetchError);
  });
});

describe('scanFrameworks: independent verdicts per framework', () => {
  const input = { diff: diffOf(IBAN_LINE, ENDPOINT_LINE), prDescription: '', truncated: false };

  it('scans each framework with ITS OWN rules and gives each its own verdict and findings', () => {
    const out = scanFrameworks([dcRuleset(), aiRuleset()], input, ['Data Compliance']);
    expect(out.map((o) => [o.framework, o.result.verdict])).toEqual([['Data Compliance', 'fail'], ['EU AI Act', 'needs_review']]);
    expect(out[0].result.findings.map((f) => f.rule_id)).toEqual(['dc-pii-iban']);
    expect(out[1].result.findings.map((f) => f.rule_id)).toEqual(['eaa-ci-endpoint']);
  });

  it('GDPR findings keep the legacy shape; schema-2 findings carry `articles` and no gdpr_article', () => {
    const out = scanFrameworks([dcRuleset(), aiRuleset()], input, ['Data Compliance']);
    expect(Object.keys(out[0].result.findings[0])).toEqual(['rule_id', 'gdpr_article', 'action', 'masked_evidence']);
    expect(out[1].result.findings[0]).toEqual({ rule_id: 'eaa-ci-endpoint', articles: ['Art. 15'], action: 'review', masked_evidence: expect.any(String) });
    expect(out[1].result.findings[0]).not.toHaveProperty('gdpr_article');
  });

  it('a framework-specific warning floors ONLY that framework', () => {
    const broken = aiRule({ id: 'eaa-broken', detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: '(', mask: 'm' } });
    const out = scanFrameworks([dcRuleset([]), aiRuleset([broken])], input, ['Data Compliance']);
    const dc = out.find((o) => o.framework === 'Data Compliance')!;
    const ai = out.find((o) => o.framework === 'EU AI Act')!;
    expect(dc.result.verdict).toBe('pass');
    expect(dc.result.warnings).toEqual([]);
    expect(ai.result.verdict).toBe('needs_review');
    expect(ai.result.warnings.length).toBeGreaterThan(0);
  });

  it('running scan() for several frameworks in one process gives each the result it would get alone', () => {
    const both = scanFrameworks([dcRuleset(), aiRuleset()], input, ['Data Compliance']);
    const dcAlone = scanFrameworks([dcRuleset()], input, ['Data Compliance'])[0];
    const aiAlone = scanFrameworks([aiRuleset()], input, ['Data Compliance'])[0];
    expect(both[0].result).toEqual(dcAlone.result);
    expect(both[1].result).toEqual(aiAlone.result);
  });

  it('marks a framework advisory unless fail-on lists it', () => {
    const out = scanFrameworks([dcRuleset(), aiRuleset()], input, ['Data Compliance']);
    expect(out.map((o) => o.advisory)).toEqual([false, true]);
    expect(scanFrameworks([dcRuleset(), aiRuleset()], input, ['Data Compliance', 'EU AI Act']).map((o) => o.advisory)).toEqual([false, false]);
  });
});

describe('failingFrameworks (fail-on)', () => {
  const blocking = (): Rule => aiRule({ action: 'block' });
  const input = { diff: diffOf(IBAN_LINE, ENDPOINT_LINE), prDescription: '', truncated: false };

  it('fails the step only for a failing framework that fail-on lists', () => {
    const out = scanFrameworks([dcRuleset([]), aiRuleset([blocking()])], input, ['Data Compliance']);
    expect(out.find((o) => o.framework === 'EU AI Act')!.result.verdict).toBe('fail');
    expect(failingFrameworks(out)).toEqual([]); // EU AI Act failed but is not in fail-on
  });

  it('fails the step for a failing framework that IS in fail-on', () => {
    const out = scanFrameworks([dcRuleset(), aiRuleset()], input, ['Data Compliance']);
    expect(failingFrameworks(out).map((o) => o.framework)).toEqual(['Data Compliance']);
    const both = scanFrameworks([dcRuleset([]), aiRuleset([blocking()])], input, ['Data Compliance', 'EU AI Act']);
    expect(failingFrameworks(both).map((o) => o.framework)).toEqual(['EU AI Act']);
  });

  it('needs_review never fails the step', () => {
    const out = scanFrameworks([dcRuleset([]), aiRuleset()], input, ['Data Compliance', 'EU AI Act']);
    expect(failingFrameworks(out)).toEqual([]);
  });

  it('fail-on "none" never fails the step', () => {
    const out = scanFrameworks([dcRuleset()], input, []);
    expect(out[0].result.verdict).toBe('fail');
    expect(failingFrameworks(out)).toEqual([]);
  });
});

describe('primaryOutcome', () => {
  const input = { diff: diffOf(ENDPOINT_LINE), prDescription: '', truncated: false };

  it('is the Data Compliance outcome, so the action outputs stay what they always were', () => {
    const out = scanFrameworks([aiRuleset(), dcRuleset()], input, ['Data Compliance']);
    expect(primaryOutcome(out)?.framework).toBe('Data Compliance');
  });

  it('is the first outcome when there is no Data Compliance ruleset', () => {
    expect(primaryOutcome(scanFrameworks([aiRuleset()], input, []))?.framework).toBe('EU AI Act');
  });

  it('is undefined for no outcomes', () => {
    expect(primaryOutcome([])).toBeUndefined();
  });
});

describe('check run per framework', () => {
  const result = (verdict: ScanResult['verdict']): ScanResult => ({ verdict, findings: [], warnings: [] });

  it('an advisory framework never concludes `failure`, so it cannot block a merge by itself', () => {
    expect(checkRunConclusion('fail', false)).toBe('failure');
    expect(checkRunConclusion('fail', true)).toBe('neutral');
    expect(checkRunConclusion('pass', true)).toBe('success');
    expect(checkRunConclusion('needs_review', true)).toBe('neutral');
  });

  it('Data Compliance keeps the exact legacy name, title and GDPR column', async () => {
    const created: Array<Record<string, any>> = []; // eslint-disable-line @typescript-eslint/no-explicit-any -- loosely typed check-run capture
    const octokit = { rest: { checks: { create: async (p: Record<string, unknown>) => { created.push(p); } } } };
    await publishCheckRun(octokit, { owner: 'o', repo: 'r', headSha: 'abc', result: { verdict: 'fail', findings: [{ rule_id: 'x', gdpr_article: ['Art 5'], action: 'block', masked_evidence: 'm' }], warnings: [] } });
    expect(created[0].name).toBe('Data Compliance Gate');
    expect(created[0].conclusion).toBe('failure');
    expect(created[0].output.title).toBe('Data Compliance: fail');
    expect(created[0].output.summary).toContain('| Action | Rule | GDPR | Evidence (masked) |');
  });

  it('another framework gets its own check name, title, "May be relevant to" column and articles values', async () => {
    const created: Array<Record<string, any>> = []; // eslint-disable-line @typescript-eslint/no-explicit-any -- loosely typed check-run capture
    const octokit = { rest: { checks: { create: async (p: Record<string, unknown>) => { created.push(p); } } } };
    await publishCheckRun(octokit, {
      owner: 'o', repo: 'r', headSha: 'abc', framework: 'EU AI Act', advisory: true,
      result: { verdict: 'fail', findings: [{ rule_id: 'eaa-x', articles: ['Art. 15', 'Art. 11'], action: 'block', masked_evidence: 'm' }], warnings: [] },
    });
    expect(created[0].name).toBe('PulseCheck · AI change control');
    expect(created[0].name).not.toBe('Data Compliance Gate');
    expect(created[0].conclusion).toBe('neutral');
    expect(created[0].output.summary).toContain('| Action | Rule | May be relevant to | Evidence (masked) |');
    expect(created[0].output.summary).toContain('Art. 15, Art. 11');
  });

  it('buildSummary without a framework is byte-identical to the legacy summary', () => {
    const r: ScanResult = { verdict: 'needs_review', findings: [{ rule_id: 'dc-pii-bare', gdpr_article: ['Art 5'], action: 'review', masked_evidence: 'Email (masked)' }], warnings: ['w'] };
    expect(buildSummary(r)).toBe(buildSummary(r, 'Data Compliance'));
    expect(buildSummary(r)).toContain('_Scanned in your CI by the PulseCheck Data Compliance Gate. Raw diff and PII never leave this runner._');
  });
});

describe('posting the verdict', () => {
  const base = { repo: 'o/r', pr_number: 7, commit_sha: 'c0ffee' };
  const input = { diff: diffOf(IBAN_LINE, ENDPOINT_LINE), prDescription: '', truncated: false };
  const outcomes = () => scanFrameworks([dcRuleset(), aiRuleset()], input, ['Data Compliance']);

  it('a legacy payload is exactly today\'s body for the Data Compliance outcome', () => {
    const dc = outcomes()[0];
    const body = buildLegacyPayload(base, dc);
    expect(Object.keys(body)).toEqual(['repo', 'pr_number', 'commit_sha', 'ruleset_version', 'ruleset_hash', 'verdict', 'findings']);
    expect(body).toMatchObject({ repo: 'o/r', pr_number: 7, commit_sha: 'c0ffee', ruleset_version: 3, ruleset_hash: HASH_A, verdict: 'fail' });
  });

  it('a schema-2 payload carries one result per framework with its own verdict, hash and findings', () => {
    const body = buildSchema2Payload(base, outcomes());
    expect(body.results.map((r) => [r.framework, r.verdict, r.ruleset_hash])).toEqual([
      ['Data Compliance', 'fail', HASH_A],
      ['EU AI Act', 'needs_review', HASH_B],
    ]);
    expect(body).toMatchObject({ repo: 'o/r', pr_number: 7, commit_sha: 'c0ffee', provider: 'github' });
  });

  describe('a big scan is still recorded: the post is clamped, the verdict is not', () => {
    const manyFindings = (n: number, action = 'advise') =>
      Array.from({ length: n }, (_, i) => ({ rule_id: `r${i}`, gdpr_article: ['Art 5'], action, masked_evidence: `m${i}` }));
    const withFindings = (findings: ReturnType<typeof manyFindings>, verdict: 'pass' | 'fail' | 'needs_review' = 'fail') => {
      const o = scanFrameworks([dcRuleset()], input, ['Data Compliance'])[0];
      return { ...o, result: { ...o.result, verdict, findings } };
    };

    it('an ordinary scan is posted EXACTLY as before: same findings, same order, same bytes', () => {
      const o = withFindings(manyFindings(5, 'review'), 'needs_review');
      expect(JSON.stringify(buildLegacyPayload(base, o).findings)).toBe(JSON.stringify(o.result.findings));
      expect(JSON.stringify(buildSchema2Payload(base, [o]).results[0].findings)).toBe(JSON.stringify(o.result.findings));
    });

    it('keeps the cap, the most severe first, and never changes the verdict', () => {
      const o = withFindings([...manyFindings(250, 'advise'), ...manyFindings(1, 'review').map((f) => ({ ...f, rule_id: 'rev' })), ...manyFindings(1, 'block').map((f) => ({ ...f, rule_id: 'blk' }))]);
      const legacy = buildLegacyPayload(base, o);
      expect(legacy.findings).toHaveLength(POST_LIMITS.maxFindings);
      expect(legacy.findings.slice(0, 2).map((f) => f.rule_id)).toEqual(['blk', 'rev']);
      expect(legacy.verdict).toBe('fail');
      expect(buildSchema2Payload(base, [o]).results[0].findings).toHaveLength(POST_LIMITS.maxFindings);
    });

    it('clamps an over-long field and article list without mutating the scan result', () => {
      const long = 'x'.repeat(POST_LIMITS.maxFieldChars + 50);
      const o = withFindings([{ rule_id: long, gdpr_article: Array.from({ length: 30 }, (_, i) => `Art ${i}`), action: 'block', masked_evidence: long }]);
      const posted = buildLegacyPayload(base, o).findings[0];
      expect(posted.rule_id).toHaveLength(POST_LIMITS.maxFieldChars);
      expect(posted.masked_evidence).toHaveLength(POST_LIMITS.maxFieldChars);
      expect(posted.gdpr_article).toHaveLength(POST_LIMITS.maxListItems);
      expect(o.result.findings[0].masked_evidence).toHaveLength(long.length); // the check run still sees the original
    });

    it('is applied to every framework in a schema-2 post', () => {
      const dc = withFindings(manyFindings(260));
      const ai = { ...scanFrameworks([aiRuleset()], input, [])[0] };
      ai.result = { ...ai.result, findings: manyFindings(230).map((f) => ({ rule_id: f.rule_id, articles: ['Art. 15'], action: f.action, masked_evidence: f.masked_evidence })) };
      const body = buildSchema2Payload(base, [dc, ai]);
      expect(body.results.map((r) => r.findings.length)).toEqual([POST_LIMITS.maxFindings, POST_LIMITS.maxFindings]);
    });
  });

  it('posts schema 2 to a schema-2 server', async () => {
    const calls = stubFetch(() => ({ body: { stored: true } }));
    const out = await postResults('https://pc.example', 't', base, outcomes(), 'schema2');
    expect(out.ok).toBe(true);
    expect(calls).toHaveLength(1);
    expect(JSON.parse(String(calls[0].init?.body)).results).toHaveLength(2);
  });

  it('posts the LEGACY body to a legacy server, for the Data Compliance outcome only', async () => {
    const calls = stubFetch(() => ({ body: { stored: true } }));
    const out = await postResults('https://pc.example', 't', base, outcomes(), 'legacy');
    expect(out.ok).toBe(true);
    expect(calls).toHaveLength(1);
    const sent = JSON.parse(String(calls[0].init?.body));
    expect(sent).not.toHaveProperty('results');
    expect(sent.ruleset_hash).toBe(HASH_A);
    expect(sent.verdict).toBe('fail');
  });

  it('FALLBACK: a 400 to the schema-2 post is retried ONCE in the legacy shape', async () => {
    let n = 0;
    const calls = stubFetch((_u, init) => {
      n += 1;
      const sent = JSON.parse(String(init?.body));
      return sent.results ? { status: 400, body: {} } : { body: { stored: true } };
    });
    const out = await postResults('https://pc.example', 't', base, outcomes(), 'schema2');
    expect(n).toBe(2);
    expect(out.ok).toBe(true);
    expect(JSON.parse(String(calls[1].init?.body)).ruleset_hash).toBe(HASH_A);
  });

  it('a server error on a post with another framework is retried ONCE in the legacy shape (review #4)', async () => {
    const calls = stubFetch(() => ({ status: 500, body: {} }));
    const out = await postResults('https://pc.example', 't', base, outcomes(), 'schema2');
    expect(out.ok).toBe(false);
    expect(calls).toHaveLength(2);
    expect(JSON.parse(String(calls[1].init?.body))).not.toHaveProperty('results');
  });

  it('does not retry a server error on a GDPR-only post or a network failure, and never throws', async () => {
    const calls = stubFetch(() => ({ status: 500, body: {} }));
    const out = await postResults('https://pc.example', 't', base, outcomes().filter((o) => o.framework === 'Data Compliance'), 'schema2');
    expect(out.ok).toBe(false);
    expect(calls).toHaveLength(1);
    stubFetch(() => ({ throws: new Error('down') }));
    expect((await postResults('https://pc.example', 't', base, outcomes(), 'schema2')).ok).toBe(false);
  });

  it('with no Data Compliance outcome there is nothing to retry in the legacy shape', async () => {
    const calls = stubFetch(() => ({ status: 400, body: {} }));
    const onlyAi = scanFrameworks([aiRuleset()], input, []);
    const out = await postResults('https://pc.example', 't', base, onlyAi, 'schema2');
    expect(out.ok).toBe(false);
    expect(calls).toHaveLength(1);
  });
});
