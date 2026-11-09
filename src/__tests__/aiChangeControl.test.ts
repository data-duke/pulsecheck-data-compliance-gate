/**
 * AI change control (PR B2 of docs/plans/eu-ai-act-ci-change-control.md) on the Action side: the `context`
 * capability, `applies_when` grading, the registry context round trip, the `unavailable` notice, the loud
 * partial-record warning and the digit grouping of POSTED evidence.
 *
 * Grading is tested through `scan()` (gradeByContext is module-private on purpose): the property that matters is
 * what a whole scan returns, not a helper's return value.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { scan } from '../scan.js';
import { fetchRulesets } from '../ruleset.js';
import { SUPPORTED_CAPS, FRAMEWORK_INFO } from '../frameworks.js';
import { buildLegacyPayload, buildSchema2Payload, clampFindingsForPost, notRecordedWarning, postResults } from '../report.js';
import { groupLongDigitRuns } from '../mask.js';
import { runGate, type GateIo, type ProviderAdapter } from '../core.js';
import type { FrameworkRuleset, Rule } from '../types.js';

// Built at runtime so no committed fixture holds a literal 8+ digit run.
const LONG_RUN = ['1234', '5678', '90'].join('');
const STAMP = ['2026', '1007', '0900', '00'].join('');
const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);
const CTX_HASH = 'c'.repeat(64);
const EMPTY_ALLOWLIST = { emails: [], names: [], domains: [], ip_ranges: [], ibans: [] };
const EMPTY_SIGNATURES = { 'telemetry-sdks': [], 'pii-datastore-credentials': [], 'processor-jurisdiction': [] };

const sdkRule = (over: Partial<Rule['detect']> = {}): Rule => ({
  id: 'eaa-ci-ai-sdk-manifest', name: 'AI SDK added', articles: [], relevance: ['assessment'], action: 'review', tier: 2,
  detect: {
    method: 'pattern', target: 'diff', diff_side: 'added', pattern: '"openai"\\s*:', file_scope: ['package.json$'],
    applies_when: [{ when: { repo_linked: true }, action: 'advise' }], mask: 'AI SDK dependency', ...over,
  },
});
const endpointRule = (): Rule => ({
  id: 'eaa-ci-ai-endpoint', name: 'Endpoint', articles: [], relevance: ['assessment'], action: 'review', tier: 2,
  detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: 'api\\.openai\\.com', mask: 'Hosted model endpoint' },
});
const aiRuleset = (rules: Rule[], context?: Record<string, unknown>): FrameworkRuleset => ({
  framework: 'EU AI Act', ruleset_version: 1, ruleset_hash: HASH_B, rules, allowlist: EMPTY_ALLOWLIST, signatures: {},
  dropped_rules: [], ...(context ? { context, context_hash: CTX_HASH } : {}),
});
const dcRuleset = (): FrameworkRuleset => ({
  framework: 'Data Compliance', ruleset_version: 3, ruleset_hash: HASH_A, rules: [], allowlist: EMPTY_ALLOWLIST,
  signatures: EMPTY_SIGNATURES, dropped_rules: [],
});

const file = (path: string, ...added: string[]) =>
  [`diff --git a/${path} b/${path}`, `--- a/${path}`, `+++ b/${path}`, `@@ -1,1 +1,${added.length + 1} @@`, ' {', ...added.map((l) => `+${l}`)].join('\n');
const DIFF = [file('package.json', '  "openai": "^4.52.0",'), file('src/c.ts', 'const u = "https://api.openai.com/v1";')].join('\n');

const UNLINKED = { v: 1, repo_linked: false, emotion_or_biometric_declared: false };
const LINKED = { v: 1, repo_linked: true, emotion_or_biometric_declared: false };

describe('applies_when grading (through scan)', () => {
  const actions = (context?: Record<string, unknown>) =>
    scan(aiRuleset([sdkRule(), endpointRule()], context), { diff: DIFF }).findings.map((f) => `${f.rule_id}=${f.action}`);

  it('no context: every finding keeps its declared action', () => {
    expect(actions()).toEqual(['eaa-ci-ai-sdk-manifest=review', 'eaa-ci-ai-endpoint=review']);
  });
  it('unlinked repository: review', () => {
    expect(actions(UNLINKED)).toEqual(['eaa-ci-ai-sdk-manifest=review', 'eaa-ci-ai-endpoint=review']);
  });
  it('linked repository: the graded rule becomes advise, the ungraded rule does not change', () => {
    expect(actions(LINKED)).toEqual(['eaa-ci-ai-sdk-manifest=advise', 'eaa-ci-ai-endpoint=review']);
  });
  it('a string "true" is not true (strict equality)', () => {
    expect(actions({ v: 1, repo_linked: 'true' })).toEqual(['eaa-ci-ai-sdk-manifest=review', 'eaa-ci-ai-endpoint=review']);
  });
  it('a key the context does not carry (an older context version) never matches', () => {
    expect(actions({ v: 1 })).toEqual(['eaa-ci-ai-sdk-manifest=review', 'eaa-ci-ai-endpoint=review']);
  });
  it('grading only lowers: an entry asking for a stricter action than declared changes nothing', () => {
    const r = scan(aiRuleset([{ ...sdkRule(), action: 'advise', tier: 3 }, endpointRule()], { ...LINKED }), { diff: DIFF });
    const strict = { ...sdkRule({ applies_when: [{ when: { repo_linked: true }, action: 'review' }] }), action: 'advise' as const, tier: 3 as const };
    const r2 = scan(aiRuleset([strict], LINKED), { diff: DIFF });
    expect(r.findings[0].action).toBe('advise');
    expect(r2.findings[0].action).toBe('advise');
  });
  it('a `block` entry is unreadable: findings keep their declared action and one warning names the rule', () => {
    const bad = sdkRule({ applies_when: [{ when: { repo_linked: true }, action: 'block' as never }] });
    const r = scan(aiRuleset([bad], LINKED), { diff: DIFF });
    expect(r.findings.map((f) => f.action)).toEqual(['review']);
    expect(r.warnings).toEqual(['Rule "eaa-ci-ai-sdk-manifest" declares an applies_when this Action cannot read; its findings keep their declared action.']);
  });
  it('an empty `when` is unreadable (it would match every context)', () => {
    const bad = sdkRule({ applies_when: [{ when: {}, action: 'advise' }] });
    expect(scan(aiRuleset([bad], LINKED), { diff: DIFF }).findings[0].action).toBe('review');
  });
  it('the first matching entry wins', () => {
    const two = sdkRule({ applies_when: [{ when: { repo_linked: true }, action: 'review' }, { when: { repo_linked: true }, action: 'advise' }] });
    expect(scan(aiRuleset([two], LINKED), { diff: DIFF }).findings[0].action).toBe('review');
  });
  it('the verdict follows the graded actions: linked + only graded findings is a pass', () => {
    const onlySdk = file('package.json', '  "openai": "^4.52.0",');
    expect(scan(aiRuleset([sdkRule()], UNLINKED), { diff: onlySdk }).verdict).toBe('needs_review');
    expect(scan(aiRuleset([sdkRule()], LINKED), { diff: onlySdk }).verdict).toBe('pass');
  });
});

describe('determinism and "context changes grading only"', () => {
  it('same ruleset + context + diff gives byte-identical results, also across repeated scans in one process', () => {
    const a = scan(aiRuleset([sdkRule(), endpointRule()], LINKED), { diff: DIFF });
    const b = scan(aiRuleset([sdkRule(), endpointRule()], LINKED), { diff: DIFF });
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
  it('changing only the context changes only actions, never which lines match or their evidence', () => {
    const a = scan(aiRuleset([sdkRule(), endpointRule()], LINKED), { diff: DIFF });
    const b = scan(aiRuleset([sdkRule(), endpointRule()], UNLINKED), { diff: DIFF });
    const strip = (r: typeof a) => r.findings.map((f) => [f.rule_id, f.masked_evidence, f.articles]);
    expect(strip(a)).toEqual(strip(b));
    expect(a.findings.map((f) => f.action)).not.toEqual(b.findings.map((f) => f.action));
  });
});

describe('the context round trip', () => {
  it('the Action announces exactly the context capability', () => {
    expect([...SUPPORTED_CAPS]).toEqual(['context']);
  });

  afterEach(() => vi.unstubAllGlobals());
  const stub = (body: unknown) => {
    const calls: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string) => { calls.push(url); return { ok: true, status: 200, json: async () => body } as unknown as Response; }));
    return calls;
  };
  const wireEu = (extra: Record<string, unknown>) => ({ framework: 'EU AI Act', ruleset_version: 1, ruleset_hash: HASH_B, rules: [], allowlist: EMPTY_ALLOWLIST, signatures: {}, dropped_rules: [], ...extra });

  it('sends caps and the repository; the server normalises it', async () => {
    const calls = stub({ schema: 2, rulesets: [wireEu({})] });
    await fetchRulesets('https://pc.example/', 'ci_live_x', SUPPORTED_CAPS, 'Acme/App');
    expect(calls[0]).toBe('https://pc.example/functions/v1/ci-ruleset?schema=2&caps=context&repo=Acme%2FApp');
  });
  it('keeps a context that comes with a 64-hex hash', async () => {
    stub({ schema: 2, rulesets: [wireEu({ context: LINKED, context_hash: CTX_HASH })] });
    const r = await fetchRulesets('https://pc.example', 't');
    expect(r.rulesets[0].context).toEqual(LINKED);
    expect(r.rulesets[0].context_hash).toBe(CTX_HASH);
    expect(r.rulesets[0].context_rejected).toBeUndefined();
  });
  it.each([
    ['context without a hash', { context: LINKED }],
    ['a hash without a context', { context_hash: CTX_HASH }],
    ['a short hash', { context: LINKED, context_hash: 'abc' }],
    ['an array context', { context: [1], context_hash: CTX_HASH }],
  ])('rejects %s: graded without it, never posted', async (_n, extra) => {
    stub({ schema: 2, rulesets: [wireEu(extra)] });
    const r = await fetchRulesets('https://pc.example', 't');
    expect(r.rulesets[0].context).toBeUndefined();
    expect(r.rulesets[0].context_rejected).toBe(true);
  });
  it('reads `unavailable`, sanitised and bounded; a legacy server has none', async () => {
    stub({ schema: 2, rulesets: [wireEu({})], unavailable: [{ framework: 'EU AI Act', reason: 'context_unavailable' }, { framework: 'x', reason: 'Bad Reason!' }, 'junk'] });
    expect((await fetchRulesets('https://pc.example', 't')).unavailable).toEqual([{ framework: 'EU AI Act', reason: 'context_unavailable' }]);
    stub({ ruleset_version: 3, ruleset_hash: HASH_A, rules: [] });
    expect((await fetchRulesets('https://pc.example', 't')).unavailable).toEqual([]);
  });
  it('posts the context and hash unchanged with that framework only; the legacy body never carries them', () => {
    const eu = aiRuleset([], LINKED);
    const outcomes = [
      { framework: 'Data Compliance' as const, ruleset: dcRuleset(), result: { verdict: 'pass' as const, findings: [], warnings: [] }, advisory: false },
      { framework: 'EU AI Act' as const, ruleset: eu, result: { verdict: 'pass' as const, findings: [], warnings: [] }, advisory: true },
    ];
    const body = buildSchema2Payload({ repo: 'Acme/App', pr_number: 1, commit_sha: 'abc' }, outcomes);
    expect(body.results[0]).not.toHaveProperty('context');
    expect(body.results[1]).toMatchObject({ context: LINKED, context_hash: CTX_HASH });
    expect(buildLegacyPayload({ repo: 'Acme/App', pr_number: 1, commit_sha: 'abc' }, outcomes[0])).not.toHaveProperty('context');
  });
});

describe('posted evidence never trips the server backstop on a timestamped path (regression, N1)', () => {
  it('groups every 8+ digit run, keeps every digit, leaves short runs alone', () => {
    expect(groupLongDigitRuns(`Hosted model endpoint @ supabase/migrations/${STAMP}_x.sql:12`)).toBe(
      'Hosted model endpoint @ supabase/migrations/2026·1007·0900·00_x.sql:12',
    );
    expect(groupLongDigitRuns('x @ a/1234567/b.ts:9')).toBe('x @ a/1234567/b.ts:9');
    expect(groupLongDigitRuns(`x @ ${'1234'}${'5678'}`)).toBe('x @ 1234·5678');
  });
  it('clampFindingsForPost applies it, so no posted string holds an 8+ digit run', () => {
    const [f] = clampFindingsForPost([{ rule_id: 'r', articles: [], action: 'review', masked_evidence: `m @ supabase/migrations/${STAMP}_x.sql:3` }]);
    expect(f.masked_evidence).not.toMatch(/\d{8,}/);
  });
  it('the check run is unaffected: scan() still reports the real path', () => {
    const r = scan(aiRuleset([endpointRule()]), { diff: file(`supabase/migrations/${STAMP}_x.sql`, "VALUES ('https://api.openai.com');") });
    expect(r.findings[0].masked_evidence).toBe(`Hosted model endpoint @ supabase/migrations/${STAMP}_x.sql:2`);
  });
});

describe('a refused schema-2 post is never a silent loss of the EU AI Act verdict', () => {
  afterEach(() => vi.unstubAllGlobals());
  const outcomes = [
    { framework: 'Data Compliance' as const, ruleset: dcRuleset(), result: { verdict: 'pass' as const, findings: [], warnings: [] }, advisory: false },
    { framework: 'EU AI Act' as const, ruleset: aiRuleset([], LINKED), result: { verdict: 'needs_review' as const, findings: [], warnings: [] }, advisory: true },
  ];
  it('400 then a successful legacy retry: ok, but names what was not recorded and the server code', async () => {
    let n = 0;
    vi.stubGlobal('fetch', vi.fn(async () => (++n === 1
      ? { ok: false, status: 400, json: async () => ({ error: { code: 'bad_request', message: 'context_hash does not match context' } }) }
      : { ok: true, status: 200, json: async () => ({ stored: true }) }) as unknown as Response));
    const post = await postResults('https://pc.example', 't', { repo: 'Acme/App', pr_number: 1, commit_sha: 'abc' }, outcomes, 'schema2');
    expect(post).toMatchObject({ ok: true, notRecorded: ['EU AI Act'], code: 'bad_request' });
    expect(notRecordedWarning(post)).toBe(
      `PulseCheck refused the multi-framework verdict post (HTTP 400 bad_request); only the Data Compliance verdict was recorded. NOT recorded: ${FRAMEWORK_INFO['EU AI Act'].title}.`,
    );
  });
  it('a GDPR-only schema-2 post that is retried reports nothing extra', async () => {
    let n = 0;
    vi.stubGlobal('fetch', vi.fn(async () => (++n === 1 ? { ok: false, status: 400, json: async () => ({}) } : { ok: true, status: 200, json: async () => ({}) }) as unknown as Response));
    const post = await postResults('https://pc.example', 't', { repo: 'Acme/App', pr_number: 1, commit_sha: 'abc' }, [outcomes[0]], 'schema2');
    expect(notRecordedWarning(post)).toBeNull();
  });
  it('a body that is not JSON does not break the error path', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false, status: 500, json: async () => { throw new Error('html'); } }) as unknown as Response));
    const post = await postResults('https://pc.example', 't', { repo: 'Acme/App', pr_number: 1, commit_sha: 'abc' }, outcomes, 'schema2');
    expect(post).toEqual({ ok: false, status: 500, error: 'ci-scan-result returned HTTP 500' });
  });
});

describe('runGate warnings', () => {
  afterEach(() => vi.unstubAllGlobals());
  const io = () => {
    const out = { warnings: [] as string[], infos: [] as string[] };
    const gateIo: GateIo = { info: (m) => out.infos.push(m), warning: (m) => out.warnings.push(m), setFailed: () => {}, setOutput: () => {} };
    return { out, gateIo };
  };
  const adapter: ProviderAdapter = { fetchDiff: async () => DIFF, publishVerdict: async () => 'success' };
  const run = { url: 'https://pc.example', token: 't', failOn: ['Data Compliance' as const], diffCap: 5_000_000, publishChecks: true, repo: 'Acme/App', prNumber: 1, headSha: 'abc', prDescription: '' };
  const serve = (rulesetsBody: unknown) => vi.stubGlobal('fetch', vi.fn(async (_u: string, init?: RequestInit) =>
    ({ ok: true, status: 200, json: async () => ((init?.method ?? 'GET') === 'GET' ? rulesetsBody : { stored: true }) }) as unknown as Response));
  const wireDc = { framework: 'Data Compliance', ruleset_version: 3, ruleset_hash: HASH_A, rules: [], allowlist: EMPTY_ALLOWLIST, signatures: EMPTY_SIGNATURES, dropped_rules: [] };

  it('warns once per framework the server did not serve', async () => {
    serve({ schema: 2, rulesets: [wireDc], unavailable: [{ framework: 'EU AI Act', reason: 'context_unavailable' }] });
    const { out, gateIo } = io();
    await runGate(run, adapter, gateIo);
    expect(out.warnings).toContain('AI change control: PulseCheck did not serve this ruleset in this run (context_unavailable), so it was not scanned.');
  });
  it('warns when a context was rejected', async () => {
    serve({ schema: 2, rulesets: [wireDc, { ...wireDc, framework: 'EU AI Act', ruleset_hash: HASH_B, signatures: {}, context: LINKED }] });
    const { out, gateIo } = io();
    await runGate(run, adapter, gateIo);
    expect(out.warnings).toContain('AI change control: PulseCheck sent a registry context this Action could not use; it was ignored, so findings keep their declared action and no context is recorded.');
  });
  it('a plain GDPR-only run against a schema-2 server adds no new warning', async () => {
    serve({ schema: 2, rulesets: [wireDc] });
    const { out, gateIo } = io();
    await runGate(run, adapter, gateIo);
    expect(out.warnings).toEqual([]);
  });
});

// ── Review fixes (B2 round 2) ─────────────────────────────────────────────────────────────────────────────────────

describe('digit grouping touches ONLY the location part of posted evidence (review #1)', () => {
  it('an unmasked 8+ digit run in the mask part is posted untouched, so the server backstop can still refuse it', () => {
    const [f] = clampFindingsForPost([{ rule_id: 'r', articles: [], action: 'review', masked_evidence: `IBAN-pattern ${LONG_RUN} @ src/${STAMP}_x.sql:3` }]);
    expect(f.masked_evidence.split(' @ ')[0]).toBe(`IBAN-pattern ${LONG_RUN}`);
    expect(f.masked_evidence).toBe(`IBAN-pattern ${LONG_RUN} @ src/2026·1007·0900·00_x.sql:3`);
  });
  it('a path digit run is grouped; evidence with no location is never transformed', () => {
    expect(groupLongDigitRuns(`m @ a/${STAMP}/b.ts:9`)).toBe('m @ a/2026·1007·0900·00/b.ts:9');
    expect(groupLongDigitRuns(`m ${LONG_RUN}`)).toBe(`m ${LONG_RUN}`);
  });
  it('only the FIRST " @ " splits: a later " @ " is part of the location and is grouped with it', () => {
    expect(groupLongDigitRuns(`m ${LONG_RUN} @ x @ ${STAMP}.ts`)).toBe(`m ${LONG_RUN} @ x @ 2026·1007·0900·00.ts`);
  });
});

describe('an unavailable EU AI Act verification never loses the Data Compliance verdict (review #4)', () => {
  afterEach(() => vi.unstubAllGlobals());
  const base = { repo: 'Acme/App', pr_number: 1, commit_sha: 'abc' };
  const both = [
    { framework: 'Data Compliance' as const, ruleset: dcRuleset(), result: { verdict: 'fail' as const, findings: [], warnings: [] }, advisory: false },
    { framework: 'EU AI Act' as const, ruleset: aiRuleset([], LINKED), result: { verdict: 'pass' as const, findings: [], warnings: [] }, advisory: true },
  ];
  const stubSequence = (...replies: Array<{ status: number; body: unknown }>) => {
    const sent: unknown[] = [];
    vi.stubGlobal('fetch', vi.fn(async (_u: string, init?: RequestInit) => {
      sent.push(JSON.parse(String(init?.body)));
      const r = replies[Math.min(sent.length - 1, replies.length - 1)];
      return { ok: r.status < 300, status: r.status, json: async () => r.body } as unknown as Response;
    }));
    return sent;
  };

  it.each([
    [503, 'context_unavailable'], [503, 'framework_status_unavailable'], [503, 'ruleset_check_unavailable'], [500, 'insert_failed'],
  ])('HTTP %i %s on the schema-2 post → the GDPR verdict is still recorded, and the loss is named', async (status, code) => {
    const sent = stubSequence({ status, body: { error: { code } } }, { status: 200, body: { stored: true } });
    const post = await postResults('https://pc.example', 't', base, both, 'schema2');
    expect(sent).toHaveLength(2);
    expect(sent[1]).toMatchObject({ ruleset_hash: HASH_A, verdict: 'fail' });
    expect(sent[1]).not.toHaveProperty('results');
    expect(post).toMatchObject({ ok: true, notRecorded: ['EU AI Act'], code });
    expect(notRecordedWarning(post)).toBe(
      `PulseCheck refused the multi-framework verdict post (HTTP ${status} ${code}); only the Data Compliance verdict was recorded. NOT recorded: ${FRAMEWORK_INFO['EU AI Act'].title}.`,
    );
  });
  it('a 5xx on a GDPR-only post is NOT re-posted (nothing would be gained, a stored row could be doubled)', async () => {
    const sent = stubSequence({ status: 503, body: {} });
    const post = await postResults('https://pc.example', 't', base, [both[0]], 'schema2');
    expect(sent).toHaveLength(1);
    expect(post.ok).toBe(false);
  });
  it('a server that stored GDPR and reported EU AI Act as not recorded (200 + not_recorded) is surfaced too', async () => {
    stubSequence({ status: 200, body: { stored: true, id: 'x', ids: ['x'], not_recorded: [{ framework: 'EU AI Act', code: 'context_unavailable' }, { framework: 'Bogus', code: 'x' }, 'junk'] } });
    const post = await postResults('https://pc.example', 't', base, both, 'schema2');
    expect(post).toMatchObject({ ok: true, notRecorded: ['EU AI Act'], code: 'context_unavailable' });
    expect(notRecordedWarning(post)).toBe(
      `PulseCheck recorded the verdict post only in part (context_unavailable). NOT recorded: ${FRAMEWORK_INFO['EU AI Act'].title}.`,
    );
  });
  it('runGate emits the warning on a 503', async () => {
    let n = 0;
    vi.stubGlobal('fetch', vi.fn(async (_u: string, init?: RequestInit) => {
      if ((init?.method ?? 'GET') === 'GET') {
        return { ok: true, status: 200, json: async () => ({ schema: 2, rulesets: [
          { framework: 'Data Compliance', ruleset_version: 3, ruleset_hash: HASH_A, rules: [], allowlist: EMPTY_ALLOWLIST, signatures: EMPTY_SIGNATURES, dropped_rules: [] },
          { framework: 'EU AI Act', ruleset_version: 1, ruleset_hash: HASH_B, rules: [], allowlist: EMPTY_ALLOWLIST, signatures: {}, dropped_rules: [] },
        ] }) } as unknown as Response;
      }
      n += 1;
      return (n === 1
        ? { ok: false, status: 503, json: async () => ({ error: { code: 'context_unavailable' } }) }
        : { ok: true, status: 200, json: async () => ({ stored: true }) }) as unknown as Response;
    }));
    const warnings: string[] = [];
    const gateIo: GateIo = { info: () => {}, warning: (m) => warnings.push(m), setFailed: () => {}, setOutput: () => {} };
    await runGate({ url: 'https://pc.example', token: 't', failOn: ['Data Compliance'], diffCap: 5_000_000, publishChecks: true, repo: 'Acme/App', prNumber: 1, headSha: 'abc', prDescription: '' },
      { fetchDiff: async () => DIFF, publishVerdict: async () => 'success' }, gateIo);
    expect(n).toBe(2);
    expect(warnings.some((w) => w.startsWith('PulseCheck refused the multi-framework verdict post (HTTP 503 context_unavailable)'))).toBe(true);
    expect(warnings.some((w) => w.startsWith('Could not record the verdict'))).toBe(false);
  });
});

describe('withheld-rule message names the real cause (review #5)', () => {
  afterEach(() => vi.unstubAllGlobals());
  const runWith = async (dropped: unknown) => {
    vi.stubGlobal('fetch', vi.fn(async (_u: string, init?: RequestInit) => ({ ok: true, status: 200, json: async () => ((init?.method ?? 'GET') === 'GET'
      ? { schema: 2, rulesets: [{ framework: 'EU AI Act', ruleset_version: 1, ruleset_hash: HASH_B, rules: [], allowlist: EMPTY_ALLOWLIST, signatures: {}, dropped_rules: dropped }] }
      : { stored: true }) }) as unknown as Response));
    const infos: string[] = [];
    const gateIo: GateIo = { info: (m) => infos.push(m), warning: () => {}, setFailed: () => {}, setOutput: () => {} };
    await runGate({ url: 'https://pc.example', token: 't', failOn: [], diffCap: 5_000_000, publishChecks: false, repo: 'Acme/App', prNumber: 1, headSha: 'abc', prDescription: '' },
      { fetchDiff: async () => DIFF, publishVerdict: async () => 'success' }, gateIo);
    return infos.filter((m) => m.includes('withheld'));
  };
  it('context withheld although this Action supports it → blames the missing registry context, not the Action', async () => {
    expect(SUPPORTED_CAPS).toContain('context');
    expect(await runWith([{ id: 'a', missing_caps: ['context'] }, { id: 'b', missing_caps: ['context'] }])).toEqual([
      'EU AI Act: 2 rule(s) withheld: PulseCheck could not attach a registry context (no valid repository).',
    ]);
  });
  it('a capability this Action really lacks keeps the original message; a mix reports both', async () => {
    expect(await runWith([{ id: 'a', missing_caps: ['file_path'] }])).toEqual([
      'EU AI Act: 1 rule(s) withheld because this Action does not support a capability they need.',
    ]);
    expect(await runWith([{ id: 'a', missing_caps: ['context'] }, { id: 'b', missing_caps: ['context', 'file_path'] }])).toEqual([
      'EU AI Act: 1 rule(s) withheld because this Action does not support a capability they need.',
      'EU AI Act: 1 rule(s) withheld: PulseCheck could not attach a registry context (no valid repository).',
    ]);
  });
});
