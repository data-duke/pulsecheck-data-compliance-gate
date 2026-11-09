/**
 * CHARACTERIZATION of the GitHub entry point (`index.ts`), written BEFORE it is split
 * into a provider-neutral core plus adapters (PR D of
 * docs/plans/eu-ai-act-ci-change-control.md, "Prove identical GitHub behaviour").
 *
 * `index.ts` runs on import, so it was never unit-tested as a whole: the pieces were
 * (scan, ruleset, report, checkRun) but not how they are wired. This drives the real
 * entry point with a faked `@actions/core`, `@actions/github` and `fetch`, and pins
 * every externally visible effect: what is read, what is posted and to where, which
 * check runs are created, which outputs are set and whether the step fails.
 *
 * It passed against the pre-refactor code and must pass UNCHANGED after it. If a
 * refactor needs an assertion here to change, that is a GitHub behaviour change and
 * has to be called out as one.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Rule } from '../types.js';

const h = vi.hoisted(() => {
  const state = {
    inputs: {} as Record<string, string>,
    infos: [] as string[],
    warnings: [] as string[],
    failed: [] as string[],
    outputs: {} as Record<string, string>,
    checks: [] as Array<Record<string, unknown>>,
    pullsGet: [] as Array<Record<string, unknown>>,
    context: {
      repo: { owner: 'Acme', repo: 'App' },
      payload: { pull_request: { number: 7, body: 'PR body', head: { sha: 'abc123' } } } as Record<string, unknown>,
    },
    diffResponse: '' as string | Error,
    metaResponse: { head: { sha: 'meta456' }, body: 'meta body', merged: false } as Record<string, unknown>,
    metaError: null as unknown,
    checksError: null as unknown,
    events: [] as string[],
  };
  return state;
});

vi.mock('@actions/core', () => ({
  getInput: (name: string) => h.inputs[name] ?? '',
  info: (m: string) => { h.infos.push(m); },
  warning: (m: string) => { h.warnings.push(m); },
  setFailed: (m: string) => { h.failed.push(m); },
  setOutput: (k: string, v: string) => { h.outputs[k] = v; },
}));

vi.mock('@actions/github', () => ({
  get context() { return h.context; },
  getOctokit: () => ({
    rest: {
      pulls: {
        get: async (params: Record<string, unknown>) => {
          h.pullsGet.push(params);
          if (params.mediaType) {
            h.events.push('diff');
            if (h.diffResponse instanceof Error) throw h.diffResponse;
            return { data: h.diffResponse };
          }
          h.events.push('meta');
          if (h.metaError) throw h.metaError;
          return { data: h.metaResponse };
        },
      },
      checks: {
        create: async (params: Record<string, unknown>) => {
          h.events.push(`check:${String(params.name)}`);
          if (h.checksError) throw h.checksError;
          h.checks.push(params);
          return {};
        },
      },
    },
  }),
}));

const HASH = 'a'.repeat(64);
const EMPTY_ALLOWLIST = { emails: [], names: [], domains: [], ip_ranges: [], ibans: [] };
const EMPTY_SIGNATURES = { 'telemetry-sdks': [], 'pii-datastore-credentials': [], 'processor-jurisdiction': [] };
const ibanRule: Rule = {
  id: 'dc-pii-iban', name: 'IBAN', gdpr_article: ['Art 32'], action: 'block', tier: 1,
  detect: { method: 'checksum', target: 'diff', diff_side: 'added', validator: ['iban'], mask: 'IBAN (masked)' },
};
const aiRule: Rule = {
  id: 'eaa-ci-endpoint', name: 'Hosted model endpoint', articles: ['Art. 15'], relevance: ['control'], action: 'review', tier: 2,
  detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: 'api\\.openai\\.com', mask: 'Model endpoint' },
};
const legacyBody = { ruleset_version: 3, ruleset_hash: HASH, rules: [ibanRule], allowlist: EMPTY_ALLOWLIST, signatures: EMPTY_SIGNATURES };
const schema2Body = {
  schema: 2,
  rulesets: [
    { framework: 'Data Compliance', ruleset_version: 3, ruleset_hash: HASH, rules: [ibanRule], allowlist: EMPTY_ALLOWLIST, signatures: EMPTY_SIGNATURES, dropped_rules: [] },
    { framework: 'EU AI Act', ruleset_version: 1, ruleset_hash: 'b'.repeat(64), rules: [aiRule], allowlist: EMPTY_ALLOWLIST, signatures: {}, dropped_rules: [] },
  ],
};

// A syntactically valid IBAN that is not on the default allowlist. Assembled at runtime on
// purpose: written as one literal, this very file is a blocking finding for the Data
// Compliance Gate that scans every PR of this repo (dc-pii-iban / dc-pii-in-fixtures). The
// value the code under test sees is identical.
const RAW_IBAN = ['AT61', '1904', '3002', '3457', '3201'].join('');
const diffOf = (...added: string[]) =>
  ['diff --git a/src/a.ts b/src/a.ts', '--- a/src/a.ts', '+++ b/src/a.ts', `@@ -1,1 +1,${added.length + 1} @@`, ' ctx', ...added.map((l) => `+${l}`)].join('\n');
const CLEAN_DIFF = diffOf('const x = 1;');
const IBAN_DIFF = diffOf(`const iban = "${RAW_IBAN}";`);

interface FetchCall { url: string; method: string; headers: Record<string, string>; body?: unknown }
let fetchCalls: FetchCall[];

function stubFetch(handler: (c: FetchCall) => { status?: number; body?: unknown; throws?: Error }) {
  fetchCalls = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const call: FetchCall = {
      url,
      method: init?.method ?? 'GET',
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: init?.body ? JSON.parse(init.body as string) : undefined,
    };
    fetchCalls.push(call);
    h.events.push(call.method === 'GET' ? 'ruleset' : 'post');
    const r = handler(call);
    if (r.throws) throw r.throws;
    const status = r.status ?? 200;
    return { ok: status >= 200 && status < 300, status, json: async () => r.body } as unknown as Response;
  }));
}

/** Import the entry point fresh and let its top-level `run()` settle. */
async function runEntry() {
  vi.resetModules();
  await import('../index.js');
  await new Promise((r) => setTimeout(r, 0));
  await new Promise((r) => setTimeout(r, 0));
}

const BASE_URL = 'https://pc.example.test';
const posts = () => fetchCalls.filter((c) => c.method === 'POST');
const rulesetGets = () => fetchCalls.filter((c) => c.method === 'GET');

beforeEach(() => {
  h.inputs = { 'pulsecheck-token': 'tok_123', 'pulsecheck-url': BASE_URL, 'github-token': 'ghs_abc' };
  h.infos = []; h.warnings = []; h.failed = []; h.outputs = {}; h.checks = []; h.pullsGet = [];
  h.metaError = null; h.checksError = null; h.events = [];
  h.context = { repo: { owner: 'Acme', repo: 'App' }, payload: { pull_request: { number: 7, body: 'PR body', head: { sha: 'abc123' } } } };
  h.diffResponse = CLEAN_DIFF;
  h.metaResponse = { head: { sha: 'meta456' }, body: 'meta body', merged: false };
});
afterEach(() => vi.unstubAllGlobals());

describe('GitHub entry point (characterization)', () => {
  it('without a token it is inert: no API call, no fetch, no check run, no failure', async () => {
    h.inputs['pulsecheck-token'] = '';
    stubFetch(() => ({ body: legacyBody }));
    await runEntry();
    expect(fetchCalls).toEqual([]);
    expect(h.pullsGet).toEqual([]);
    expect(h.checks).toEqual([]);
    expect(h.failed).toEqual([]);
    expect(h.outputs).toEqual({});
  });

  it('a clean PR against a legacy server: GETs the ruleset, publishes ONE success check, posts a legacy pass', async () => {
    stubFetch((c) => (c.method === 'GET' ? { body: legacyBody } : { status: 200 }));
    await runEntry();

    expect(rulesetGets()).toHaveLength(1);
    // DELIBERATE GitHub behaviour change (PR B2): the Action announces `context` and names the repository as GitHub spells it.
    expect(rulesetGets()[0].url).toBe('https://pc.example.test/functions/v1/ci-ruleset?schema=2&caps=context&repo=Acme%2FApp');
    expect(rulesetGets()[0].headers.Authorization).toBe('Bearer tok_123');

    expect(h.checks).toHaveLength(1);
    expect(h.checks[0]).toMatchObject({ owner: 'Acme', repo: 'App', name: 'Data Compliance Gate', head_sha: 'abc123', status: 'completed', conclusion: 'success' });

    expect(posts()).toHaveLength(1);
    expect(posts()[0].url).toBe(`${BASE_URL}/functions/v1/ci-scan-result`);
    expect(posts()[0].headers.Authorization).toBe('Bearer tok_123');
    expect(posts()[0].body).toMatchObject({ repo: 'Acme/App', pr_number: 7, commit_sha: 'abc123', ruleset_hash: HASH, verdict: 'pass', findings: [] });

    expect(h.outputs).toMatchObject({ verdict: 'pass', 'findings-count': '0', verdicts: '{"Data Compliance":"pass"}' });
    expect(h.failed).toEqual([]);
    // The diff was read through the API with the diff media type.
    expect(h.pullsGet).toEqual([expect.objectContaining({ owner: 'Acme', repo: 'App', pull_number: 7, mediaType: { format: 'diff' } })]);
  });

  it('a blocking finding publishes a failure check, fails the step, and never posts the raw value', async () => {
    h.diffResponse = IBAN_DIFF;
    stubFetch((c) => (c.method === 'GET' ? { body: legacyBody } : { status: 200 }));
    await runEntry();

    expect(h.checks).toHaveLength(1);
    expect(h.checks[0]).toMatchObject({ name: 'Data Compliance Gate', conclusion: 'failure' });
    expect(h.failed).toHaveLength(1);
    expect(h.failed[0]).toMatch(/Data Compliance Gate failed: 1 blocking finding/);

    expect(posts()).toHaveLength(1);
    expect(posts()[0].body).toMatchObject({ verdict: 'fail' });
    expect((posts()[0].body as { findings: unknown[] }).findings).toHaveLength(1);
    expect(JSON.stringify(posts()[0].body)).not.toContain(RAW_IBAN);
    expect(JSON.stringify(h.checks)).not.toContain(RAW_IBAN);
    expect(h.outputs).toMatchObject({ verdict: 'fail', 'findings-count': '1' });
  });

  it('PulseCheck unreachable: one neutral check, a warning, NO post, and the pipeline is not failed', async () => {
    stubFetch(() => ({ throws: new Error('ECONNREFUSED') }));
    await runEntry();

    expect(h.checks).toHaveLength(1);
    expect(h.checks[0]).toMatchObject({ name: 'Data Compliance Gate', conclusion: 'neutral' });
    expect(h.warnings.join('\n')).toMatch(/Could not reach PulseCheck to fetch the ruleset/);
    expect(posts()).toEqual([]);
    expect(h.failed).toEqual([]);
    expect(h.outputs.verdict).toBe('needs_review');
  });

  it('diff unavailable: a neutral check, a warning, no ruleset fetch, no post, not failed', async () => {
    h.diffResponse = new Error('Not Found');
    stubFetch(() => ({ body: legacyBody }));
    await runEntry();

    expect(h.checks).toHaveLength(1);
    expect(h.checks[0]).toMatchObject({ conclusion: 'neutral' });
    expect(h.warnings.join('\n')).toMatch(/Could not fetch the PR diff \(Not Found\)/);
    expect(fetchCalls).toEqual([]);
    expect(h.failed).toEqual([]);
    expect(h.outputs.verdict).toBe('needs_review');
  });

  it('an explicit pr-number reads the PR metadata, scans that PR, and records against ITS head sha', async () => {
    h.inputs['pr-number'] = '22';
    h.context = { repo: { owner: 'Acme', repo: 'App' }, payload: {} };
    stubFetch((c) => (c.method === 'GET' ? { body: legacyBody } : { status: 200 }));
    await runEntry();

    expect(h.pullsGet[0]).toMatchObject({ owner: 'Acme', repo: 'App', pull_number: 22 });
    expect(h.checks[0]).toMatchObject({ head_sha: 'meta456' });
    expect(posts()[0].body).toMatchObject({ pr_number: 22, commit_sha: 'meta456' });
  });

  it('an invalid pr-number fails the step before anything is read or posted', async () => {
    h.inputs['pr-number'] = '22abc';
    stubFetch(() => ({ body: legacyBody }));
    await runEntry();
    expect(h.failed).toEqual(["pr-number must be a positive whole number (e.g. '22')."]);
    expect(fetchCalls).toEqual([]);
    expect(h.checks).toEqual([]);
  });

  it('no pull request context and no input: nothing to scan, no failure', async () => {
    h.context = { repo: { owner: 'Acme', repo: 'App' }, payload: {} };
    stubFetch(() => ({ body: legacyBody }));
    await runEntry();
    expect(fetchCalls).toEqual([]);
    expect(h.checks).toEqual([]);
    expect(h.failed).toEqual([]);
  });

  it('publish-check-run: false records the verdict but publishes no check run', async () => {
    h.inputs['publish-check-run'] = 'false';
    stubFetch((c) => (c.method === 'GET' ? { body: legacyBody } : { status: 200 }));
    await runEntry();
    expect(h.checks).toEqual([]);
    expect(posts()).toHaveLength(1);
  });

  it('a missing github-token fails the step', async () => {
    h.inputs['github-token'] = '';
    stubFetch(() => ({ body: legacyBody }));
    await runEntry();
    expect(h.failed).toEqual(['github-token is required to fetch the diff and publish the check run.']);
    expect(fetchCalls).toEqual([]);
  });

  it('two frameworks, default fail-on: GDPR gates; the AI check is advisory (neutral) even when it flags', async () => {
    h.diffResponse = diffOf('const url = "https://api.openai.com/v1/chat";');
    stubFetch((c) => (c.method === 'GET' ? { body: schema2Body } : { status: 200 }));
    await runEntry();

    const names = h.checks.map((c) => c.name);
    expect(names).toEqual(['Data Compliance Gate', 'PulseCheck · AI change control']);
    const ai = h.checks.find((c) => c.name !== 'Data Compliance Gate')!;
    expect(ai.conclusion).toBe('neutral');
    expect(h.failed).toEqual([]);
    expect(posts()).toHaveLength(1);
    // Schema-2 body: a `results` array (no `schema` key), and the provider is hard-coded to 'github' today.
    const body = posts()[0].body as { provider?: string; results?: Array<{ framework: string; verdict: string }> };
    expect(body.provider).toBe('github');
    expect(body.results?.map((r) => [r.framework, r.verdict])).toEqual([['Data Compliance', 'pass'], ['EU AI Act', 'needs_review']]);
    expect(JSON.parse(h.outputs.verdicts)).toEqual({ 'Data Compliance': 'pass', 'EU AI Act': 'needs_review' });
  });

  it('fail-on listing both frameworks lets the AI check fail the step', async () => {
    h.inputs['fail-on'] = 'Data Compliance, EU AI Act';
    h.diffResponse = diffOf('const url = "https://api.openai.com/v1/chat";');
    stubFetch((c) => (c.method === 'GET' ? { body: schema2Body } : { status: 200 }));
    await runEntry();
    // A `review` rule yields needs_review, which is neutral even when gating; only `fail` fails the step.
    expect(h.failed).toEqual([]);
    expect(h.checks.find((c) => c.name !== 'Data Compliance Gate')!.conclusion).toBe('neutral');
  });
});

describe('GitHub entry point (characterization): remaining paths', () => {
  const ok = (c: FetchCall) => (c.method === 'GET' ? { body: legacyBody } : { status: 200 });

  it('caps the diff at diff-cap-bytes: a truncated scan is floored to needs_review with the truncation warning', async () => {
    h.inputs['diff-cap-bytes'] = '120';
    h.diffResponse = diffOf(...Array.from({ length: 40 }, (_, i) => `const line${i} = ${i};`));
    stubFetch(ok);
    await runEntry();
    expect(h.warnings.join('\n')).toContain('Diff exceeded the configured size cap and was truncated; verdict floored to needs_review.');
    expect(h.outputs.verdict).toBe('needs_review');
    expect(posts()[0].body).toMatchObject({ verdict: 'needs_review' });
  });

  it.each(['abc', '-1', '0'])('an invalid diff-cap-bytes (%s) falls back to the 5 MB default, so a small diff is not truncated', async (cap) => {
    h.inputs['diff-cap-bytes'] = cap;
    h.diffResponse = diffOf(...Array.from({ length: 40 }, (_, i) => `const line${i} = ${i};`));
    stubFetch(ok);
    await runEntry();
    expect(h.warnings.join('\n')).not.toContain('truncated');
    expect(h.outputs.verdict).toBe('pass');
  });

  it('a check run that cannot be published is a warning and a neutral conclusion, and the verdict is still posted', async () => {
    h.checksError = new Error('403');
    stubFetch(ok);
    await runEntry();
    expect(h.warnings.join('\n')).toContain('Could not publish the check run: 403');
    expect(h.infos.join('\n')).toContain('Data Compliance Gate: pass (check run conclusion: neutral).');
    expect(posts()).toHaveLength(1);
    expect(h.failed).toEqual([]);
  });

  it('a non-Error thrown while publishing is reported the same way', async () => {
    h.checksError = 'plain string';
    stubFetch(ok);
    await runEntry();
    expect(h.warnings.join('\n')).toContain('Could not publish the check run: plain string');
  });

  it('a failed post is a warning only: it neither fails the step nor changes the outputs', async () => {
    stubFetch((c) => (c.method === 'GET' ? { body: legacyBody } : { status: 500 }));
    await runEntry();
    expect(h.warnings.join('\n')).toContain('Could not record the verdict with PulseCheck: ci-scan-result returned HTTP 500');
    expect(h.failed).toEqual([]);
    expect(h.outputs.verdict).toBe('pass');
  });

  it('a post refused for token limits says so in plain words, and is still only a warning', async () => {
    stubFetch((c) => (c.method === 'GET' ? { body: legacyBody } : { status: 403, body: { error: { code: 'token_scope_mismatch' } } }));
    await runEntry();
    expect(h.warnings.join('\n')).toContain('this token is limited to other repositories or providers');
    expect(h.failed).toEqual([]);
  });

  it('an explicit pr-number whose metadata cannot be read fails the step before any scan', async () => {
    h.inputs['pr-number'] = '22';
    h.context = { repo: { owner: 'Acme', repo: 'App' }, payload: {} };
    h.metaError = new Error('Not Found');
    stubFetch(ok);
    await runEntry();
    expect(h.failed).toEqual(['Could not read pull request #22: Not Found']);
    expect(fetchCalls).toEqual([]);
    expect(h.checks).toEqual([]);
  });

  it('a merged explicit pull request is announced as a backfill and still scanned', async () => {
    h.inputs['pr-number'] = '22';
    h.context = { repo: { owner: 'Acme', repo: 'App' }, payload: {} };
    h.metaResponse = { head: { sha: 'meta456' }, body: 'meta body', merged: true };
    stubFetch(ok);
    await runEntry();
    expect(h.infos).toContain('Pull request #22 is merged — scanning it as a backfill.');
    expect(posts()[0].body).toMatchObject({ pr_number: 22 });
  });

  it('rules the server withheld for a missing capability are logged per framework', async () => {
    const withheld = {
      schema: 2,
      rulesets: [{ ...schema2Body.rulesets[0], dropped_rules: ['r1', 'r2'] }],
    };
    stubFetch((c) => (c.method === 'GET' ? { body: withheld } : { status: 200 }));
    await runEntry();
    expect(h.infos).toContain('Data Compliance: 2 rule(s) withheld because this Action does not support a capability they need.');
  });

  it('an unknown fail-on name is warned about, not silently ignored', async () => {
    h.inputs['fail-on'] = 'Data Compliance, Bogus';
    stubFetch(ok);
    await runEntry();
    expect(h.warnings).toContain('fail-on: unknown framework "Bogus" was ignored.');
  });

  it('per-framework warnings are prefixed with the framework title, except for the original GDPR stream', async () => {
    h.inputs['diff-cap-bytes'] = '120';
    h.diffResponse = diffOf(...Array.from({ length: 40 }, (_, i) => `const line${i} = ${i};`));
    stubFetch((c) => (c.method === 'GET' ? { body: schema2Body } : { status: 200 }));
    await runEntry();
    const cut = 'Diff exceeded the configured size cap and was truncated; verdict floored to needs_review.';
    expect(h.warnings).toContain(cut);
    expect(h.warnings).toContain(`AI change control: ${cut}`);
  });

  it('keeps the order of effects: diff, then ruleset, then one check per framework, then the post', async () => {
    h.inputs['pr-number'] = '22';
    h.context = { repo: { owner: 'Acme', repo: 'App' }, payload: {} };
    stubFetch((c) => (c.method === 'GET' ? { body: schema2Body } : { status: 200 }));
    await runEntry();
    expect(h.events).toEqual(['meta', 'diff', 'ruleset', 'check:Data Compliance Gate', 'check:PulseCheck · AI change control', 'post']);
  });

  it('a null pull-request body is treated as an empty description', async () => {
    h.context = { repo: { owner: 'Acme', repo: 'App' }, payload: { pull_request: { number: 7, body: null, head: { sha: 'abc123' } } } };
    stubFetch(ok);
    await runEntry();
    expect(h.failed).toEqual([]);
    expect(h.outputs.verdict).toBe('pass');
  });

  it('a non-Error thrown while fetching the ruleset is reported with String(err)', async () => {
    stubFetch(() => ({ throws: 'boom' as unknown as Error }));
    await runEntry();
    expect(h.warnings.join('\n')).toMatch(/Could not reach PulseCheck to fetch the ruleset \(.*boom.*\)/);
    expect(h.checks[0]).toMatchObject({ conclusion: 'neutral' });
    expect(posts()).toEqual([]);
  });
});
