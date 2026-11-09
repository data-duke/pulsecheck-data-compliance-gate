/**
 * PR E: `scan-mode: baseline` end to end, minus GitHub: input parsing, the ruleset fetch (EU AI Act only, same
 * caps as a PR scan), the post to ci-inventory-result and every way that post can fail. The policy under test:
 * a baseline run NEVER fails the customer's workflow, because it is a scheduled inventory, not a gate.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { parseSamplePaths, parseScanMode, runBaseline, type BaselineCheckout } from '../baselineRun.js';
import type { Rule } from '../types.js';

const BASE_URL = 'https://pc.example.test';
const HASH = 'a'.repeat(64);
const SHA = 'f'.repeat(40);
const EMPTY_ALLOWLIST = { emails: [], names: [], domains: [], ip_ranges: [], ibans: [] };
const EMPTY_SIGNATURES = { 'telemetry-sdks': [], 'pii-datastore-credentials': [], 'processor-jurisdiction': [] };
const endpointRule = (over: Partial<Rule> = {}): Rule => ({
  id: 'eaa-ci-ai-endpoint', name: 'Endpoint', articles: [], relevance: ['assessment'], action: 'review', tier: 2,
  detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: '(?i)api\\.openai\\.com', mask: 'Hosted model endpoint' },
  baseline: true,
  ...over,
});
const gdpr = { framework: 'Data Compliance', ruleset_version: 3, ruleset_hash: HASH, rules: [], allowlist: EMPTY_ALLOWLIST, signatures: EMPTY_SIGNATURES, dropped_rules: [] };
const eu = (rules: Rule[]) => ({ framework: 'EU AI Act', ruleset_version: 1, ruleset_hash: 'b'.repeat(64), rules, allowlist: EMPTY_ALLOWLIST, signatures: {}, dropped_rules: [] });
const schema2 = (rules: Rule[] = [endpointRule()]) => ({ schema: 2, rulesets: [gdpr, eu(rules)] });

interface FetchCall { url: string; method: string; headers: Record<string, string>; body?: unknown }
let calls: FetchCall[];
function stubFetch(handler: (c: FetchCall) => { status?: number; body?: unknown; throws?: unknown; badJson?: boolean }) {
  calls = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const call: FetchCall = {
      url, method: init?.method ?? 'GET', headers: (init?.headers ?? {}) as Record<string, string>,
      body: init?.body ? JSON.parse(init.body as string) : undefined,
    };
    calls.push(call);
    const r = handler(call);
    if (r.throws !== undefined) throw r.throws;
    const status = r.status ?? 200;
    return {
      ok: status >= 200 && status < 300, status,
      json: async () => { if (r.badJson) throw new SyntaxError('bad json'); return r.body; },
    } as unknown as Response;
  }));
}
const posts = () => calls.filter((c) => c.method === 'POST');

function checkout(files: Record<string, string>, over: Partial<BaselineCheckout> = {}): BaselineCheckout {
  const enc = new TextEncoder();
  return {
    listFiles: async () => Object.keys(files),
    size: async (p) => (p in files ? enc.encode(files[p]).length : null),
    read: async (p) => enc.encode(files[p]),
    headSha: async () => SHA,
    ...over,
  };
}
const TREE = { 'src/a.ts': 'const u = "https://api.openai.com/v1";\n', 'README.md': 'hello\n' };

let io: { infos: string[]; warnings: string[]; info(m: string): void; warning(m: string): void };
beforeEach(() => {
  io = { infos: [], warnings: [], info(m) { this.infos.push(m); }, warning(m) { this.warnings.push(m); } };
});
afterEach(() => vi.unstubAllGlobals());

const RUN = { url: BASE_URL, token: 'tok_123', repo: 'Acme/App', samplePaths: false, fallbackSha: 'e'.repeat(40) };
const ok = (postBody: unknown = { ok: true, stored: true }, postStatus = 200) => (c: FetchCall) =>
  c.method === 'GET' ? { body: schema2() } : { status: postStatus, body: postBody };

describe('parseScanMode', () => {
  it.each([['', 'pr'], ['pr', 'pr'], ['PR', 'pr'], [' baseline ', 'baseline'], ['Baseline', 'baseline']])('%j -> %s', (raw, mode) => {
    expect(parseScanMode(raw)).toEqual({ mode });
  });
  it('an unknown value is an error that names the allowed values, clamped and de-fanged', () => {
    const r = parseScanMode('full');
    expect(r).toEqual({ error: expect.stringContaining("scan-mode must be 'pr' or 'baseline'") });
    const long = parseScanMode(`${'x'.repeat(200)}\n::set-output name=a::b`);
    expect('error' in long && long.error.length).toBeLessThan(160);
    expect('error' in long && long.error).not.toMatch(/\n|::/);
  });
});

describe('parseSamplePaths', () => {
  it.each([['', false], ['false', false], ['FALSE', false], ['true', true], [' True ', true]])('%j -> %s', (raw, value) => {
    expect(parseSamplePaths(raw)).toEqual({ value });
  });
  it('anything else stays OFF (the safe default) with a warning', () => {
    expect(parseSamplePaths('yes')).toEqual({ value: false, warning: expect.stringContaining('baseline-sample-paths') });
  });
});

describe('runBaseline: ruleset', () => {
  it('fetches with the same URL, caps and auth as a PR scan, then posts ONLY the EU AI Act inventory', async () => {
    stubFetch(ok());
    await runBaseline(RUN, checkout(TREE), io);
    expect(calls[0]).toMatchObject({ method: 'GET', url: `${BASE_URL}/functions/v1/ci-ruleset?schema=2&caps=context&repo=Acme%2FApp` });
    expect(calls[0].headers.Authorization).toBe('Bearer tok_123');
    expect(posts()).toHaveLength(1);
    expect(posts()[0].url).toBe(`${BASE_URL}/functions/v1/ci-inventory-result`);
    expect(posts()[0].headers).toMatchObject({ Authorization: 'Bearer tok_123', 'Content-Type': 'application/json' });
    expect(posts()[0].body).toEqual({
      repo: 'Acme/App', provider: 'github', commit_sha: SHA, files_scanned: 2, truncated: false,
      observations: [{ rule_id: 'eaa-ci-ai-endpoint', signature_key: 'openai', count: 1 }],
    });
    expect(io.warnings).toEqual([]);
  });

  it('a trailing slash on the URL is tolerated', async () => {
    stubFetch(ok());
    await runBaseline({ ...RUN, url: `${BASE_URL}/` }, checkout(TREE), io);
    expect(posts()[0].url).toBe(`${BASE_URL}/functions/v1/ci-inventory-result`);
  });

  it('the GDPR ruleset is never scanned in baseline mode, even when its rules carry baseline: true', async () => {
    const gdprWithFlag = { ...gdpr, rules: [endpointRule()] };
    stubFetch((c) => (c.method === 'GET' ? { body: { schema: 2, rulesets: [gdprWithFlag] } } : { status: 200, body: {} }));
    await runBaseline(RUN, checkout(TREE), io);
    expect(posts()).toEqual([]);
    expect(io.infos.join('\n')).toMatch(/EU AI Act ruleset/);
  });

  it('no EU AI Act ruleset served (org not opted in, or an old server): logs and exits, no post, no warning', async () => {
    stubFetch((c) => (c.method === 'GET' ? { body: { schema: 2, rulesets: [gdpr] } } : { status: 200 }));
    await runBaseline(RUN, checkout(TREE), io);
    expect(posts()).toEqual([]);
    expect(io.warnings).toEqual([]);
  });

  it('a legacy (pre-schema-2) server: logs and exits, no post', async () => {
    stubFetch((c) => (c.method === 'GET' ? { body: { ruleset_version: 3, ruleset_hash: HASH, rules: [] } } : { status: 200 }));
    await runBaseline(RUN, checkout(TREE), io);
    expect(posts()).toEqual([]);
  });

  it('an EU AI Act ruleset without baseline rules (server predates PR E): logs and exits, no post, the tree is not walked', async () => {
    const listFiles = vi.fn(async () => Object.keys(TREE));
    stubFetch((c) => (c.method === 'GET' ? { body: schema2([endpointRule({ baseline: undefined })]) } : { status: 200 }));
    await runBaseline(RUN, checkout(TREE, { listFiles }), io);
    expect(posts()).toEqual([]);
    expect(listFiles).not.toHaveBeenCalled();
    expect(io.infos.join('\n')).toMatch(/no baseline rules/i);
  });

  it('the ruleset fetch failing is a warning, never a failure, and nothing is posted', async () => {
    stubFetch(() => ({ throws: new Error('ECONNREFUSED') }));
    await runBaseline(RUN, checkout(TREE), io);
    expect(posts()).toEqual([]);
    expect(io.warnings.join('\n')).toMatch(/Could not reach PulseCheck to fetch the ruleset.*ECONNREFUSED/);
  });

  it('a 401 on the ruleset fetch is a warning too (bad or revoked token)', async () => {
    stubFetch(() => ({ status: 401, body: {} }));
    await runBaseline(RUN, checkout(TREE), io);
    expect(posts()).toEqual([]);
    expect(io.warnings.join('\n')).toMatch(/HTTP 401/);
  });
});

describe('runBaseline: the checkout', () => {
  it('no git checkout (actions/checkout missing): a warning naming the fix, nothing posted', async () => {
    stubFetch(ok());
    await runBaseline(RUN, checkout(TREE, { listFiles: async () => { throw new Error('not a git repository'); } }), io);
    expect(posts()).toEqual([]);
    expect(io.warnings.join('\n')).toMatch(/actions\/checkout/);
  });

  it('HEAD unreadable: falls back to the workflow commit sha', async () => {
    stubFetch(ok());
    await runBaseline(RUN, checkout(TREE, { headSha: async () => { throw new Error('no HEAD'); } }), io);
    expect(posts()[0].body).toMatchObject({ commit_sha: 'e'.repeat(40) });
  });

  it('sample paths are sent only when the input asked for them', async () => {
    stubFetch(ok());
    await runBaseline({ ...RUN, samplePaths: true }, checkout(TREE), io);
    expect((posts()[0].body as { observations: unknown[] }).observations).toEqual([
      { rule_id: 'eaa-ci-ai-endpoint', signature_key: 'openai', count: 1, sample_paths: ['src/a.ts'] },
    ]);
  });

  it('a truncated walk still posts (a lower bound), and says so in a warning', async () => {
    stubFetch(ok());
    const big = Object.fromEntries(Array.from({ length: 4 }, (_, i) => [`src/f${i}.ts`, TREE['src/a.ts']]));
    await runBaseline({ ...RUN, limits: { maxFiles: 2 } }, checkout(big), io);
    expect(posts()[0].body).toMatchObject({ truncated: true, files_scanned: 2 });
    expect(io.warnings.join('\n')).toMatch(/lower bound/);
  });

  it('rule problems found by the walker are surfaced as warnings', async () => {
    stubFetch((c) => (c.method === 'GET'
      ? { body: schema2([endpointRule({ detect: { ...endpointRule().detect, pattern: '(?x)nope' } })]) }
      : { status: 200, body: { ok: true, stored: true } }));
    await runBaseline(RUN, checkout(TREE), io);
    expect(io.warnings.join('\n')).toMatch(/could not be compiled/);
    // Nothing ran, so it must not be posted as a complete, clean scan (the server would clear the repository).
    expect(posts()[0].body).toMatchObject({ truncated: true, files_scanned: 0, observations: [] });
    expect(io.warnings.join('\n')).toMatch(/keeps the previous detections/);
  });

  it('every file unreadable: posted as incomplete (truncated), never as a clean scan', async () => {
    stubFetch(ok());
    await runBaseline(RUN, checkout(TREE, { size: async () => null }), io);
    expect(posts()[0].body).toMatchObject({ truncated: true, files_scanned: 0, observations: [] });
  });

  it('a normal clean scan posts truncated:false with files_scanned > 0', async () => {
    stubFetch(ok());
    await runBaseline(RUN, checkout({ 'src/a.ts': 'const n = 1;\n' }), io);
    expect(posts()[0].body).toMatchObject({ truncated: false, files_scanned: 1, observations: [] });
    expect(io.warnings).toEqual([]);
  });
});

describe('runBaseline: the post (never fails the workflow)', () => {
  it('200 stored:true is an info line with the observation count', async () => {
    stubFetch(ok({ ok: true, stored: true }));
    await runBaseline(RUN, checkout(TREE), io);
    expect(io.infos.join('\n')).toMatch(/Recorded 1 observation/);
    expect(io.warnings).toEqual([]);
  });

  it('200 stored:false (org not opted in) is an info line, not a warning', async () => {
    stubFetch(ok({ ok: true, stored: false }));
    await runBaseline(RUN, checkout(TREE), io);
    expect(io.warnings).toEqual([]);
    expect(io.infos.join('\n')).toMatch(/did not store/);
  });

  it('a 2xx whose body is not JSON still counts as recorded', async () => {
    stubFetch((c) => (c.method === 'GET' ? { body: schema2() } : { status: 200, badJson: true }));
    await runBaseline(RUN, checkout(TREE), io);
    expect(io.warnings).toEqual([]);
    expect(io.infos.join('\n')).toMatch(/Recorded/);
  });

  it('403 forbidden: the token lacks the inventory:write scope', async () => {
    stubFetch(ok({ error: { code: 'forbidden', message: 'Token lacks inventory:write scope' }, success: false }, 403));
    await runBaseline(RUN, checkout(TREE), io);
    expect(io.warnings).toHaveLength(1);
    expect(io.warnings[0]).toMatch(/HTTP 403/);
    expect(io.warnings[0]).toMatch(/lacks the inventory:write scope/);
    expect(io.warnings[0]).not.toMatch(/subscription|revoked/i);
  });

  it("403 org_expired: the organization's subscription or trial has ended (not a token problem)", async () => {
    stubFetch(ok({ error: { code: 'org_expired', message: 'x' }, success: false }, 403));
    await runBaseline(RUN, checkout(TREE), io);
    expect(io.warnings).toHaveLength(1);
    expect(io.warnings[0]).toMatch(/HTTP 403/);
    expect(io.warnings[0]).toMatch(/subscription or trial has ended/);
    expect(io.warnings[0]).not.toMatch(/inventory:write/);
  });

  it('401: the token is invalid or revoked', async () => {
    stubFetch(ok({ error: { code: 'unauthorized', message: 'Token revoked' }, success: false }, 401));
    await runBaseline(RUN, checkout(TREE), io);
    expect(io.warnings).toHaveLength(1);
    expect(io.warnings[0]).toMatch(/HTTP 401/);
    expect(io.warnings[0]).toMatch(/invalid or has been revoked/);
    expect(io.warnings[0]).not.toMatch(/subscription/);
  });

  it('a 403 whose body is not JSON falls back to the scope explanation', async () => {
    stubFetch((c) => (c.method === 'GET' ? { body: schema2() } : { status: 403, badJson: true }));
    await runBaseline(RUN, checkout(TREE), io);
    expect(io.warnings).toHaveLength(1);
    expect(io.warnings[0]).toMatch(/inventory:write/);
  });

  it('the server error message is never echoed (only the allowlisted code chooses the text)', async () => {
    stubFetch(ok({ error: { code: 'org_expired', message: '::set-output name=x::injected' }, success: false }, 403));
    await runBaseline(RUN, checkout(TREE), io);
    expect(io.warnings.join('\n')).not.toContain('injected');
  });

  it.each([400, 404, 429, 500, 503])('%i: a warning with the status', async (status) => {
    stubFetch(ok({ error: { code: 'x' } }, status));
    await runBaseline(RUN, checkout(TREE), io);
    expect(io.warnings).toHaveLength(1);
    expect(io.warnings[0]).toMatch(new RegExp(`HTTP ${status}`));
  });

  it('a network error on the post is a warning', async () => {
    stubFetch((c) => (c.method === 'GET' ? { body: schema2() } : { throws: new Error('socket hang up') }));
    await runBaseline(RUN, checkout(TREE), io);
    expect(io.warnings.join('\n')).toMatch(/Could not record the AI usage inventory.*socket hang up/);
  });

  it('a non-Error thrown on the post is reported with String()', async () => {
    stubFetch((c) => (c.method === 'GET' ? { body: schema2() } : { throws: 'boom' }));
    await runBaseline(RUN, checkout(TREE), io);
    expect(io.warnings.join('\n')).toMatch(/boom/);
  });

  it('an empty tree still posts (an empty inventory is information)', async () => {
    stubFetch(ok());
    await runBaseline(RUN, checkout({}), io);
    expect(posts()[0].body).toMatchObject({ files_scanned: 0, observations: [] });
  });

  it('nothing it logs contains file content', async () => {
    const MARKER = ['QQ', 'LEAK', 'CHECK'].join('_');
    stubFetch(ok());
    await runBaseline({ ...RUN, samplePaths: true }, checkout({ 'src/a.ts': `const u = "https://api.openai.com/${MARKER}";\n` }), io);
    expect(JSON.stringify([io.infos, io.warnings, posts()[0].body])).not.toContain(MARKER);
  });
});
