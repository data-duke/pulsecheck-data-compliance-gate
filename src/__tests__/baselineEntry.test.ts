/**
 * PR E: the GitHub entry point (`index.ts`) in `scan-mode: baseline`, driven like the PR-mode characterization
 * test: faked `@actions/core`, `@actions/github` and `fetch`, plus a faked checkout. PR mode itself stays pinned,
 * unchanged, by githubEntry.characterization.test.ts.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => ({
  inputs: {} as Record<string, string>,
  infos: [] as string[],
  warnings: [] as string[],
  failed: [] as string[],
  outputs: {} as Record<string, string>,
  octokitCalls: 0,
  checkoutDirs: [] as string[],
  files: {} as Record<string, string>,
  context: {
    repo: { owner: 'Acme', repo: 'App' },
    sha: 'e'.repeat(40),
    payload: {} as Record<string, unknown>,
  },
}));

vi.mock('@actions/core', () => ({
  getInput: (name: string) => h.inputs[name] ?? '',
  info: (m: string) => { h.infos.push(m); },
  warning: (m: string) => { h.warnings.push(m); },
  setFailed: (m: string) => { h.failed.push(m); },
  setOutput: (k: string, v: string) => { h.outputs[k] = v; },
}));

vi.mock('@actions/github', () => ({
  get context() { return h.context; },
  getOctokit: () => { h.octokitCalls++; return {}; },
}));

vi.mock('../gitCheckout.js', () => ({
  gitCheckout: (dir: string) => {
    h.checkoutDirs.push(dir);
    const enc = new TextEncoder();
    return {
      listFiles: async () => Object.keys(h.files),
      size: async (p: string) => (p in h.files ? enc.encode(h.files[p]).length : null),
      read: async (p: string) => enc.encode(h.files[p]),
      headSha: async () => 'f'.repeat(40),
    };
  },
}));

const BASE_URL = 'https://pc.example.test';
const EMPTY_ALLOWLIST = { emails: [], names: [], domains: [], ip_ranges: [], ibans: [] };
const endpointRule = {
  id: 'eaa-ci-ai-endpoint', name: 'Endpoint', articles: [], relevance: ['assessment'], action: 'review', tier: 2, baseline: true,
  detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: '(?i)api\\.openai\\.com', mask: 'Hosted model endpoint' },
};
const schema2 = {
  schema: 2,
  rulesets: [
    { framework: 'Data Compliance', ruleset_version: 3, ruleset_hash: 'a'.repeat(64), rules: [], allowlist: EMPTY_ALLOWLIST, signatures: {}, dropped_rules: [] },
    { framework: 'EU AI Act', ruleset_version: 1, ruleset_hash: 'b'.repeat(64), rules: [endpointRule], allowlist: EMPTY_ALLOWLIST, signatures: {}, dropped_rules: [] },
  ],
};

interface FetchCall { url: string; method: string; body?: unknown }
let calls: FetchCall[];
function stubFetch(postStatus = 200, postBody: unknown = { ok: true, stored: true }) {
  calls = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: init?.body ? JSON.parse(init.body as string) : undefined });
    const status = method === 'GET' ? 200 : postStatus;
    return { ok: status >= 200 && status < 300, status, json: async () => (method === 'GET' ? schema2 : postBody) } as unknown as Response;
  }));
}

async function runEntry() {
  vi.resetModules();
  await import('../index.js');
  for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0));
}

beforeEach(() => {
  h.inputs = { 'pulsecheck-token': 'tok_123', 'pulsecheck-url': BASE_URL, 'github-token': 'ghs_abc', 'scan-mode': 'baseline', 'fail-on': 'Data Compliance, EU AI Act' };
  h.infos = []; h.warnings = []; h.failed = []; h.outputs = {}; h.octokitCalls = 0; h.checkoutDirs = [];
  h.files = { 'src/a.ts': 'const u = "https://api.openai.com";\n' };
  h.context = { repo: { owner: 'Acme', repo: 'App' }, sha: 'e'.repeat(40), payload: {} };
  delete process.env.GITHUB_WORKSPACE;
});
afterEach(() => vi.unstubAllGlobals());

describe('index.ts: scan-mode', () => {
  it('an invalid scan-mode fails the step with a clear message, before anything is fetched', async () => {
    h.inputs['scan-mode'] = 'nightly';
    stubFetch();
    await runEntry();
    expect(h.failed).toEqual([`scan-mode must be 'pr' or 'baseline' (got "nightly").`]);
    expect(calls).toEqual([]);
  });

  it('baseline: needs no pull request, creates no Octokit (no check run), posts the inventory, sets no verdict', async () => {
    stubFetch();
    await runEntry();
    expect(h.failed).toEqual([]);
    expect(h.octokitCalls).toBe(0);
    expect(calls.map((c) => `${c.method} ${c.url.split('?')[0]}`)).toEqual([
      `GET ${BASE_URL}/functions/v1/ci-ruleset`,
      `POST ${BASE_URL}/functions/v1/ci-inventory-result`,
    ]);
    expect(calls[1].body).toEqual({
      repo: 'Acme/App', provider: 'github', commit_sha: 'f'.repeat(40), files_scanned: 1, truncated: false,
      observations: [{ rule_id: 'eaa-ci-ai-endpoint', signature_key: 'openai', count: 1 }],
    });
    expect(h.outputs).toEqual({});
  });

  it('baseline: walks GITHUB_WORKSPACE when set, else the working directory', async () => {
    stubFetch();
    process.env.GITHUB_WORKSPACE = '/w/acme';
    await runEntry();
    expect(h.checkoutDirs).toEqual(['/w/acme']);
    delete process.env.GITHUB_WORKSPACE;
    await runEntry();
    expect(h.checkoutDirs[1]).toBe(process.cwd());
  });

  it('baseline: fail-on is ignored, even with a pull request in the payload', async () => {
    h.context.payload = { pull_request: { number: 7, body: '', head: { sha: 'abc' } } };
    stubFetch();
    await runEntry();
    expect(h.failed).toEqual([]);
    expect(h.octokitCalls).toBe(0);
  });

  it('baseline-sample-paths: true sends paths; an invalid value warns and keeps them off', async () => {
    h.inputs['baseline-sample-paths'] = 'true';
    stubFetch();
    await runEntry();
    expect((calls[1].body as { observations: Array<{ sample_paths?: string[] }> }).observations[0].sample_paths).toEqual(['src/a.ts']);

    h.inputs['baseline-sample-paths'] = 'yes please';
    stubFetch();
    await runEntry();
    expect((calls[1].body as { observations: Array<Record<string, unknown>> }).observations[0]).not.toHaveProperty('sample_paths');
    expect(h.warnings.join('\n')).toMatch(/baseline-sample-paths/);
  });

  it('baseline without a token is inert: nothing fetched, nothing failed', async () => {
    h.inputs['pulsecheck-token'] = '';
    stubFetch();
    await runEntry();
    expect(calls).toEqual([]);
    expect(h.failed).toEqual([]);
    expect(h.infos.join('\n')).toMatch(/inert/);
  });

  it('baseline: a 403 from ci-inventory-result is a warning, never a failed step', async () => {
    stubFetch(403, { error: { code: 'forbidden' } });
    await runEntry();
    expect(h.failed).toEqual([]);
    expect(h.warnings.join('\n')).toMatch(/inventory:write/);
  });

  it('baseline: the default URL is used when pulsecheck-url is empty', async () => {
    h.inputs['pulsecheck-url'] = '';
    stubFetch();
    await runEntry();
    expect(calls[0].url.startsWith('https://nmvlxonedqnejdevrchx.supabase.co/functions/v1/ci-ruleset?')).toBe(true);
  });
});
