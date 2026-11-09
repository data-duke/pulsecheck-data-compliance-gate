/**
 * Provider threading (PR D): GitHub stays byte-for-byte what it was, GitLab says so, and a GitLab merge request is never
 * recorded as a GitHub pull request.
 *
 * The server defaults an absent `provider` to `github`. Two paths in this Action produce a request with no provider:
 * the legacy (pre-multi-framework) post, and the retry of a refused schema-2 post in that legacy shape. For GitHub that
 * is a harmless fallback; for GitLab it would store the merge request as a GitHub PR of the same path, so for any other
 * provider neither path may run.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchRulesets } from '../ruleset.js';
import { buildSchema2Payload, postResults } from '../report.js';
import { scanFrameworks } from '../orchestrate.js';
import { DEFAULT_FRAMEWORK } from '../frameworks.js';
import type { FrameworkRuleset, Rule } from '../types.js';

const EMPTY_ALLOWLIST = { emails: [], names: [], domains: [], ip_ranges: [], ibans: [] };
const iban = (): Rule => ({
  id: 'dc-pii-iban', name: 'IBAN', gdpr_article: ['Art 32'], action: 'block', tier: 1,
  detect: { method: 'checksum', target: 'diff', diff_side: 'added', validator: ['iban'], mask: 'IBAN (masked)' },
});
const aiRule = (): Rule => ({
  id: 'eaa-ci-endpoint', name: 'Hosted model endpoint', articles: ['Art. 15'], relevance: ['control'], action: 'review', tier: 2,
  detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: 'api\\.openai\\.com', mask: 'Model endpoint' },
});
const dc: FrameworkRuleset = {
  framework: DEFAULT_FRAMEWORK, ruleset_version: 3, ruleset_hash: 'a'.repeat(64), rules: [iban()],
  allowlist: EMPTY_ALLOWLIST, signatures: { 'telemetry-sdks': [], 'pii-datastore-credentials': [], 'processor-jurisdiction': [] }, dropped_rules: [],
};
const eu: FrameworkRuleset = {
  framework: 'EU AI Act', ruleset_version: 1, ruleset_hash: 'b'.repeat(64), rules: [aiRule()],
  allowlist: EMPTY_ALLOWLIST, signatures: {}, dropped_rules: [],
};
const diff = ['diff --git a/a.ts b/a.ts', '--- a/a.ts', '+++ b/a.ts', '@@ -1,1 +1,2 @@', ' x', '+const u = "https://api.openai.com/v1";'].join('\n') + '\n';
const outcomes = scanFrameworks([dc, eu], { diff, prDescription: '', truncated: false }, ['EU AI Act']);
const BASE = { repo: 'acme/group/app', pr_number: 12, commit_sha: 'abc123' };

type Call = { url: string; body?: Record<string, unknown> };
function stubFetch(responses: Array<{ status: number; body?: unknown }>): Call[] {
  const calls: Call[] = [];
  let i = 0;
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, body: init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined });
    const r = responses[Math.min(i++, responses.length - 1)];
    return { ok: r.status >= 200 && r.status < 300, status: r.status, json: async () => r.body ?? {} } as unknown as Response;
  }));
  return calls;
}

afterEach(() => vi.unstubAllGlobals());

describe('fetchRulesets and the provider', () => {
  const rulesetBody = { schema: 2, rulesets: [] };

  it('sends no provider parameter for GitHub, so the request is byte-identical to before', async () => {
    const calls = stubFetch([{ status: 200, body: rulesetBody }]);
    await fetchRulesets('https://x.test', 't', ['context'], 'acme/app').catch(() => undefined);
    expect(calls[0].url).toBe('https://x.test/functions/v1/ci-ruleset?schema=2&caps=context&repo=acme%2Fapp');
    await fetchRulesets('https://x.test', 't', ['context'], 'acme/app', 'github').catch(() => undefined);
    expect(calls[1].url).toBe(calls[0].url);
  });

  it('names a GitLab project so the registry context is looked up under gitlab, nested groups included', async () => {
    const calls = stubFetch([{ status: 200, body: rulesetBody }]);
    await fetchRulesets('https://x.test', 't', ['context'], 'acme/group/app', 'gitlab').catch(() => undefined);
    const u = new URL(calls[0].url);
    expect(u.searchParams.get('provider')).toBe('gitlab');
    expect(u.searchParams.get('repo')).toBe('acme/group/app');
  });
});

describe('the verdict post and the provider', () => {
  it('posts provider "github" by default and "gitlab" when asked, with everything else equal', () => {
    expect(buildSchema2Payload(BASE, outcomes).provider).toBe('github');
    expect(buildSchema2Payload({ ...BASE, provider: 'github' }, outcomes).provider).toBe('github');
    const gl = buildSchema2Payload({ ...BASE, provider: 'gitlab' }, outcomes);
    expect(gl.provider).toBe('gitlab');
    expect(gl.repo).toBe('acme/group/app');
    expect(gl.pr_number).toBe(12);
    expect(gl.results.map((r) => r.framework)).toEqual([DEFAULT_FRAMEWORK, 'EU AI Act']);
  });

  it('GitHub keeps its legacy retry after a 400 (unchanged)', async () => {
    const calls = stubFetch([{ status: 400, body: {} }, { status: 200, body: {} }]);
    const res = await postResults('https://x.test', 't', BASE, outcomes, 'schema2');
    expect(calls).toHaveLength(2);
    expect(calls[1].body?.provider).toBeUndefined(); // the legacy body: this is why it must never run for GitLab
    expect(res.ok).toBe(true);
  });

  it('GitLab is NEVER retried in the legacy shape: that body has no provider and would be stored as a GitHub PR', async () => {
    const calls = stubFetch([{ status: 400, body: { error: { code: 'bad_request' } } }, { status: 200, body: {} }]);
    const res = await postResults('https://x.test', 't', { ...BASE, provider: 'gitlab' }, outcomes, 'schema2');
    expect(calls).toHaveLength(1);
    expect(calls[0].body?.provider).toBe('gitlab');
    expect(res.ok).toBe(false);
    expect(res.status).toBe(400);
  });

  it('GitLab is not retried after a 5xx either, even with another framework riding along', async () => {
    const calls = stubFetch([{ status: 502 }, { status: 200 }]);
    const res = await postResults('https://x.test', 't', { ...BASE, provider: 'gitlab' }, outcomes, 'schema2');
    expect(calls).toHaveLength(1);
    expect(res.ok).toBe(false);
  });

  it('GitLab against a legacy-only server posts nothing at all and says why', async () => {
    const calls = stubFetch([{ status: 200 }]);
    const res = await postResults('https://x.test', 't', { ...BASE, provider: 'gitlab' }, outcomes, 'legacy');
    expect(calls).toHaveLength(0);
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/GitLab/i);
    expect(res.error).toMatch(/not recorded/i);
  });

  it('GitHub against a legacy-only server still posts the Data Compliance verdict (unchanged)', async () => {
    const calls = stubFetch([{ status: 200 }]);
    const res = await postResults('https://x.test', 't', BASE, outcomes, 'legacy');
    expect(calls).toHaveLength(1);
    expect(calls[0].body?.provider).toBeUndefined();
    expect(res.ok).toBe(true);
  });
});
