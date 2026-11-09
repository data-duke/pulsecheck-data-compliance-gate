/**
 * The `pulsecheck-gate` CLI (PR D), driven end to end: real argument parsing, real GitLab context reading, the REAL core
 * (`runGate`), real scanning and report building. Only the network (`fetch`), git (`readDiff`) and the file system
 * (`writeFile`) are replaced, so what is asserted is the wiring: which requests go out, with which provider and path, what
 * is written for GitLab, and the exit code.
 *
 * Exit codes: 0 pass, advisory, inert, or PulseCheck unreachable / diff unreadable (never block on an outage, as the
 * Action); 1 a `--fail-on` framework failed; 2 usage or configuration error.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CLI_USAGE, parseCliArgs, runCli, type CliDeps } from '../cli.js';
import type { Rule } from '../types.js';

// Built at runtime: a whole ci_live_… literal trips the publish leak screen (scripts/publish-gate-action.sh), dummy or not.
const TOKEN = ['ci_live', 'SECRETTOKENVALUE0123456789'].join('_');
const EMPTY_ALLOWLIST = { emails: [], names: [], domains: [], ip_ranges: [], ibans: [] };

const MR_ENV: Record<string, string | undefined> = {
  GITLAB_CI: 'true',
  CI_PIPELINE_SOURCE: 'merge_request_event',
  CI_MERGE_REQUEST_IID: '12',
  CI_MERGE_REQUEST_PROJECT_PATH: 'acme/platform/api',
  CI_PROJECT_PATH: 'acme/platform/api',
  CI_PROJECT_DIR: '/builds/acme/platform/api',
  CI_COMMIT_SHA: 'a'.repeat(40),
  CI_MERGE_REQUEST_DIFF_BASE_SHA: 'b'.repeat(40),
  CI_MERGE_REQUEST_DESCRIPTION: 'Adds the summariser.',
  CI_MERGE_REQUEST_DESCRIPTION_IS_TRUNCATED: 'false',
  PULSECHECK_TOKEN: TOKEN,
};

const reviewRule = (): Rule => ({
  id: 'eaa-ci-endpoint', name: 'Hosted model endpoint', articles: ['Art. 15'], relevance: ['control'], action: 'review', tier: 2,
  detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: 'api\\.openai\\.com', mask: 'Model endpoint' },
});
const blockRule = (): Rule => ({ ...reviewRule(), id: 'eaa-ci-block', action: 'block', tier: 1 });
const rulesetBody = (rules: Rule[]) => ({
  schema: 2,
  rulesets: [{ framework: 'EU AI Act', ruleset_version: 1, ruleset_hash: 'b'.repeat(64), rules, allowlist: EMPTY_ALLOWLIST, signatures: {}, dropped_rules: [] }],
});
const DIFF = ['diff --git a/src/ai.ts b/src/ai.ts', '--- a/src/ai.ts', '+++ b/src/ai.ts', '@@ -1,1 +1,2 @@', ' x', '+fetch("https://api.openai.com/v1/chat");'].join('\n') + '\n';

interface Call { url: string; method: string; body?: Record<string, unknown> }
function stubNetwork(opts: { ruleset?: { status: number; body?: unknown }; post?: { status: number; body?: unknown } } = {}): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined });
    const r = url.includes('/ci-ruleset') ? (opts.ruleset ?? { status: 200, body: rulesetBody([reviewRule()]) }) : (opts.post ?? { status: 200, body: {} });
    return { ok: r.status >= 200 && r.status < 300, status: r.status, json: async () => r.body ?? {} } as unknown as Response;
  }));
  return calls;
}

function makeDeps(over: Partial<CliDeps> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const files = new Map<string, string>();
  const readDiff = vi.fn(async () => DIFF);
  const deps: CliDeps = {
    out: (l) => out.push(l),
    err: (l) => err.push(l),
    cwd: '/work',
    writeFile: async (p, c) => { files.set(p, c); },
    readDiff,
    ...over,
  };
  return { deps, out, err, files, readDiff };
}

afterEach(() => vi.unstubAllGlobals());

describe('parseCliArgs', () => {
  it('reads flags in both "--flag value" and "--flag=value" form', () => {
    expect(parseCliArgs(['--provider', 'gitlab', '--fail-on=EU AI Act', '--diff-cap-bytes', '1000', '--code-quality', 'out/cq.json'])).toEqual({
      provider: 'gitlab', failOn: 'EU AI Act', diffCap: 1000, codeQuality: 'out/cq.json',
    });
  });
  it('has no --token flag: a token on the command line is visible to every process on the runner', () => {
    const r = parseCliArgs(['--token', 'x']);
    expect('error' in r && r.error).toMatch(/PULSECHECK_TOKEN/);
    expect(CLI_USAGE).toContain('PULSECHECK_TOKEN');
    expect(CLI_USAGE).not.toMatch(/--token/);
  });
  it('rejects unknown flags, stray words, a missing value and a bad number', () => {
    for (const argv of [['--nope'], ['stray'], ['--provider'], ['--diff-cap-bytes', 'abc'], ['--diff-cap-bytes', '-5'], ['--provider', 'svn']]) {
      expect('error' in parseCliArgs(argv)).toBe(true);
    }
  });
  it('rejects an empty --code-quality value instead of writing to the directory itself', () => {
    expect(parseCliArgs(['--code-quality='])).toHaveProperty('error');
    expect(parseCliArgs(['--code-quality', ' '])).toHaveProperty('error');
  });

  it('accepts --no-code-quality and --help/--version', () => {
    expect(parseCliArgs(['--no-code-quality'])).toEqual({ codeQuality: null });
    expect(parseCliArgs(['--help'])).toEqual({ help: true });
    expect(parseCliArgs(['--version'])).toEqual({ version: true });
  });
});

describe('runCli: the inert and usage cases', () => {
  it('without PULSECHECK_TOKEN it is inert: no request, no report, exit 0', async () => {
    const calls = stubNetwork();
    const { deps, out, files } = makeDeps();
    expect(await runCli([], { ...MR_ENV, PULSECHECK_TOKEN: undefined }, deps)).toBe(0);
    expect(calls).toHaveLength(0);
    expect(files.size).toBe(0);
    expect(out.join('\n')).toMatch(/inert/i);
  });

  it('is inert in a branch pipeline (no merge request): exit 0, no request', async () => {
    const calls = stubNetwork();
    const { deps, out, files } = makeDeps();
    expect(await runCli([], { ...MR_ENV, CI_PIPELINE_SOURCE: 'push', CI_MERGE_REQUEST_IID: undefined }, deps)).toBe(0);
    expect(calls).toHaveLength(0);
    expect(files.size).toBe(0);
    expect(out.join('\n')).toMatch(/not a merge request pipeline/i);
  });

  it('outside any CI it asks for --provider (exit 2); the GitHub provider is served by the GitHub Action', async () => {
    const { deps, err } = makeDeps();
    expect(await runCli([], { PULSECHECK_TOKEN: TOKEN }, deps)).toBe(2);
    expect(err.join('\n')).toMatch(/--provider/);
    const second = makeDeps();
    expect(await runCli(['--provider', 'github'], { PULSECHECK_TOKEN: TOKEN }, second.deps)).toBe(2);
    expect(second.err.join('\n')).toMatch(/GitHub Action/);
  });

  it('a usage error is exit 2 and prints the usage; --help is exit 0; --version prints the version', async () => {
    const a = makeDeps();
    expect(await runCli(['--bogus'], MR_ENV, a.deps)).toBe(2);
    expect(a.err.join('\n')).toContain('Usage');
    const b = makeDeps();
    expect(await runCli(['--help'], {}, b.deps)).toBe(0);
    expect(b.out.join('\n')).toContain('Usage');
    const c = makeDeps();
    expect(await runCli(['--version'], {}, c.deps)).toBe(0);
    expect(c.out.join('').trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it('a merge request pipeline with a missing variable is a configuration error, exit 2, naming the variable', async () => {
    const calls = stubNetwork();
    const { deps, err } = makeDeps();
    expect(await runCli([], { ...MR_ENV, CI_MERGE_REQUEST_DIFF_BASE_SHA: '' }, deps)).toBe(2);
    expect(err.join('\n')).toContain('CI_MERGE_REQUEST_DIFF_BASE_SHA');
    expect(calls).toHaveLength(0);
  });
});

describe('runCli: a GitLab merge request pipeline', () => {
  it('scans, posts as provider gitlab under the merge request\'s own project path, writes the Code Quality report, exits 0 for an advisory finding', async () => {
    const calls = stubNetwork();
    const { deps, files, readDiff } = makeDeps();
    expect(await runCli([], MR_ENV, deps)).toBe(0);

    expect(readDiff).toHaveBeenCalledWith(expect.objectContaining({ baseSha: 'b'.repeat(40), headSha: 'a'.repeat(40), cwd: '/builds/acme/platform/api' }));

    const ruleset = new URL(calls[0].url);
    expect(ruleset.pathname).toBe('/functions/v1/ci-ruleset');
    expect(ruleset.searchParams.get('provider')).toBe('gitlab');
    expect(ruleset.searchParams.get('repo')).toBe('acme/platform/api');

    const post = calls.find((c) => c.url.includes('/ci-scan-result'))!;
    expect(post.method).toBe('POST');
    expect(post.body).toMatchObject({ repo: 'acme/platform/api', pr_number: 12, commit_sha: 'a'.repeat(40), provider: 'gitlab' });
    expect((post.body!.results as Array<{ framework: string }>).map((r) => r.framework)).toEqual(['EU AI Act']);

    const report = files.get('/builds/acme/platform/api/gl-code-quality-report.json')!;
    const issues = JSON.parse(report) as Array<{ severity: string; location: { path: string; lines: { begin: number } } }>;
    expect(issues).toHaveLength(1);
    expect(issues[0].severity).toBe('major');
    expect(issues[0].location).toEqual({ path: 'src/ai.ts', lines: { begin: 2 } });
  });

  it('exits 1 when a framework listed in --fail-on fails, and still writes the report', async () => {
    stubNetwork({ ruleset: { status: 200, body: rulesetBody([blockRule()]) } });
    const { deps, files, err } = makeDeps();
    expect(await runCli(['--fail-on', 'EU AI Act'], MR_ENV, deps)).toBe(1);
    expect(files.size).toBe(1);
    expect(err.join('\n')).toMatch(/failed/i);
  });

  it('exits 0 for the same blocking finding when its framework is not in --fail-on (advisory)', async () => {
    stubNetwork({ ruleset: { status: 200, body: rulesetBody([blockRule()]) } });
    const { deps } = makeDeps();
    expect(await runCli([], MR_ENV, deps)).toBe(0);
  });

  it('never blocks on an outage: an unreachable ruleset is a warning, exit 0, an empty report and no post', async () => {
    const calls = stubNetwork({ ruleset: { status: 503 } });
    const { deps, files, err } = makeDeps();
    expect(await runCli(['--fail-on', 'EU AI Act'], MR_ENV, deps)).toBe(0);
    expect(calls.some((c) => c.url.includes('/ci-scan-result'))).toBe(false);
    expect(files.get('/builds/acme/platform/api/gl-code-quality-report.json')).toBe('[]\n');
    expect(err.join('\n')).toMatch(/unreachable|Could not reach/i);
  });

  it('never blocks on an unreadable diff: a warning, exit 0, an empty report', async () => {
    stubNetwork();
    const { deps, files, err } = makeDeps({ readDiff: async () => { throw new Error('The base commit bbbbbbbbbbbb is not in this clone'); } });
    expect(await runCli(['--fail-on', 'EU AI Act'], MR_ENV, deps)).toBe(0);
    expect(files.get('/builds/acme/platform/api/gl-code-quality-report.json')).toBe('[]\n');
    expect(err.join('\n')).toMatch(/base commit/);
  });

  it('records nothing against a legacy-only server and says so, never as a GitHub pull request', async () => {
    const calls = stubNetwork({ ruleset: { status: 200, body: { ruleset_version: 3, ruleset_hash: 'a'.repeat(64), rules: [] } } });
    const { deps, err } = makeDeps();
    expect(await runCli([], MR_ENV, deps)).toBe(0);
    expect(calls.some((c) => c.url.includes('/ci-scan-result'))).toBe(false);
    expect(err.join('\n')).toMatch(/predates GitLab support/);
  });

  it('warns that a description cut at 2,700 characters was only partly scanned', async () => {
    stubNetwork();
    const { deps, err } = makeDeps();
    await runCli([], { ...MR_ENV, CI_MERGE_REQUEST_DESCRIPTION: 'x'.repeat(2700), CI_MERGE_REQUEST_DESCRIPTION_IS_TRUNCATED: 'true' }, deps);
    expect(err.join('\n')).toMatch(/2,?700/);
    expect(err.join('\n')).toMatch(/description/i);
  });

  it('honours --code-quality <path> (relative to the project directory) and --no-code-quality', async () => {
    stubNetwork();
    const a = makeDeps();
    await runCli(['--code-quality', 'reports/cq.json'], MR_ENV, a.deps);
    expect([...a.files.keys()]).toEqual(['/builds/acme/platform/api/reports/cq.json']);
    const b = makeDeps();
    await runCli(['--no-code-quality'], MR_ENV, b.deps);
    expect(b.files.size).toBe(0);
  });

  it('a report that cannot be written is a warning, not a failure', async () => {
    stubNetwork();
    const { deps, err } = makeDeps({ writeFile: async () => { throw new Error('EACCES'); } });
    expect(await runCli([], MR_ENV, deps)).toBe(0);
    expect(err.join('\n')).toMatch(/Code Quality report/);
  });

  it('honours --url and PULSECHECK_URL, flag first', async () => {
    const calls = stubNetwork();
    await runCli(['--url', 'https://flag.example'], { ...MR_ENV, PULSECHECK_URL: 'https://env.example' }, makeDeps().deps);
    expect(calls[0].url.startsWith('https://flag.example/')).toBe(true);
    calls.length = 0;
    await runCli([], { ...MR_ENV, PULSECHECK_URL: 'https://env.example' }, makeDeps().deps);
    expect(calls[0].url.startsWith('https://env.example/')).toBe(true);
  });

  it('never prints the token', async () => {
    stubNetwork({ ruleset: { status: 503 } });
    const { deps, out, err } = makeDeps();
    await runCli([], MR_ENV, deps);
    expect([...out, ...err].join('\n')).not.toContain(TOKEN);
  });
});
