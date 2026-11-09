/**
 * The optional GitLab merge request note (PR F3): addressing, body, create-or-update-in-place, and the CLI wiring. The note is
 * opt-in by PULSECHECK_GITLAB_TOKEN and best effort: it never changes the verdict or the exit code, and the token never
 * reaches an output, a git process or the wrong host.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { NOTE_MARKER, NOTE_MAX_FINDINGS, buildNoteBody, postMergeRequestNote, readNoteTarget } from '../gitlabNote.js';
import { runCli, type CliDeps } from '../cli.js';
import type { FrameworkOutcome } from '../orchestrate.js';
import type { Rule } from '../types.js';

const GL_TOKEN = 'glpat-SECRETGITLABTOKEN0123';
// Built at runtime: a whole ci_live_… literal trips the publish leak screen (scripts/publish-gate-action.sh), dummy or not.
const PC_TOKEN = ['ci_live', 'SECRETTOKENVALUE0123456789'].join('_');
const NOTE_ENV = { CI_API_V4_URL: 'https://gitlab.example.com/api/v4', CI_MERGE_REQUEST_PROJECT_ID: '4242', CI_MERGE_REQUEST_IID: '12' };
const TARGET = { apiUrl: 'https://gitlab.example.com/api/v4', projectId: '4242', iid: 12 };

describe('readNoteTarget', () => {
  it('reads the API root, project id and iid from the pipeline variables', () => {
    expect(readNoteTarget(NOTE_ENV)).toEqual(TARGET);
    expect(readNoteTarget({ ...NOTE_ENV, CI_API_V4_URL: 'https://gitlab.internal:8443/api/v4/' })).toMatchObject({ apiUrl: 'https://gitlab.internal:8443/api/v4' });
  });
  it.each([
    { CI_API_V4_URL: undefined }, { CI_API_V4_URL: 'ftp://x/api/v4' }, { CI_API_V4_URL: 'http://gitlab.internal/api/v4' }, { CI_API_V4_URL: 'not a url' },
    { CI_MERGE_REQUEST_PROJECT_ID: undefined }, { CI_MERGE_REQUEST_PROJECT_ID: '12/../3' }, { CI_MERGE_REQUEST_PROJECT_ID: 'acme/api' },
    { CI_MERGE_REQUEST_IID: '0' }, { CI_MERGE_REQUEST_IID: 'x' },
  ])('is null for %j', (over) => expect(readNoteTarget({ ...NOTE_ENV, ...over })).toBeNull());
});

const finding = (over: Record<string, unknown> = {}) => ({ rule_id: 'eaa-ci-endpoint', articles: ['Art. 15'], action: 'review', masked_evidence: 'Model endpoint: api.openai.com', ...over });
const outcome = (verdict: string, findings: unknown[]): FrameworkOutcome => ({ framework: 'EU AI Act', result: { verdict, findings, warnings: [] } } as unknown as FrameworkOutcome);

describe('buildNoteBody', () => {
  it('starts with the marker and states the verdict per framework', () => {
    const body = buildNoteBody([outcome('needs_review', [finding()])]);
    expect(body.startsWith(NOTE_MARKER)).toBe(true);
    expect(body).toContain('**AI change control:** ⚠️ needs review');
    expect(body).toContain('eaa-ci-endpoint');
    expect(body).toContain('Model endpoint: api.openai.com');
  });

  it('a clean scan lists no table', () => {
    const body = buildNoteBody([outcome('pass', [])]);
    expect(body).toContain('✅ passed');
    expect(body).not.toContain('| Action |');
  });

  it('puts finding text in code spans: no backtick breakout, no line breaks, no mention that would notify someone', () => {
    const body = buildNoteBody([outcome('fail', [finding({ masked_evidence: 'x` @everyone [click](https://evil)\n| a | b |', rule_id: 'r`ule' })])]);
    const row = body.split('\n').find((l) => l.startsWith('| review'))!;
    expect(row).toBeDefined();
    expect(row.match(/\|/g)!.length).toBeGreaterThanOrEqual(4); // the table stays a table
    expect(row).not.toMatch(/`[^`]*`[^|]*`[^`]*`[^|]*`/); // each cell is exactly one span
    expect(body.split('\n').filter((l) => l.includes('@everyone'))).toHaveLength(1);
    // Pipes are escaped, so the table cell (and with it the code span) ends only where the cell does.
    expect(row).toContain('`x @everyone [click](https://evil) \\| a \\| b \\|`');
  });

  it('shows the most severe findings first and counts the rest past the cap', () => {
    const many = [
      ...Array.from({ length: NOTE_MAX_FINDINGS + 5 }, (_, i) => finding({ rule_id: `adv-${i}`, action: 'advise' })),
      finding({ rule_id: 'blocking-one', action: 'block' }),
    ];
    const body = buildNoteBody([outcome('fail', many)]);
    expect(body).toContain('blocking-one');
    expect(body).toMatch(/…and 6 more finding\(s\)/);
  });

  it('keeps a pipe inside the evidence from ending its table cell: exactly three unescaped cell separators plus the edges', () => {
    const row = buildNoteBody([outcome('fail', [finding({ masked_evidence: 'a || b | @all [x](https://evil) <img src=https://evil/p>' })])]).split('\n').find((l) => l.startsWith('| review'))!;
    const unescapedPipes = row.match(/(?<!\\)\|/g)!;
    expect(unescapedPipes).toHaveLength(4); // | action | rule | evidence |
    expect(row.endsWith('`|') || row.endsWith('` |')).toBe(true);
  });

  it('bounds a long evidence string', () => {
    expect(buildNoteBody([outcome('fail', [finding({ masked_evidence: 'e'.repeat(5000) })])]).length).toBeLessThan(2000);
  });
});

/** The JSON body a GitLab note request carries (`{ body: <markdown> }`). */
interface Call { url: string; method: string; headers: Record<string, string>; body?: { body: string } }
function stubGitlab(handlers: Record<string, (c: Call) => { status: number; json?: unknown }>): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const call: Call = { url, method: init?.method ?? 'GET', headers: (init?.headers ?? {}) as Record<string, string>, body: init?.body ? JSON.parse(String(init.body)) : undefined };
    calls.push(call);
    const key = Object.keys(handlers).find((k) => `${call.method} ${new URL(url).pathname}`.startsWith(k));
    const r = key ? handlers[key](call) : { status: 404 };
    return { ok: r.status >= 200 && r.status < 300, status: r.status, json: async () => r.json } as unknown as Response;
  }));
  return calls;
}
afterEach(() => vi.unstubAllGlobals());

describe('postMergeRequestNote', () => {
  const base = '/api/v4/projects/4242/merge_requests/12/notes';

  it('creates a note when none of ours exists, sending the token only as PRIVATE-TOKEN to the instance', async () => {
    const calls = stubGitlab({
      'GET /api/v4/user': () => ({ status: 200, json: { id: 7 } }),
      [`GET ${base}`]: () => ({ status: 200, json: [{ id: 1, body: 'a human comment', author: { id: 9 } }] }),
      [`POST ${base}`]: () => ({ status: 201, json: { id: 2 } }),
    });
    expect(await postMergeRequestNote(TARGET, GL_TOKEN, `${NOTE_MARKER}\nhello`)).toEqual({ ok: true, action: 'created' });
    expect(calls.every((c) => new URL(c.url).host === 'gitlab.example.com')).toBe(true);
    expect(calls.every((c) => c.headers['PRIVATE-TOKEN'] === GL_TOKEN && !('Authorization' in c.headers))).toBe(true);
    expect(calls.at(-1)!.body).toEqual({ body: `${NOTE_MARKER}\nhello` });
  });

  it('updates OUR previous note in place instead of adding another', async () => {
    const calls = stubGitlab({
      'GET /api/v4/user': () => ({ status: 200, json: { id: 7 } }),
      [`GET ${base}`]: () => ({ status: 200, json: [{ id: 5, body: `${NOTE_MARKER}\nold`, author: { id: 7 }, system: false }] }),
      [`PUT ${base}/5`]: () => ({ status: 200, json: { id: 5 } }),
    });
    expect(await postMergeRequestNote(TARGET, GL_TOKEN, `${NOTE_MARKER}\nnew`)).toEqual({ ok: true, action: 'updated' });
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
  });

  it('never overwrites someone else\'s comment that merely contains the marker, nor a system note', async () => {
    const calls = stubGitlab({
      'GET /api/v4/user': () => ({ status: 200, json: { id: 7 } }),
      [`GET ${base}`]: () => ({ status: 200, json: [
        { id: 3, body: `${NOTE_MARKER} forged`, author: { id: 99 } },
        { id: 4, body: `${NOTE_MARKER}`, author: { id: 7 }, system: true },
      ] }),
      [`POST ${base}`]: () => ({ status: 201, json: {} }),
    });
    expect(await postMergeRequestNote(TARGET, GL_TOKEN, NOTE_MARKER)).toEqual({ ok: true, action: 'created' });
    expect(calls.some((c) => c.method === 'PUT')).toBe(false);
  });

  it('adds NO note when a lookup failed or was incomplete: a transient error must not become one more comment per pipeline', async () => {
    let calls = stubGitlab({ 'GET /api/v4/user': () => ({ status: 401 }), [`POST ${base}`]: () => ({ status: 201, json: {} }) });
    expect(await postMergeRequestNote(TARGET, GL_TOKEN, NOTE_MARKER)).toMatchObject({ ok: false });
    expect(calls.some((c) => c.method === 'POST' || c.method === 'PUT')).toBe(false);
    calls = stubGitlab({ 'GET /api/v4/user': () => ({ status: 200, json: { id: 7 } }), [`GET ${base}`]: () => ({ status: 503 }), [`POST ${base}`]: () => ({ status: 201, json: {} }) });
    expect(await postMergeRequestNote(TARGET, GL_TOKEN, NOTE_MARKER)).toMatchObject({ ok: false });
    expect(calls.some((c) => c.method === 'POST' || c.method === 'PUT')).toBe(false);
  });

  it('finds our note on a later page of a busy merge request', async () => {
    const full = Array.from({ length: 100 }, (_, i) => ({ id: 100 + i, body: 'x', author: { id: 9 } }));
    const calls = stubGitlab({
      'GET /api/v4/user': () => ({ status: 200, json: { id: 7 } }),
      [`GET ${base}`]: (c) => (new URL(c.url).searchParams.get('page') === '1' ? { status: 200, json: full } : { status: 200, json: [{ id: 5, body: NOTE_MARKER, author: { id: 7 } }] }),
      [`PUT ${base}/5`]: () => ({ status: 200, json: {} }),
    });
    expect(await postMergeRequestNote(TARGET, GL_TOKEN, NOTE_MARKER)).toEqual({ ok: true, action: 'updated' });
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
  });

  it('never follows a redirect, so the token cannot be forwarded to another host', async () => {
    const seen: RequestInit[] = [];
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) => { seen.push(init ?? {}); throw new TypeError('fetch failed'); }));
    const r = await postMergeRequestNote(TARGET, GL_TOKEN, NOTE_MARKER);
    expect(r.ok).toBe(false);
    expect(seen.length).toBeGreaterThan(0);
    expect(seen.every((i) => i.redirect === 'error')).toBe(true);
  });

  it('reports an HTTP refusal and a network error without the token', async () => {
    stubGitlab({ 'GET /api/v4/user': () => ({ status: 200, json: { id: 7 } }), [`GET ${base}`]: () => ({ status: 200, json: [] }), [`POST ${base}`]: () => ({ status: 403 }) });
    expect(await postMergeRequestNote(TARGET, GL_TOKEN, NOTE_MARKER)).toEqual({ ok: false, error: 'GitLab answered HTTP 403' });
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error(`connect failed for ${GL_TOKEN}`); }));
    const r = await postMergeRequestNote(TARGET, GL_TOKEN, NOTE_MARKER);
    expect(r.ok).toBe(false);
    expect(JSON.stringify(r)).not.toContain(GL_TOKEN);
  });
});

// ── CLI wiring ──────────────────────────────────────────────────────────────────────────────────

const EMPTY_ALLOWLIST = { emails: [], names: [], domains: [], ip_ranges: [], ibans: [] };
const reviewRule = (): Rule => ({
  id: 'eaa-ci-endpoint', name: 'Hosted model endpoint', articles: ['Art. 15'], relevance: ['control'], action: 'review', tier: 2,
  detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: 'api\\.openai\\.com', mask: 'Model endpoint' },
});
const DIFF = ['diff --git a/src/ai.ts b/src/ai.ts', '--- a/src/ai.ts', '+++ b/src/ai.ts', '@@ -1,1 +1,2 @@', ' x', '+fetch("https://api.openai.com/v1/chat");'].join('\n') + '\n';
const MR_ENV: Record<string, string | undefined> = {
  GITLAB_CI: 'true', CI_PIPELINE_SOURCE: 'merge_request_event', CI_MERGE_REQUEST_IID: '12',
  CI_MERGE_REQUEST_PROJECT_PATH: 'acme/platform/api', CI_PROJECT_PATH: 'acme/platform/api', CI_PROJECT_DIR: '/builds/acme/platform/api',
  CI_COMMIT_SHA: 'a'.repeat(40), CI_MERGE_REQUEST_DIFF_BASE_SHA: 'b'.repeat(40), CI_MERGE_REQUEST_DESCRIPTION: '', CI_MERGE_REQUEST_DESCRIPTION_IS_TRUNCATED: 'false',
  PULSECHECK_TOKEN: PC_TOKEN, ...NOTE_ENV,
};
function deps(): { deps: CliDeps; out: string[]; err: string[] } {
  const out: string[] = []; const err: string[] = [];
  return { deps: { out: (l) => out.push(l), err: (l) => err.push(l), cwd: '/work', writeFile: async () => undefined, readDiff: async () => DIFF }, out, err };
}
function stubAll(note: { status: number }): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET';
    calls.push({ url, method, headers: (init?.headers ?? {}) as Record<string, string>, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    const path = new URL(url).pathname;
    let r: { status: number; json?: unknown };
    if (path.endsWith('/ci-ruleset')) r = { status: 200, json: { schema: 2, rulesets: [{ framework: 'EU AI Act', ruleset_version: 1, ruleset_hash: 'b'.repeat(64), rules: [reviewRule()], allowlist: EMPTY_ALLOWLIST, signatures: {}, dropped_rules: [] }] } };
    else if (path.endsWith('/ci-scan-result')) r = { status: 200, json: {} };
    else if (path === '/api/v4/user') r = { status: 200, json: { id: 7 } };
    else if (method === 'GET') r = { status: 200, json: [] };
    else r = note;
    return { ok: r.status >= 200 && r.status < 300, status: r.status, json: async () => r.json } as unknown as Response;
  }));
  return calls;
}

describe('runCli and the merge request note', () => {
  it('posts nothing to GitLab without PULSECHECK_GITLAB_TOKEN', async () => {
    const calls = stubAll({ status: 201 });
    const d = deps();
    expect(await runCli([], MR_ENV, d.deps)).toBe(0);
    expect(calls.some((c) => c.url.includes('gitlab.example.com'))).toBe(false);
  });

  it('with the token, posts one note carrying the masked findings, and keeps the two tokens apart', async () => {
    const calls = stubAll({ status: 201 });
    const d = deps();
    expect(await runCli([], { ...MR_ENV, PULSECHECK_GITLAB_TOKEN: GL_TOKEN }, d.deps)).toBe(0);
    const gitlabCalls = calls.filter((c) => c.url.includes('gitlab.example.com'));
    const post = gitlabCalls.find((c) => c.method === 'POST')!;
    expect(post.body.body).toContain(NOTE_MARKER);
    expect(post.body.body).toContain('eaa-ci-endpoint');
    expect(gitlabCalls.every((c) => c.headers['PRIVATE-TOKEN'] === GL_TOKEN)).toBe(true);
    // The PulseCheck token goes only to PulseCheck; the GitLab token only to GitLab.
    expect(calls.filter((c) => !c.url.includes('gitlab.example.com')).every((c) => !JSON.stringify(c.headers).includes(GL_TOKEN))).toBe(true);
    expect(gitlabCalls.every((c) => !JSON.stringify(c.headers).includes(PC_TOKEN))).toBe(true);
    expect(d.out.join('\n')).toContain('Merge request note created.');
  });

  it('a refused note is a warning only: same exit code, no token in any output', async () => {
    stubAll({ status: 403 });
    const d = deps();
    expect(await runCli([], { ...MR_ENV, PULSECHECK_GITLAB_TOKEN: GL_TOKEN }, d.deps)).toBe(0);
    const all = [...d.out, ...d.err].join('\n');
    expect(all).toContain('Could not post the merge request note (GitLab answered HTTP 403)');
    expect(all).not.toContain(GL_TOKEN);
    expect(all).not.toContain(PC_TOKEN);
  });

  it('warns, and posts nothing, when the job lacks the API variables', async () => {
    const calls = stubAll({ status: 201 });
    const d = deps();
    expect(await runCli([], { ...MR_ENV, PULSECHECK_GITLAB_TOKEN: GL_TOKEN, CI_API_V4_URL: undefined }, d.deps)).toBe(0);
    expect(calls.some((c) => c.url.includes('gitlab.example.com'))).toBe(false);
    expect(d.err.join('\n')).toContain('no merge request note was posted');
  });

  it('a failing --fail-on framework still exits 1 when the note is refused (the note never changes the verdict)', async () => {
    const blocking = { ...reviewRule(), id: 'eaa-ci-block', action: 'block', tier: 1 } as Rule;
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      const path = new URL(url).pathname;
      const r = path.endsWith('/ci-ruleset')
        ? { status: 200, json: { schema: 2, rulesets: [{ framework: 'EU AI Act', ruleset_version: 1, ruleset_hash: 'b'.repeat(64), rules: [blocking], allowlist: EMPTY_ALLOWLIST, signatures: {}, dropped_rules: [] }] } }
        : path.endsWith('/ci-scan-result') ? { status: 200, json: {} }
        : url.includes('gitlab.example.com') ? { status: 500, json: {} } : { status: 404, json: {} };
      return { ok: r.status < 300, status: r.status, json: async () => r.json, method: init?.method } as unknown as Response;
    }));
    const d = deps();
    expect(await runCli(['--fail-on', 'EU AI Act'], { ...MR_ENV, PULSECHECK_GITLAB_TOKEN: GL_TOKEN }, d.deps)).toBe(1);
    expect(d.err.join('\n')).toContain('Could not post the merge request note');
  });
});
