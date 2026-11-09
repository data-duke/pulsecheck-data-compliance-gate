/**
 * Reading the merge request diff with git (PR D), against REAL temporary repositories: a mock of `git` would only prove
 * the arguments were assembled, and what matters here is what git does with a shallow clone.
 *
 * GitLab's default clone depth is 20 (documented; overridable with GIT_DEPTH, maximum 1000). The diff is
 * `git diff <base> <head>` with the two commits GitLab names, not a three-dot range: `CI_MERGE_REQUEST_DIFF_BASE_SHA` is
 * already the base of the merge request's diff, and the two-argument form needs only those two commits' trees, so it does
 * not depend on the shared history a shallow clone does not have.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { parseDiff } from '../diff.js';
import { readGitDiff, scrubGitMessage } from '../gitDiff.js';

const dirs: string[] = [];
function tmp(prefix: string): string {
  const d = mkdtempSync(join(tmpdir(), `pcgate-${prefix}-`));
  dirs.push(d);
  return d;
}
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const GIT_ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.test', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.test',
  GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null',
};
const git = (cwd: string, ...args: string[]) => execFileSync('git', args, { cwd, env: GIT_ENV, encoding: 'utf8' }).trim();

/** origin with `main` (3 commits) and `feature` branching from the first commit; returns the commit ids. */
function makeOrigin() {
  const dir = tmp('origin');
  git(dir, 'init', '-q', '-b', 'main');
  mkdirSync(join(dir, 'src'), { recursive: true });
  writeFileSync(join(dir, 'src', 'a.ts'), 'export const a = 1;\n');
  git(dir, 'add', '.');
  git(dir, 'commit', '-q', '-m', 'one');
  const base = git(dir, 'rev-parse', 'HEAD');
  git(dir, 'checkout', '-q', '-b', 'feature');
  writeFileSync(join(dir, 'src', 'a.ts'), 'export const a = 1;\nfetch("https://api.openai.com/v1/chat");\n');
  writeFileSync(join(dir, 'src', 'café.ts'), 'export const b = 2;\n');
  git(dir, 'add', '.');
  git(dir, 'commit', '-q', '-m', 'two');
  const head = git(dir, 'rev-parse', 'HEAD');
  git(dir, 'checkout', '-q', 'main');
  writeFileSync(join(dir, 'unrelated.txt'), 'main moved on\n');
  git(dir, 'add', '.');
  git(dir, 'commit', '-q', '-m', 'three');
  return { dir, base, head };
}

describe('readGitDiff', () => {
  it('returns the unified diff of the merge request in the form the scanner parses', async () => {
    const { dir, base, head } = makeOrigin();
    const diff = await readGitDiff({ cwd: dir, baseSha: base, headSha: head, env: GIT_ENV });
    const parsed = parseDiff(diff);
    const added = parsed.lines.filter((l) => l.side === 'added');
    expect(added.some((l) => l.file === 'src/a.ts' && l.text.includes('api.openai.com'))).toBe(true);
    expect(added.some((l) => l.file === 'src/café.ts')).toBe(true); // not octal-quoted
    expect(parsed.lines.some((l) => l.file === 'unrelated.txt')).toBe(false); // main's later commit is not part of the MR
  });

  it('ignores a user diff configuration (prefixes, external diff tools) so the output is always the same shape', async () => {
    const { dir, base, head } = makeOrigin();
    git(dir, 'config', 'diff.noprefix', 'true');
    git(dir, 'config', 'diff.external', 'false');
    const diff = await readGitDiff({ cwd: dir, baseSha: base, headSha: head, env: { ...GIT_ENV, GIT_CONFIG_GLOBAL: undefined } });
    expect(diff).toContain('diff --git a/src/a.ts b/src/a.ts');
  });

  it('works in a shallow clone that holds only the head: it fetches the base commit by id', async () => {
    const { dir, base, head } = makeOrigin();
    const clone = tmp('clone');
    git(tmp('x'), 'clone', '-q', '--depth', '1', '--branch', 'feature', `file://${dir}`, clone);
    expect(git(clone, 'rev-parse', 'HEAD')).toBe(head);
    expect(() => git(clone, 'cat-file', '-e', `${base}^{commit}`)).toThrow(); // the base really is missing
    const diff = await readGitDiff({ cwd: clone, baseSha: base, headSha: head, env: GIT_ENV });
    expect(diff).toContain('api.openai.com');
  });

  it('fails with an actionable message when the base cannot be found, never with an empty diff', async () => {
    const { dir, head } = makeOrigin();
    const clone = tmp('clone2');
    git(tmp('y'), 'clone', '-q', '--depth', '1', '--branch', 'feature', `file://${dir}`, clone);
    await expect(
      readGitDiff({ cwd: clone, baseSha: 'f'.repeat(40), headSha: head, env: GIT_ENV }),
    ).rejects.toThrow(/GIT_DEPTH|base commit/i);
  });

  it('refuses a value that is not a commit id before any git command runs', async () => {
    const { dir, head } = makeOrigin();
    for (const bad of ['--upload-pack=touch /tmp/pwned', 'main; rm -rf /', '', 'HEAD~1', '-p']) {
      await expect(readGitDiff({ cwd: dir, baseSha: bad, headSha: head, env: GIT_ENV })).rejects.toThrow(/commit id/i);
      await expect(readGitDiff({ cwd: dir, baseSha: head, headSha: bad, env: GIT_ENV })).rejects.toThrow(/commit id/i);
    }
  });
});

describe('scrubGitMessage', () => {
  it('removes credentials embedded in a URL, as git prints them for a CI job token remote', () => {
    const msg = "fatal: unable to access 'https://gitlab-ci-token:glcbt-secret123@gitlab.example.com/acme/api.git/': The requested URL returned error: 403";
    const out = scrubGitMessage(msg);
    expect(out).not.toContain('glcbt-secret123');
    expect(out).not.toContain('gitlab-ci-token');
    expect(out).toContain('gitlab.example.com/acme/api.git');
  });

  it('keeps a message without a credential unchanged and bounds a very long one', () => {
    expect(scrubGitMessage('fatal: bad object')).toBe('fatal: bad object');
    expect(scrubGitMessage('x'.repeat(5000)).length).toBeLessThanOrEqual(600);
  });
});
