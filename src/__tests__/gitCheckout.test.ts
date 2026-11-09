/**
 * PR E: the real checkout behind a baseline scan, against a throwaway git repository: only TRACKED files are listed,
 * a symlink or a submodule is never followed (size null), and HEAD is read from the checkout.
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { gitCheckout } from '../gitCheckout.js';

let dir: string;
let outside: string;
const git = (...args: string[]) => execFileSync('git', ['-C', dir, ...args], { encoding: 'utf8' });

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'baseline-git-'));
  outside = mkdtempSync(join(tmpdir(), 'baseline-outside-'));
  writeFileSync(join(outside, 'secret.ts'), 'outside the repository\n');
  git('init', '-q');
  git('config', 'user.email', 'test@example.com');
  git('config', 'user.name', 'Test');
  git('config', 'commit.gpgsign', 'false');
  mkdirSync(join(dir, 'src', 'spaced dir'), { recursive: true });
  writeFileSync(join(dir, 'src', 'a.ts'), 'const u = "https://api.openai.com";\n');
  writeFileSync(join(dir, 'src', 'spaced dir', 'ü.ts'), 'x\n');
  symlinkSync(join(outside, 'secret.ts'), join(dir, 'src', 'link.ts'));
  writeFileSync(join(dir, 'untracked.ts'), 'not added\n');
  git('add', 'src');
  git('commit', '-q', '-m', 'init');
});
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
  rmSync(outside, { recursive: true, force: true });
});

describe('gitCheckout', () => {
  it('lists tracked files only, with unusual names intact (ls-files -z, no quoting)', async () => {
    const files = await gitCheckout(dir).listFiles();
    expect(files.sort()).toEqual(['src/a.ts', 'src/link.ts', 'src/spaced dir/ü.ts']);
  });

  it('a regular file has its size and content; a symlink is not followed', async () => {
    const co = gitCheckout(dir);
    expect(await co.size('src/a.ts')).toBe(36);
    expect(new TextDecoder().decode(await co.read('src/a.ts'))).toContain('api.openai.com');
    expect(await co.size('src/link.ts')).toBeNull();
    expect(await co.size('does/not/exist.ts')).toBeNull();
  });

  it('refuses a path that would leave the checkout', async () => {
    const co = gitCheckout(dir);
    expect(await co.size('../escape.ts')).toBeNull();
    await expect(co.read('../escape.ts')).rejects.toThrow();
  });

  it('reads HEAD', async () => {
    expect(await gitCheckout(dir).headSha()).toBe(git('rev-parse', 'HEAD').trim());
  });

  it('a directory that is not a git checkout rejects listFiles', async () => {
    await expect(gitCheckout(outside).listFiles()).rejects.toThrow();
  });
});
