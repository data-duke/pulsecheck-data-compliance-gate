/**
 * PR E · the checkout a baseline scan walks: `git ls-files` for the tracked files and the filesystem for their
 * bytes. Only regular files are read (lstat, so a symlink is never followed out of the checkout, and a submodule's
 * directory entry is skipped), and a path that would resolve outside the checkout is refused.
 */
import { execFile } from 'node:child_process';
import { lstat, readFile } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import type { BaselineCheckout } from './baselineRun.js';

/** ls-files output of a very large monorepo still fits; past this git's output is cut and the call fails loudly. */
const MAX_LS_FILES_BYTES = 256 * 1024 * 1024;

function git(dir: string, args: string[], maxBuffer = 1024 * 1024): Promise<string> {
  return new Promise((done, fail) => {
    execFile('git', ['-C', dir, ...args], { encoding: 'utf8', maxBuffer }, (err, stdout) => {
      if (err) fail(err);
      else done(stdout);
    });
  });
}

export function gitCheckout(dir: string): BaselineCheckout {
  const root = resolve(dir);
  /** The absolute path of a repo-relative one, or null when it would leave the checkout. */
  const inside = (path: string): string | null => {
    const abs = resolve(root, path);
    const rel = relative(root, abs);
    if (rel === '' || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) return null;
    return abs;
  };

  return {
    async listFiles() {
      const out = await git(root, ['ls-files', '-z'], MAX_LS_FILES_BYTES);
      return out.split('\0').filter((p) => p.length > 0);
    },
    async size(path) {
      const abs = inside(path);
      if (!abs) return null;
      try {
        const st = await lstat(abs);
        return st.isFile() ? st.size : null;
      } catch {
        return null;
      }
    },
    async read(path) {
      const abs = inside(path);
      if (!abs) throw new Error('path outside the checkout');
      return new Uint8Array(await readFile(abs));
    },
    async headSha() {
      const sha = (await git(root, ['rev-parse', 'HEAD'])).trim();
      if (!/^[0-9a-f]{40}([0-9a-f]{24})?$/.test(sha)) throw new Error('unexpected HEAD');
      return sha;
    },
  };
}
