/**
 * The merge request diff, read with git (the CLI adapter; the GitHub adapter reads it through the API instead).
 *
 * `git diff <base> <head>` with the two commit ids GitLab names. `CI_MERGE_REQUEST_DIFF_BASE_SHA` is already the base of
 * the merge request's diff, so the two-argument form is exactly the merge request's change and needs only those two
 * commits' trees: it does not need the shared history that GitLab's default shallow clone (depth 20, documented) lacks,
 * which a three-dot range would.
 *
 * Safety:
 *  - both ids are validated as hex object ids BEFORE any process starts, so a value from the environment can never be read
 *    by git as an option (`--upload-pack=...`) or a revision expression;
 *  - arguments go to `execFile`, never through a shell;
 *  - the diff format is forced (`a/` `b/` prefixes, no external diff, no textconv, no rename detection, no octal-quoted
 *    names) so a user's or a repository's git configuration cannot change what the scanner reads;
 *  - an error message never carries a credential: git prints the remote URL on a failed fetch, and in a CI job that URL
 *    holds the job token (`scrubGitMessage`).
 */
import { execFile } from 'node:child_process';

export interface ReadGitDiffOptions {
  cwd: string;
  baseSha: string;
  headSha: string;
  /** Environment for git; defaults to the process environment. */
  env?: NodeJS.ProcessEnv;
  /** The remote a missing commit is fetched from. */
  remote?: string;
}

// Full object ids only: git reads a short hex string as a ref name first, so a branch named like one could shadow the commit.
const SHA_PATTERN = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i;
/** A diff can be large; the core caps what it scans (`diff-cap-bytes`), this only has to hold what git prints. */
const MAX_BUFFER = 256 * 1024 * 1024;
const COMMAND_TIMEOUT_MS = 120_000;
const MAX_MESSAGE_CHARS = 600;

interface GitResult {
  code: number;
  stdout: string;
  stderr: string;
}

/** git (and any credential helper or ssh it starts) never needs the PulseCheck or GitLab API tokens. */
function withoutToken(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const { PULSECHECK_TOKEN: _token, PULSECHECK_GITLAB_TOKEN: _gitlabToken, ...rest } = env;
  return rest;
}

function runGit(cwd: string, env: NodeJS.ProcessEnv, args: string[]): Promise<GitResult> {
  return new Promise((resolve, reject) => {
    execFile(
      'git',
      args,
      { cwd, env: { ...withoutToken(env), GIT_TERMINAL_PROMPT: '0' }, maxBuffer: MAX_BUFFER, timeout: COMMAND_TIMEOUT_MS, encoding: 'utf8' },
      (err, stdout, stderr) => {
        if (!err) return resolve({ code: 0, stdout, stderr });
        const code = (err as NodeJS.ErrnoException & { code?: number | string }).code;
        // A git that ran and exited non-zero is a result; a git that did not start (ENOENT) is an error.
        if (typeof code === 'number') return resolve({ code, stdout: stdout ?? '', stderr: stderr ?? '' });
        reject(new Error(`could not run git (${(err as Error).message})`));
      },
    );
  });
}

/** Remove a credential from a git message (`https://user:token@host/...` becomes `https://host/...`) and bound its length. */
export function scrubGitMessage(message: string): string {
  const scrubbed = message.replace(/(\b[a-z][a-z0-9+.-]*:\/\/)[^\s/@'"]+@/gi, '$1');
  return scrubbed.length > MAX_MESSAGE_CHARS ? `${scrubbed.slice(0, MAX_MESSAGE_CHARS - 1)}…` : scrubbed;
}

const short = (sha: string): string => sha.slice(0, 12);

async function hasCommit(cwd: string, env: NodeJS.ProcessEnv, sha: string): Promise<boolean> {
  return (await runGit(cwd, env, ['cat-file', '-e', `${sha}^{commit}`])).code === 0;
}

/** Make sure a commit is present, fetching just that commit (depth 1) when the clone does not have it. */
async function ensureCommit(cwd: string, env: NodeJS.ProcessEnv, remote: string, sha: string, role: 'base' | 'head'): Promise<void> {
  if (await hasCommit(cwd, env, sha)) return;
  const fetched = await runGit(cwd, env, ['fetch', '--no-tags', '--no-recurse-submodules', '--depth=1', remote, sha]);
  if (fetched.code === 0 && (await hasCommit(cwd, env, sha))) return;
  throw new Error(
    `The ${role} commit ${short(sha)} is not in this clone and could not be fetched` +
      (fetched.stderr.trim() ? ` (${scrubGitMessage(fetched.stderr.trim())})` : '') +
      '. Check that the job can read the repository, and raise GIT_DEPTH (GitLab\'s default clone depth is 20) if the base is older than that.',
  );
}

/** The unified diff of the merge request. Throws with an actionable message when it cannot be read. */
export async function readGitDiff(opts: ReadGitDiffOptions): Promise<string> {
  const { cwd, baseSha, headSha } = opts;
  const env = opts.env ?? process.env;
  const remote = opts.remote ?? 'origin';
  for (const [role, sha] of [['base', baseSha], ['head', headSha]] as const) {
    if (typeof sha !== 'string' || !SHA_PATTERN.test(sha)) throw new Error(`The ${role} is not a commit id.`);
  }

  await ensureCommit(cwd, env, remote, headSha, 'head');
  await ensureCommit(cwd, env, remote, baseSha, 'base');

  const result = await runGit(cwd, env, [
    '-c', 'core.quotepath=false',
    'diff', '--no-color', '--no-ext-diff', '--no-textconv', '--no-renames',
    '--src-prefix=a/', '--dst-prefix=b/',
    baseSha, headSha, '--',
  ]);
  if (result.code !== 0) {
    throw new Error(`git diff failed (${scrubGitMessage(result.stderr.trim() || `exit ${result.code}`)}).`);
  }
  return result.stdout;
}
