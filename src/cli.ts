/**
 * `pulsecheck-gate`: the Data Compliance Gate for pipelines that are not GitHub Actions (today: GitLab merge request
 * pipelines). The same core as the Action (`runGate`), a GitLab adapter, and a Code Quality report.
 *
 * Everything that touches the outside (network, git, the file system, the process) is injected, so the whole run is
 * testable end to end; `cliMain.ts` is the thin entry that supplies the real ones.
 *
 * Policies, the same as the Action's:
 *  - no token: inert (nothing scanned, nothing recorded), exit 0;
 *  - not a merge request pipeline: inert, exit 0;
 *  - PulseCheck unreachable or the diff unreadable: a warning and an empty report, never a block (exit 0);
 *  - a `fail` verdict in a `--fail-on` framework: exit 1; any other framework is advisory;
 *  - usage and configuration errors: exit 2, loud (a pipeline that is misconfigured should not look green).
 * The token is read only from `PULSECHECK_TOKEN`: there is deliberately no `--token`, because an argument is visible to
 * every process on the runner and lands in shell history and job traces.
 */
import { resolve } from 'node:path';
import { CLI_VERSION } from './cliVersion.js';
import { runGate, type GateIo, type ProviderAdapter } from './core.js';
import { DEFAULT_URL } from './defaults.js';
import { parseFailOn, type FrameworkId } from './frameworks.js';
import { readGitlabMr, renderCodeQuality, toCodeQualityReport } from './gitlab.js';
import { buildNoteBody, postMergeRequestNote, readNoteTarget } from './gitlabNote.js';
import type { ReadGitDiffOptions } from './gitDiff.js';
import { GATE_PROVIDERS, isGateProvider, type GateProvider } from './provider.js';
import type { ScanResult } from './types.js';

type Env = Record<string, string | undefined>;

export interface CliDeps {
  out(line: string): void;
  err(line: string): void;
  /** The directory the job runs in; `CI_PROJECT_DIR` wins when set. */
  cwd: string;
  writeFile(path: string, content: string): Promise<void>;
  readDiff(options: ReadGitDiffOptions): Promise<string>;
}

export const CLI_USAGE = `Usage: pulsecheck-gate [options]

Scans a merge request for GDPR / EU AI Act findings on the runner and reports a masked
verdict to PulseCheck. No source code leaves the runner.

Environment:
  PULSECHECK_TOKEN   required. A PulseCheck CI token (Organization Settings, CI Gate).
                     Without it the command does nothing and exits 0.
  PULSECHECK_URL     optional. The PulseCheck API host.

Options:
  --provider <name>        ${GATE_PROVIDERS.join(' | ')}. Detected from GITLAB_CI when omitted.
                           (GitHub is served by the GitHub Action, not by this command.)
  --fail-on <list>         Frameworks whose "fail" verdict exits 1, e.g. "Data Compliance, EU AI Act".
                           "none" never fails. Default: Data Compliance.
  --url <url>              PulseCheck API host (overrides PULSECHECK_URL).
  --diff-cap-bytes <n>     Largest diff scanned in full (default 5000000); more is truncated, never passed.
  --code-quality <path>    Where to write the GitLab Code Quality report (default gl-code-quality-report.json).
  --no-code-quality        Do not write the report.
  -h, --help               Show this text.
  -V, --version            Show the version.

Exit codes: 0 ok (also when PulseCheck is unreachable), 1 a --fail-on framework failed, 2 usage or configuration error.
`;

export interface ParsedArgs {
  provider?: GateProvider;
  failOn?: string;
  url?: string;
  diffCap?: number;
  /** A path, or null for --no-code-quality. */
  codeQuality?: string | null;
  help?: true;
  version?: true;
}

const VALUE_FLAGS = ['--provider', '--fail-on', '--url', '--diff-cap-bytes', '--code-quality'] as const;

export function parseCliArgs(argv: readonly string[]): ParsedArgs | { error: string } {
  const out: ParsedArgs = {};
  for (let i = 0; i < argv.length; i += 1) {
    const raw = argv[i];
    const eq = raw.startsWith('--') ? raw.indexOf('=') : -1;
    const flag = eq === -1 ? raw : raw.slice(0, eq);

    if (flag === '--help' || flag === '-h') { out.help = true; continue; }
    if (flag === '--version' || flag === '-V') { out.version = true; continue; }
    if (flag === '--no-code-quality') { out.codeQuality = null; continue; }
    if (flag === '--token') {
      return { error: 'There is no --token option: set the PULSECHECK_TOKEN environment variable instead (a token on the command line is visible to other processes).' };
    }
    if (!(VALUE_FLAGS as readonly string[]).includes(flag)) {
      return { error: raw.startsWith('-') ? `Unknown option "${raw}".` : `Unexpected argument "${raw}".` };
    }

    let value: string;
    if (eq !== -1) {
      value = raw.slice(eq + 1);
    } else {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) return { error: `${flag} needs a value.` };
      value = next;
      i += 1;
    }

    switch (flag) {
      case '--provider':
        if (!isGateProvider(value)) return { error: `Unknown provider "${value.slice(0, 40)}": expected ${GATE_PROVIDERS.join(' or ')}.` };
        out.provider = value;
        break;
      case '--fail-on': out.failOn = value; break;
      case '--url': out.url = value; break;
      case '--code-quality':
        if (value.trim() === '') return { error: '--code-quality needs a file path.' };
        out.codeQuality = value;
        break;
      case '--diff-cap-bytes': {
        const n = /^\d+$/.test(value) ? Number(value) : NaN;
        if (!Number.isSafeInteger(n) || n <= 0) return { error: '--diff-cap-bytes must be a positive whole number.' };
        out.diffCap = n;
        break;
      }
    }
  }
  return out;
}

/** The file the CLI writes (and the GitLab snippet declares as the Code Quality artifact) unless told otherwise. */
export const DEFAULT_CODE_QUALITY_FILE = 'gl-code-quality-report.json';
const DEFAULT_DIFF_CAP = 5_000_000;

/** Run the CLI. Resolves to the process exit code; never throws. */
export async function runCli(argv: readonly string[], env: Env, deps: CliDeps): Promise<number> {
  const parsed = parseCliArgs(argv);
  if ('error' in parsed) {
    deps.err(`error: ${parsed.error}`);
    deps.err(CLI_USAGE);
    return 2;
  }
  if (parsed.help) { deps.out(CLI_USAGE); return 0; }
  if (parsed.version) { deps.out(CLI_VERSION); return 0; }

  const token = (env.PULSECHECK_TOKEN ?? '').trim();
  if (!token) {
    deps.out('No PULSECHECK_TOKEN provided: Data Compliance Gate is inert (no scan, no verdict).');
    return 0;
  }

  const provider = parsed.provider ?? (env.GITLAB_CI === 'true' ? 'gitlab' : undefined);
  if (!provider) {
    deps.err('error: could not tell which provider this job runs on. Pass --provider gitlab.');
    return 2;
  }
  if (provider === 'github') {
    deps.err('error: GitHub pull requests are scanned by the GitHub Action (data-duke/pulsecheck-data-compliance-gate), not by this command. This command supports GitLab merge request pipelines.');
    return 2;
  }

  return runGitlab(parsed, token, env, deps);
}

async function runGitlab(parsed: ParsedArgs, token: string, env: Env, deps: CliDeps): Promise<number> {
  const context = readGitlabMr(env);
  if (!context.ok) {
    if (context.reason === 'not-merge-request') {
      deps.out(context.detail);
      return 0;
    }
    deps.err(`error: ${context.detail}`);
    return 2;
  }
  const mr = context.mr;

  let failed = false;
  const io: GateIo = {
    info: (m) => deps.out(m),
    warning: (m) => deps.err(`warning: ${m}`),
    setFailed: (m) => { failed = true; deps.err(`error: ${m}`); },
    setOutput: () => undefined,
  };

  const { failOn, unknown } = parseFailOn(parsed.failOn);
  for (const name of unknown) io.warning(`--fail-on: unknown framework "${name}" was ignored.`);
  if (mr.descriptionTruncated) {
    io.warning('GitLab cut the merge request description at 2,700 characters, so a description longer than that was only partly scanned.');
  }

  const projectDir = env.CI_PROJECT_DIR || deps.cwd;
  const collected: Array<{ framework: FrameworkId; result: ScanResult }> = [];
  const adapter: ProviderAdapter = {
    fetchDiff: () => deps.readDiff({ cwd: projectDir, baseSha: mr.baseSha, headSha: mr.headSha, env: env as NodeJS.ProcessEnv }),
    // GitLab has no check run: the verdict is the job's exit code and the Code Quality report. Remember each framework's
    // result so the report can be written after the core has finished.
    publishVerdict: async (result, framework) => {
      if (framework) collected.push({ framework, result });
      return 'not applicable on GitLab';
    },
  };

  await runGate(
    {
      url: parsed.url || env.PULSECHECK_URL || DEFAULT_URL,
      token,
      failOn,
      diffCap: parsed.diffCap ?? DEFAULT_DIFF_CAP,
      publishChecks: true,
      repo: mr.repo,
      provider: 'gitlab' satisfies GateProvider,
      prNumber: mr.iid,
      headSha: mr.headSha,
      prDescription: mr.description,
    },
    adapter,
    io,
  );

  if (parsed.codeQuality !== null) {
    const target = resolve(projectDir, parsed.codeQuality ?? DEFAULT_CODE_QUALITY_FILE);
    try {
      await deps.writeFile(target, renderCodeQuality(toCodeQualityReport(collected)));
    } catch (e) {
      io.warning(`Could not write the Code Quality report (${(e as Error)?.message ?? e}).`);
    }
  }

  // PR F3: the optional merge request note. Opt-in by a project access token the customer adds; without it nothing runs.
  // Best effort: it never changes the verdict or the exit code.
  const gitlabToken = (env.PULSECHECK_GITLAB_TOKEN ?? '').trim();
  if (gitlabToken && collected.length > 0) {
    const target = readNoteTarget(env);
    if (!target) {
      io.warning('PULSECHECK_GITLAB_TOKEN is set, but this job has no usable CI_API_V4_URL / CI_MERGE_REQUEST_PROJECT_ID, so no merge request note was posted.');
    } else {
      const note = await postMergeRequestNote(target, gitlabToken, buildNoteBody(collected));
      if (note.ok) io.info(`Merge request note ${note.action}.`);
      else io.warning(`Could not post the merge request note (${note.error}).`);
    }
  }
  return failed ? 1 : 0;
}
