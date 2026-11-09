/**
 * Provider-neutral core of the Data Compliance Gate.
 *
 * Everything that happens once we know WHICH change to scan and HOW to talk to the
 * source-control provider: read the diff, pull the rulesets, scan each framework,
 * publish a verdict per framework, post the masked verdicts back, set the outputs
 * and decide whether the step fails. A provider adapter (today only GitHub, see
 * index.ts) supplies the two things that differ between providers.
 *
 * Policies (unchanged from the GitHub-only version, pinned by
 * __tests__/githubEntry.characterization.test.ts):
 *  - Ruleset fetch fails (PulseCheck unreachable) → publish a `neutral` verdict +
 *    warning; never a silent pass, never a hard block (don't fail on an outage).
 *  - Diff unreadable → same: needs_review/neutral, no post.
 *  - verdict 'fail' in a framework `fail-on` lists → fail the step; any other
 *    framework is advisory.
 */
import { fetchRulesets, RulesetFetchError, type FetchedRulesets } from './ruleset.js';
import { notRecordedWarning, postResults } from './report.js';
import { failingFrameworks, primaryOutcome, scanFrameworks } from './orchestrate.js';
import { DEFAULT_FRAMEWORK, FRAMEWORK_INFO, SUPPORTED_CAPS, isFramework, type FrameworkId } from './frameworks.js';
import type { GateProvider } from './provider.js';
import type { ScanResult } from './types.js';

/** The slice of `@actions/core` the core needs. A CLI supplies its own. */
export interface GateIo {
  info(message: string): void;
  warning(message: string): void;
  setFailed(message: string): void;
  setOutput(name: string, value: string): void;
}

/** What differs between source-control providers. */
export interface ProviderAdapter {
  /** The unified diff of the change under review. Throws when it cannot be read. */
  fetchDiff(): Promise<string>;
  /**
   * Show a verdict on the provider (GitHub: a check run). Returns the conclusion it
   * used. May throw; the core turns that into a warning, never a failure.
   */
  publishVerdict(result: ScanResult, framework?: FrameworkId, advisory?: boolean): Promise<string>;
}

export interface GateRun {
  url: string;
  token: string;
  failOn: readonly FrameworkId[];
  diffCap: number;
  /** False for a backfill: the verdict is recorded but nothing is published on the provider. */
  publishChecks: boolean;
  /** Repository path as PulseCheck stores it, e.g. `owner/repo` (GitLab: `group/subgroup/project`). */
  repo: string;
  /** Absent = GitHub. Threads to the ruleset request and the verdict post. */
  provider?: GateProvider;
  prNumber: number;
  headSha: string;
  prDescription: string;
}

/** How a framework is named in logs and failure messages ('Data Compliance Gate' is the name users already know). */
function displayName(framework: FrameworkId): string {
  return framework === DEFAULT_FRAMEWORK ? 'Data Compliance Gate' : FRAMEWORK_INFO[framework].title;
}

async function safePublish(
  adapter: ProviderAdapter,
  io: GateIo,
  publish: boolean,
  result: ScanResult,
  framework?: FrameworkId,
  advisory = false,
): Promise<string> {
  // FEAT-09 · a backfill records its verdict but publishes nothing: a check run is a
  // claim about a commit's CURRENT state, and stamping one onto an old merged commit
  // rewrites history in the UI and can re-open a settled required-check decision.
  if (!publish) {
    io.info('publish-check-run is false — recording the verdict without publishing a check run.');
    return 'skipped';
  }
  try {
    return await adapter.publishVerdict(result, framework, advisory);
  } catch (err) {
    io.warning(`Could not publish the check run: ${(err as Error)?.message ?? err}`);
    return 'neutral';
  }
}

/**
 * True when the server withheld a rule although this Action supports every capability it lists, and one of them
 * is `context`: the server had no registry context to attach (no valid repository). Old servers sent bare ids
 * (strings) here; those cannot be attributed and keep the original message.
 */
const CONTEXT_CAP = 'context';
function isServerWithheld(dropped: unknown): boolean {
  const caps = (dropped as { missing_caps?: unknown } | null)?.missing_caps;
  if (!Array.isArray(caps) || caps.length === 0) return false;
  return caps.includes(CONTEXT_CAP) && caps.every((c) => typeof c === 'string' && SUPPORTED_CAPS.includes(c));
}

export async function runGate(run: GateRun, adapter: ProviderAdapter, io: GateIo): Promise<void> {
  // Fetch the unified diff.
  let diff = '';
  let truncated = false;
  try {
    diff = await adapter.fetchDiff();
    if (typeof diff === 'string' && diff.length > run.diffCap) {
      diff = diff.slice(0, run.diffCap);
      truncated = true;
    }
  } catch (err) {
    // Inability to read the diff is a "cannot scan" case, like a PulseCheck
    // outage: report needs_review/neutral rather than hard-failing the merge.
    const reason = (err as Error)?.message ?? String(err);
    io.warning(`Could not fetch the PR diff (${reason}). Reporting needs_review.`);
    await safePublish(adapter, io, run.publishChecks, {
      verdict: 'needs_review',
      findings: [],
      warnings: [`Diff unavailable: ${reason}`],
    });
    io.setOutput('verdict', 'needs_review');
    return;
  }

  // Pull the active rulesets. A fetch failure is a transient/outage case: emit a
  // neutral verdict + warning, never a silent pass and never a hard block.
  let fetched: FetchedRulesets;
  try {
    fetched = await fetchRulesets(run.url, run.token, SUPPORTED_CAPS, run.repo, run.provider);
  } catch (err) {
    const reason = err instanceof RulesetFetchError ? err.message : String(err);
    io.warning(`Could not reach PulseCheck to fetch the ruleset (${reason}). Reporting needs_review.`);
    const degraded: ScanResult = {
      verdict: 'needs_review',
      findings: [],
      warnings: [`PulseCheck unreachable: ${reason}`],
    };
    await safePublish(adapter, io, run.publishChecks, degraded);
    io.setOutput('verdict', 'needs_review');
    return; // do not fail the pipeline on a PulseCheck outage
  }

  for (const rs of fetched.rulesets) {
    // A rule is withheld for one of two reasons: this Action lacks a capability it needs, or the Action HAS every
    // capability and the server withheld the rule anyway because it could not attach what the rule grades with
    // (no valid repository, so no registry context). Blaming the Action for the second sends people to upgrade
    // an Action that is already current.
    const withheld = rs.dropped_rules ?? [];
    const serverSide = withheld.filter((d) => isServerWithheld(d));
    const unsupported = withheld.length - serverSide.length;
    if (unsupported > 0) {
      io.info(`${rs.framework}: ${unsupported} rule(s) withheld because this Action does not support a capability they need.`);
    }
    if (serverSide.length > 0) {
      io.info(`${rs.framework}: ${serverSide.length} rule(s) withheld: PulseCheck could not attach a registry context (no valid repository).`);
    }
    if (rs.context_rejected) {
      io.warning(`${FRAMEWORK_INFO[rs.framework].title}: PulseCheck sent a registry context this Action could not use; it was ignored, so findings keep their declared action and no context is recorded.`);
    }
  }
  for (const u of fetched.unavailable) {
    const name = isFramework(u.framework) ? FRAMEWORK_INFO[u.framework].title : u.framework;
    io.warning(`${name}: PulseCheck did not serve this ruleset in this run (${u.reason}), so it was not scanned.`);
  }

  // Scan each framework independently (own rules, own verdict, own warnings) and publish.
  const outcomes = scanFrameworks(
    fetched.rulesets,
    { diff, prDescription: run.prDescription, truncated },
    run.failOn,
  );
  const conclusions = new Map<FrameworkId, string>();
  for (const o of outcomes) {
    conclusions.set(o.framework, await safePublish(adapter, io, run.publishChecks, o.result, o.framework, o.advisory));
  }

  // Post the masked verdicts back (best-effort — never blocks, never leaks).
  const post = await postResults(
    run.url,
    run.token,
    { repo: run.repo, pr_number: run.prNumber, commit_sha: run.headSha, ...(run.provider ? { provider: run.provider } : {}) },
    outcomes,
    fetched.shape,
  );
  if (!post.ok) {
    io.warning(
      post.code === 'token_scope_mismatch'
        ? 'Could not record the verdict: this token is limited to other repositories or providers. Create a token for this repository in PulseCheck (Organization Settings, CI Gate).'
        : `Could not record the verdict with PulseCheck: ${post.error}`,
    );
  }
  const partial = notRecordedWarning(post);
  if (partial) io.warning(partial);

  // The `verdict` / `findings-count` outputs keep meaning the original GDPR stream.
  const primary = primaryOutcome(outcomes);
  io.setOutput('verdict', primary?.result.verdict ?? 'needs_review');
  io.setOutput('findings-count', String(primary?.result.findings.length ?? 0));
  io.setOutput('verdicts', JSON.stringify(Object.fromEntries(outcomes.map((o) => [o.framework, o.result.verdict]))));

  for (const o of outcomes) {
    const prefix = o.framework === DEFAULT_FRAMEWORK ? '' : `${FRAMEWORK_INFO[o.framework].title}: `;
    for (const w of o.result.warnings) io.warning(`${prefix}${w}`);
    io.info(`${displayName(o.framework)}: ${o.result.verdict} (check run conclusion: ${conclusions.get(o.framework)}).`);
  }

  // A blocking verdict fails the step too, so a job-level required check blocks
  // the merge even when the check run itself is not the configured gate.
  for (const o of failingFrameworks(outcomes)) {
    io.setFailed(`${displayName(o.framework)} failed: ${o.result.findings.filter((f) => f.action === 'block').length} blocking finding(s).`);
  }
}
