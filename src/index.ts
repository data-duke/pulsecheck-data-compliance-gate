/**
 * Data Compliance Gate — GitHub Action entrypoint (a dumb sensor).
 *
 * This file is the GitHub ADAPTER: read inputs → resolve the PR (and its head SHA)
 * from the event or the API → hand over to the provider-neutral core (core.ts),
 * which fetches the diff, pulls the rulesets from PulseCheck (one per framework),
 * scans each locally, publishes a verdict per framework and posts the masked
 * verdicts back. No rules are baked in; raw diff/PII never leave this runner.
 *
 * Policies:
 *  - No token  → inert: no scan, no check run, no post, exit 0.
 *  - Ruleset fetch fails (PulseCheck unreachable) → publish a `neutral` check +
 *    warning; never a silent pass, never a hard block (don't fail on an outage).
 *  - verdict 'fail' in a framework `fail-on` lists → publish `failure` AND fail the
 *    step (the block); 'pass' → success; 'needs_review' → neutral (advisory). A
 *    framework `fail-on` does not list is advisory: its check never concludes
 *    `failure`. The default `fail-on` is the original 'Data Compliance' stream.
 *  - An old server (no multi-framework support) is handled transparently: its
 *    single ruleset is the 'Data Compliance' stream.
 *
 * `scan-mode: baseline` (PR E, AI usage inventory) takes a different path before any of
 * the above: no pull request, no check run, no verdict, `fail-on` ignored. It walks the
 * checked-out tree and posts aggregate counts only (baselineRun.ts), and never fails the
 * step. An invalid `scan-mode` value is the one thing that fails it, before anything runs.
 */
import * as core from '@actions/core';
import * as github from '@actions/github';
import { parseSamplePaths, parseScanMode, runBaseline } from './baselineRun.js';
import { publishCheckRun } from './checkRun.js';
import { runGate, type ProviderAdapter } from './core.js';
import { parseFailOn } from './frameworks.js';
import { gitCheckout } from './gitCheckout.js';
import { resolvePrRef, shouldPublishCheckRun } from './prContext.js';

const DEFAULT_URL = 'https://nmvlxonedqnejdevrchx.supabase.co';

async function run(): Promise<void> {
  const mode = parseScanMode(core.getInput('scan-mode'));
  if ('error' in mode) {
    core.setFailed(mode.error);
    return;
  }
  if (mode.mode === 'baseline') return runBaselineMode();
  return runPr();
}

/** `scan-mode: baseline`: inventory the checked-out tree. Never fails the step (see baselineRun.ts). */
async function runBaselineMode(): Promise<void> {
  const token = core.getInput('pulsecheck-token');
  const url = core.getInput('pulsecheck-url') || DEFAULT_URL;
  if (!token) {
    core.info('No pulsecheck-token provided — Data Compliance Gate is inert (no baseline scan, nothing recorded).');
    return;
  }
  const samplePaths = parseSamplePaths(core.getInput('baseline-sample-paths'));
  if (samplePaths.warning) core.warning(samplePaths.warning);
  const { owner, repo } = github.context.repo;
  await runBaseline(
    { url, token, repo: `${owner}/${repo}`, samplePaths: samplePaths.value, fallbackSha: github.context.sha },
    gitCheckout(process.env.GITHUB_WORKSPACE || process.cwd()),
    core,
  );
}

/** `scan-mode: pr` (the default): the pull request gate, unchanged. */
async function runPr(): Promise<void> {
  const token = core.getInput('pulsecheck-token');
  const url = core.getInput('pulsecheck-url') || DEFAULT_URL;
  const githubToken = core.getInput('github-token');
  const parsedCap = Number(core.getInput('diff-cap-bytes') || '5000000');
  const diffCap = Number.isFinite(parsedCap) && parsedCap > 0 ? parsedCap : 5000000;
  const { failOn, unknown: unknownFailOn } = parseFailOn(core.getInput('fail-on'));
  for (const name of unknownFailOn) core.warning(`fail-on: unknown framework "${name}" was ignored.`);

  // Inert without a token — the brain is server-side and auth-gated.
  if (!token) {
    core.info('No pulsecheck-token provided — Data Compliance Gate is inert (no scan, no verdict).');
    return;
  }

  // FEAT-09 · an explicitly named pull request wins over the event payload, so a
  // workflow_dispatch backfill works in a repo that also runs on pull_request.
  const pr = github.context.payload.pull_request;
  const ref = resolvePrRef(pr?.number as number | undefined, core.getInput('pr-number'));
  if (ref.reason === 'invalid-input') {
    core.setFailed("pr-number must be a positive whole number (e.g. '22').");
    return;
  }
  if (ref.prNumber === null) {
    core.info('No pull_request in the event payload and no pr-number input — nothing to scan.');
    return;
  }

  const { owner, repo } = github.context.repo;
  const prNumber = ref.prNumber;
  const publishChecks = shouldPublishCheckRun(core.getInput('publish-check-run'));

  if (!githubToken) {
    core.setFailed('github-token is required to fetch the diff and publish the check run.');
    return;
  }
  const octokit = github.getOctokit(githubToken);

  // With an explicit number the event payload carries nothing about that PR, so its
  // head SHA and body have to be fetched. A merged PR answers this endpoint exactly
  // as an open one does, which is why the backfill needed no server-side change.
  let headSha: string;
  let prDescription: string;
  if (ref.explicit) {
    try {
      const meta = await octokit.rest.pulls.get({ owner, repo, pull_number: prNumber });
      headSha = meta.data.head.sha;
      prDescription = meta.data.body ?? '';
      if (meta.data.merged) {
        core.info(`Pull request #${prNumber} is merged — scanning it as a backfill.`);
      }
    } catch (err) {
      core.setFailed(`Could not read pull request #${prNumber}: ${(err as Error)?.message ?? err}`);
      return;
    }
  } else {
    headSha = (pr!.head as { sha: string }).sha;
    prDescription = (pr!.body as string | null) ?? '';
  }

  // The two provider-specific parts: how to read the diff (via the API, no shelling
  // out) and how to show a verdict (a check run). Everything else is the core.
  const adapter: ProviderAdapter = {
    async fetchDiff() {
      const res = await octokit.rest.pulls.get({
        owner,
        repo,
        pull_number: prNumber,
        mediaType: { format: 'diff' },
      });
      return res.data as unknown as string;
    },
    publishVerdict: (result, framework, advisory) =>
      publishCheckRun(octokit as never, { owner, repo, headSha, result, framework, advisory }),
  };

  await runGate(
    {
      url,
      token,
      failOn,
      diffCap,
      publishChecks,
      repo: `${owner}/${repo}`,
      prNumber,
      headSha,
      prDescription,
    },
    adapter,
    core,
  );
}

run().catch((err) => {
  core.setFailed(`Data Compliance Gate crashed: ${(err as Error)?.message ?? err}`);
});
