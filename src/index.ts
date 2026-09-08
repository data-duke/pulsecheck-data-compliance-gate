/**
 * Data Compliance Gate — GitHub Action entrypoint (a dumb sensor).
 *
 * Flow: read inputs → resolve PR context → fetch the diff → pull the active
 * ruleset from PulseCheck → scan locally → publish a check run → post the masked
 * verdict back. No rules are baked in; raw diff/PII never leave this runner.
 *
 * Policies:
 *  - No token  → inert: no scan, no check run, no post, exit 0.
 *  - Ruleset fetch fails (PulseCheck unreachable) → publish a `neutral` check +
 *    warning; never a silent pass, never a hard block (don't fail on an outage).
 *  - verdict 'fail' → publish `failure` AND fail the step (the block); 'pass' →
 *    success; 'needs_review' → neutral (advisory).
 */
import * as core from '@actions/core';
import * as github from '@actions/github';
import { fetchRuleset, RulesetFetchError } from './ruleset.js';
import { scan } from './scan.js';
import { publishCheckRun } from './checkRun.js';
import { postResult } from './report.js';
import type { ScanResult } from './types.js';

const DEFAULT_URL = 'https://nmvlxonedqnejdevrchx.supabase.co';

async function run(): Promise<void> {
  const token = core.getInput('pulsecheck-token');
  const url = core.getInput('pulsecheck-url') || DEFAULT_URL;
  const githubToken = core.getInput('github-token');
  const parsedCap = Number(core.getInput('diff-cap-bytes') || '5000000');
  const diffCap = Number.isFinite(parsedCap) && parsedCap > 0 ? parsedCap : 5000000;

  // Inert without a token — the brain is server-side and auth-gated.
  if (!token) {
    core.info('No pulsecheck-token provided — Data Compliance Gate is inert (no scan, no verdict).');
    return;
  }

  const pr = github.context.payload.pull_request;
  if (!pr) {
    core.info('No pull_request in the event payload — nothing to scan.');
    return;
  }
  const { owner, repo } = github.context.repo;
  const prNumber = pr.number as number;
  const headSha = (pr.head as { sha: string }).sha;
  const prDescription = (pr.body as string | null) ?? '';

  if (!githubToken) {
    core.setFailed('github-token is required to fetch the diff and publish the check run.');
    return;
  }
  const octokit = github.getOctokit(githubToken);

  // Fetch the unified diff via the API (no shelling out).
  let diff = '';
  let truncated = false;
  try {
    const res = await octokit.rest.pulls.get({
      owner,
      repo,
      pull_number: prNumber,
      mediaType: { format: 'diff' },
    });
    diff = res.data as unknown as string;
    if (typeof diff === 'string' && diff.length > diffCap) {
      diff = diff.slice(0, diffCap);
      truncated = true;
    }
  } catch (err) {
    // Inability to read the diff is a "cannot scan" case, like a PulseCheck
    // outage: report needs_review/neutral rather than hard-failing the merge.
    const reason = (err as Error)?.message ?? String(err);
    core.warning(`Could not fetch the PR diff (${reason}). Reporting needs_review.`);
    await safePublish(octokit, owner, repo, headSha, {
      verdict: 'needs_review',
      findings: [],
      warnings: [`Diff unavailable: ${reason}`],
    });
    core.setOutput('verdict', 'needs_review');
    return;
  }

  // Pull the active ruleset. A fetch failure is a transient/outage case: emit a
  // neutral check + warning, never a silent pass and never a hard block.
  let ruleset;
  try {
    ruleset = await fetchRuleset(url, token);
  } catch (err) {
    const reason = err instanceof RulesetFetchError ? err.message : String(err);
    core.warning(`Could not reach PulseCheck to fetch the ruleset (${reason}). Reporting needs_review.`);
    const degraded: ScanResult = {
      verdict: 'needs_review',
      findings: [],
      warnings: [`PulseCheck unreachable: ${reason}`],
    };
    await safePublish(octokit, owner, repo, headSha, degraded);
    core.setOutput('verdict', 'needs_review');
    return; // do not fail the pipeline on a PulseCheck outage
  }

  // Scan locally and publish.
  const result = scan(ruleset, { diff, prDescription, truncated });
  const conclusion = await safePublish(octokit, owner, repo, headSha, result);

  // Post the masked verdict back (best-effort — never blocks, never leaks).
  const post = await postResult(url, token, {
    repo: `${owner}/${repo}`,
    pr_number: prNumber,
    commit_sha: headSha,
    ruleset_version: ruleset.ruleset_version,
    ruleset_hash: ruleset.ruleset_hash,
    verdict: result.verdict,
    findings: result.findings,
  });
  if (!post.ok) core.warning(`Could not record the verdict with PulseCheck: ${post.error}`);

  core.setOutput('verdict', result.verdict);
  core.setOutput('findings-count', String(result.findings.length));
  for (const w of result.warnings) core.warning(w);

  core.info(`Data Compliance Gate: ${result.verdict} (check run conclusion: ${conclusion}).`);

  // A blocking verdict fails the step too, so a job-level required check blocks
  // the merge even when the check run itself is not the configured gate.
  if (result.verdict === 'fail') {
    core.setFailed(`Data Compliance Gate failed: ${result.findings.filter((f) => f.action === 'block').length} blocking finding(s).`);
  }
}

async function safePublish(
  octokit: ReturnType<typeof github.getOctokit>,
  owner: string,
  repo: string,
  headSha: string,
  result: ScanResult,
): Promise<string> {
  try {
    return await publishCheckRun(octokit as never, { owner, repo, headSha, result });
  } catch (err) {
    core.warning(`Could not publish the check run: ${(err as Error)?.message ?? err}`);
    return 'neutral';
  }
}

run().catch((err) => {
  core.setFailed(`Data Compliance Gate crashed: ${(err as Error)?.message ?? err}`);
});
