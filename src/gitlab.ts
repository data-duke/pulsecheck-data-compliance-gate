/**
 * The GitLab side of the gate: which merge request this pipeline is for, and the Code Quality report that shows the
 * findings on it.
 *
 * Every variable and format rule here was read from GitLab's documentation on 2026-10-15 (the table is in
 * docs/plans/ai-change-control-pr-d-plan.md). The ones that decide behaviour:
 *  - merge request variables exist ONLY in merge request pipelines, so a branch pipeline is inert, not an error;
 *  - `CI_MERGE_REQUEST_SOURCE_BRANCH_SHA` is empty in a plain merge request pipeline (the head is `CI_COMMIT_SHA`) and set in a
 *    merged results pipeline, where `CI_COMMIT_SHA` is a temporary merge commit, so the head is the source branch sha when present;
 *  - the description is cut at 2,700 characters (`..._IS_TRUNCATED` says so): a rule on the description may have missed
 *    text past the cut, which the caller turns into a warning;
 *  - the merge request IID belongs to the TARGET project (`CI_MERGE_REQUEST_PROJECT_PATH`); a merge request from a fork
 *    can run its pipeline in the fork, so `CI_PROJECT_PATH` is only the fallback;
 *  - a Code Quality report is ONE JSON array of {description, check_name, fingerprint, severity, location}, with a
 *    relative path (no leading "./") and no byte order mark.
 */
import { createHash } from 'node:crypto';
import { findingLocations } from './scan.js';
import { FRAMEWORK_INFO, POST_LIMITS } from './frameworks.js';
import type { FrameworkOutcome } from './orchestrate.js';

export interface GitlabMr {
  /** The merge request's project as PulseCheck stores it: `group/subgroup/project`. */
  repo: string;
  iid: number;
  headSha: string;
  baseSha: string;
  targetBranch?: string;
  description: string;
  descriptionTruncated: boolean;
}

export type GitlabMrResult =
  | { ok: true; mr: GitlabMr }
  | { ok: false; reason: 'not-gitlab' | 'not-merge-request' | 'missing'; detail: string };

type Env = Record<string, string | undefined>;

/** The shape ci-scan-result accepts for `repo` (_shared/ciScanIngest.ts REPO_PATTERN): nested groups allowed. */
const REPO_PATTERN = /^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)+$/;
const MAX_REPO_CHARS = 200;
/** A hex object id, as git prints it. Anything else is refused before it can reach a command line. */
const SHA_PATTERN = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i;
const INT32_MAX = 2147483647;

const text = (env: Env, name: string): string => (env[name] ?? '').trim();

/** Read the merge request this pipeline runs for. Pure: takes the environment, touches nothing. */
export function readGitlabMr(env: Env): GitlabMrResult {
  if (text(env, 'GITLAB_CI') !== 'true') {
    return { ok: false, reason: 'not-gitlab', detail: 'This is not a GitLab CI job (GITLAB_CI is not "true").' };
  }
  if (text(env, 'CI_PIPELINE_SOURCE') !== 'merge_request_event' || text(env, 'CI_MERGE_REQUEST_IID') === '') {
    return {
      ok: false,
      reason: 'not-merge-request',
      detail: 'This is not a merge request pipeline (CI_PIPELINE_SOURCE is not "merge_request_event"), so there is nothing to scan.',
    };
  }

  const iidRaw = text(env, 'CI_MERGE_REQUEST_IID');
  const iid = /^\d+$/.test(iidRaw) ? Number(iidRaw) : NaN;
  if (!Number.isSafeInteger(iid) || iid < 1 || iid > INT32_MAX) {
    return { ok: false, reason: 'missing', detail: `CI_MERGE_REQUEST_IID is not a positive whole number ("${iidRaw.slice(0, 20)}").` };
  }

  const repo = text(env, 'CI_MERGE_REQUEST_PROJECT_PATH') || text(env, 'CI_PROJECT_PATH');
  if (repo === '') return { ok: false, reason: 'missing', detail: 'CI_MERGE_REQUEST_PROJECT_PATH and CI_PROJECT_PATH are both empty.' };
  if (repo.length > MAX_REPO_CHARS || !REPO_PATTERN.test(repo)) {
    return { ok: false, reason: 'missing', detail: 'The project path is not a valid "group/project" path.' };
  }

  // In a plain merge request pipeline CI_COMMIT_SHA is the source branch's head. In a merged results pipeline (or merge
  // train) it is GitLab's temporary merge commit, which also holds everything merged into the target branch since the
  // merge base, and CI_MERGE_REQUEST_SOURCE_BRANCH_SHA is the real head. Using the merge commit would scan other people's
  // changes and store the verdict under a commit that is not the merge request's.
  const headSha = text(env, 'CI_MERGE_REQUEST_SOURCE_BRANCH_SHA') || text(env, 'CI_COMMIT_SHA');
  if (headSha === '') return { ok: false, reason: 'missing', detail: 'CI_COMMIT_SHA is empty.' };
  if (!SHA_PATTERN.test(headSha)) return { ok: false, reason: 'missing', detail: 'The merge request head is not a commit id.' };

  const baseSha = text(env, 'CI_MERGE_REQUEST_DIFF_BASE_SHA');
  if (baseSha === '') return { ok: false, reason: 'missing', detail: 'CI_MERGE_REQUEST_DIFF_BASE_SHA is empty.' };
  if (!SHA_PATTERN.test(baseSha)) return { ok: false, reason: 'missing', detail: 'CI_MERGE_REQUEST_DIFF_BASE_SHA is not a commit id.' };

  const targetBranch = text(env, 'CI_MERGE_REQUEST_TARGET_BRANCH_NAME');
  return {
    ok: true,
    mr: {
      repo,
      iid,
      headSha,
      baseSha,
      ...(targetBranch ? { targetBranch } : {}),
      description: env.CI_MERGE_REQUEST_DESCRIPTION ?? '',
      descriptionTruncated: text(env, 'CI_MERGE_REQUEST_DESCRIPTION_IS_TRUNCATED') === 'true',
    },
  };
}

// ── Code Quality ────────────────────────────────────────────────────────────────────────────────

export type CodeQualitySeverity = 'info' | 'minor' | 'major' | 'critical' | 'blocker';

export interface CodeQualityIssue {
  description: string;
  check_name: string;
  fingerprint: string;
  severity: CodeQualitySeverity;
  location: { path: string; lines: { begin: number } };
}

/** A finding on the merge request description has no file. GitLab requires a path, so it gets one that is plainly not a file. */
export const DESCRIPTION_PATH = 'MERGE_REQUEST_DESCRIPTION';

const RANK: Record<string, number> = { block: 0, review: 1, advise: 2 };
const SEVERITY: Record<string, CodeQualitySeverity> = { block: 'critical', review: 'major', advise: 'minor' };

/** A relative path with no "./" or "/" prefix, as GitLab requires. */
function relativePath(file: string): string {
  return file.replace(/^(?:\.\/+|\/+)+/, '');
}

/**
 * One issue per finding. The text is the finding's masked evidence, which is exactly what is already posted to PulseCheck
 * and shown in the check run: no source line is added. The fingerprint is a hash of what identifies the finding, so GitLab
 * can tell a new finding from one it has already seen on the target branch.
 */
export function toCodeQualityReport(outcomes: ReadonlyArray<Pick<FrameworkOutcome, 'framework' | 'result'>>): CodeQualityIssue[] {
  const issues: CodeQualityIssue[] = [];
  for (const outcome of outcomes) {
    const locations = findingLocations(outcome.result);
    const title = FRAMEWORK_INFO[outcome.framework].title;
    // The same selection the post makes (clampFindingsForPost): above the cap the most severe findings are kept, so a
    // blocking finding that was posted is never missing from the report.
    const kept = outcome.result.findings
      .map((finding, index) => ({ finding, index }))
      .sort((a, b) => (RANK[a.finding.action] ?? 3) - (RANK[b.finding.action] ?? 3) || a.index - b.index)
      .slice(0, POST_LIMITS.maxFindings);
    kept.forEach(({ finding, index }) => {
      const where = locations[index];
      const path = where?.file ? relativePath(where.file) || DESCRIPTION_PATH : DESCRIPTION_PATH;
      const begin = where?.file && where.line && where.line >= 1 ? where.line : 1;
      issues.push({
        description: `${title}: ${finding.masked_evidence}`,
        check_name: `pulsecheck/${outcome.framework === 'Data Compliance' ? 'data-compliance' : 'ai-change-control'}/${finding.rule_id}`,
        fingerprint: createHash('sha256')
          .update([outcome.framework, finding.rule_id, path, String(begin), finding.masked_evidence].join('\u0000'))
          .digest('hex'),
        severity: SEVERITY[finding.action] ?? 'info',
        location: { path, lines: { begin } },
      });
    });
  }
  return issues;
}

/** The file content: pretty JSON, a trailing newline, never a byte order mark. */
export function renderCodeQuality(issues: readonly CodeQualityIssue[]): string {
  return `${JSON.stringify(issues, null, issues.length === 0 ? 0 : 2)}\n`;
}
