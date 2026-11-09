/**
 * Publishes the GitHub check run that branch protection can require to block a
 * merge. Verdict → conclusion mapping is the load-bearing decision:
 *   fail → failure (blocks a required check)
 *   pass → success
 *   needs_review → neutral (advisory; surfaces findings without hard-blocking)
 *
 * The summary lists only masked evidence — it is rendered in the GitHub UI, so
 * it must never contain a raw value.
 */
import { DEFAULT_FRAMEWORK, FRAMEWORK_INFO, type FrameworkId } from './frameworks.js';
import type { Finding, ScanResult, Verdict } from './types.js';

type Conclusion = 'success' | 'failure' | 'neutral';

/**
 * Make any value safe to drop into one markdown table cell.
 *
 * A `|` ends the cell and a newline ends the ROW, so either one lets org- or
 * contributor-controlled text restructure the rendered table.
 *
 * BACKSLASHES ARE ESCAPED FIRST, and the order is load-bearing: escaping only
 * `|` turns the input `a\|b` into `a\\|b`, which GFM renders as a literal
 * backslash followed by a LIVE cell delimiter — so the escaping reintroduced
 * exactly the break it was added to prevent. `rule_id` is org-controlled and
 * reaches here unsanitised, so that was reachable.
 *
 * The 300-char clamp bounds one cell, NOT the summary: 100 rows x 4 clamped
 * cells is ~81 KB, past GitHub's 65535-char limit on its own. The caller is
 * responsible for the total (see the MAX_ROWS note there); this only guarantees
 * no single value is unbounded.
 */
function cell(value: unknown): string {
  const text = typeof value === 'string' ? value : String(value ?? '');
  const cleaned = text
    .replace(/[\r\n]+/g, ' ')
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .trim();
  return cleaned.length > 300 ? `${cleaned.slice(0, 300)}…` : cleaned;
}

export function verdictToConclusion(verdict: Verdict): Conclusion {
  if (verdict === 'fail') return 'failure';
  if (verdict === 'pass') return 'success';
  return 'neutral';
}

/**
 * The conclusion for one framework's check run. A framework that `fail-on` does not
 * list is ADVISORY: its `fail` verdict is shown but concludes `neutral`, so a check
 * the customer never asked to gate on can never block a merge by itself.
 */
export function checkRunConclusion(verdict: Verdict, advisory: boolean): Conclusion {
  const conclusion = verdictToConclusion(verdict);
  return advisory && conclusion === 'failure' ? 'neutral' : conclusion;
}

/** A finding's article references: schema-2 `articles`, else the legacy `gdpr_article`. */
function articlesOf(f: Finding): string[] {
  return f.articles ?? f.gdpr_article ?? [];
}

interface OctokitLike {
  rest: {
    checks: {
      create: (params: Record<string, unknown>) => Promise<unknown>;
    };
  };
}

export interface CheckRunInput {
  owner: string;
  repo: string;
  headSha: string;
  result: ScanResult;
  /** Which framework's check this is. Omitted = the original 'Data Compliance Gate'. */
  framework?: FrameworkId;
  /** True when `fail-on` does not list the framework: the check can never conclude `failure`. */
  advisory?: boolean;
}

/** Render a masked-only markdown summary. Safe to display in the GitHub UI. */
export function buildSummary(result: ScanResult, framework: FrameworkId = DEFAULT_FRAMEWORK): string {
  const info = FRAMEWORK_INFO[framework];
  const lines: string[] = [];
  const counts = result.findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.action] = (acc[f.action] ?? 0) + 1;
    return acc;
  }, {});
  lines.push(
    `**Verdict: ${result.verdict}** — ` +
      `${counts.block ?? 0} blocking, ${counts.review ?? 0} need review, ${counts.advise ?? 0} advisory.`,
  );
  if (result.findings.length > 0) {
    // GitHub caps the summary at 65535 chars; clamp rows so checks.create never fails.
    const MAX_ROWS = 100;
    lines.push('', `| Action | Rule | ${info.articlesLabel} | Evidence (masked) |`, '| --- | --- | --- | --- |');
    for (const f of result.findings.slice(0, MAX_ROWS)) {
      // EVERY cell is de-fanged, not just the evidence. `rule_id` comes from the
      // org's ruleset and was interpolated raw: an id containing `|` and a
      // newline could close the row and FORGE AN EXTRA ONE — an independent
      // review produced a fake row reading "ALL CLEAR" in the official gate
      // summary. `gdpr_article` is org-controlled too.
      lines.push(
        `| ${cell(f.action)} | ${cell(f.rule_id)} | ${cell(articlesOf(f).join(', '))} | ${cell(f.masked_evidence)} |`,
      );
    }
    if (result.findings.length > MAX_ROWS) {
      lines.push('', `_…and ${result.findings.length - MAX_ROWS} more findings (truncated for display)._`);
    }
  } else {
    lines.push('', 'No findings.');
  }
  if (result.warnings.length > 0) {
    lines.push('', '**Warnings:**', ...result.warnings.map((w) => `- ${w}`));
  }
  lines.push(
    '',
    framework === DEFAULT_FRAMEWORK
      ? '_Scanned in your CI by the PulseCheck Data Compliance Gate. Raw diff and PII never leave this runner._'
      : '_Scanned in your CI by PulseCheck. Raw diff and PII never leave this runner. Findings are signals to review, not a legal conclusion._',
  );
  return lines.join('\n');
}

export async function publishCheckRun(
  octokit: OctokitLike,
  input: CheckRunInput,
): Promise<Conclusion> {
  const framework = input.framework ?? DEFAULT_FRAMEWORK;
  const info = FRAMEWORK_INFO[framework];
  const conclusion = checkRunConclusion(input.result.verdict, input.advisory ?? false);
  await octokit.rest.checks.create({
    owner: input.owner,
    repo: input.repo,
    name: info.checkRunName,
    head_sha: input.headSha,
    status: 'completed',
    conclusion,
    output: {
      title: `${info.title}: ${input.result.verdict}`,
      summary: buildSummary(input.result, framework),
    },
  });
  return conclusion;
}
