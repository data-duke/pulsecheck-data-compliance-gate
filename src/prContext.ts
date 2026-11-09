/**
 * FEAT-09 (docs/plans/rule-engine-findings.md §4) — let the gate scan a pull request
 * that is named explicitly, not only the one that triggered the workflow.
 *
 * Everything downstream already works for merged pull requests: the diff endpoint
 * serves them, the scanner does not care, and the report endpoint records against a
 * PR number. Only the INPUT was missing, which is why a customer could not answer
 * "what would this ruleset have said about our last six months?" without merging
 * something first.
 *
 * TWO THINGS A BACKFILL MUST NOT DO, both encoded here:
 *
 * 1. **Stamp check runs onto old merged commits.** A check run is a claim about a
 *    commit's current state; publishing one against a six-month-old merge rewrites
 *    history in the UI and can re-open a settled required-check decision. Hence
 *    `publishCheckRun`, which a backfill turns off while still recording the verdict.
 *
 * 2. **Pretend an explicit number is the event's PR.** When both are present the
 *    explicit input wins — that is what the operator asked for — but the two are
 *    never silently conflated, because the head SHA differs and a verdict recorded
 *    against the wrong commit is worse than no verdict.
 */

export interface PrRefResolution {
  /** The pull request to scan, or null when there is nothing to do. */
  prNumber: number | null;
  /** True when the number came from the explicit input rather than the event. */
  explicit: boolean;
  /** Why nothing will be scanned, for an informational log line. */
  reason?: 'no-pr-context' | 'invalid-input';
}

/**
 * Decide which pull request to scan.
 *
 * The explicit input wins over the event payload so a `workflow_dispatch` backfill can
 * run inside a repository that also has `pull_request` triggers configured.
 */
export function resolvePrRef(
  payloadPrNumber: number | null | undefined,
  rawInput: string | null | undefined,
): PrRefResolution {
  const trimmed = (rawInput ?? '').trim();

  if (trimmed) {
    // Deliberately strict: `22abc` or `-3` is a typo in a hand-typed dispatch field,
    // and guessing at it would scan a pull request the operator did not name.
    if (!/^\d+$/.test(trimmed)) {
      return { prNumber: null, explicit: true, reason: 'invalid-input' };
    }
    const parsed = Number(trimmed);
    if (!Number.isSafeInteger(parsed) || parsed <= 0) {
      return { prNumber: null, explicit: true, reason: 'invalid-input' };
    }
    return { prNumber: parsed, explicit: true };
  }

  if (typeof payloadPrNumber === 'number' && Number.isSafeInteger(payloadPrNumber) && payloadPrNumber > 0) {
    return { prNumber: payloadPrNumber, explicit: false };
  }

  return { prNumber: null, explicit: false, reason: 'no-pr-context' };
}

/**
 * Whether to publish a check run for this run.
 *
 * Defaults to true so existing workflows are untouched. A backfill sets it false; an
 * explicitly-numbered run does NOT suppress publication on its own, because scanning
 * an open PR by number is a legitimate re-run whose check run is still wanted.
 */
export function shouldPublishCheckRun(rawInput: string | null | undefined): boolean {
  const value = (rawInput ?? '').trim().toLowerCase();
  if (!value) return true;
  return !(value === 'false' || value === 'no' || value === '0');
}
