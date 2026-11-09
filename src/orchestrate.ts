/**
 * Pure orchestration of a multi-framework scan: one independent `scan()` per
 * framework, each with its own verdict, findings and warnings, and the `fail-on`
 * decision. Kept out of index.ts (which runs on import) so it is unit-tested.
 *
 * Per-framework verdicts are computed HERE, in the Action, and never
 * reconstructed on the server from findings: the Action's warnings (which floor
 * a verdict to needs_review) are never posted.
 */
import { DEFAULT_FRAMEWORK, type FrameworkId } from './frameworks.js';
import { scan, type ScanInput } from './scan.js';
import type { FrameworkRuleset, ScanResult } from './types.js';

export interface FrameworkOutcome {
  framework: FrameworkId;
  ruleset: FrameworkRuleset;
  result: ScanResult;
  /** True when `fail-on` does not list this framework: its check run never concludes `failure`. */
  advisory: boolean;
}

/**
 * Scan every ruleset against the same PR. Each call gets its own time budget;
 * `scan()` resets all of its module state per call, so frameworks cannot leak
 * findings or warnings into one another.
 */
export function scanFrameworks(
  rulesets: readonly FrameworkRuleset[],
  input: ScanInput,
  failOn: readonly FrameworkId[],
): FrameworkOutcome[] {
  return rulesets.map((ruleset) => ({
    framework: ruleset.framework,
    ruleset,
    result: scan(ruleset, input),
    advisory: !failOn.includes(ruleset.framework),
  }));
}

/** Outcomes that must fail the step: a `fail` verdict in a framework `fail-on` lists. */
export function failingFrameworks(outcomes: readonly FrameworkOutcome[]): FrameworkOutcome[] {
  return outcomes.filter((o) => !o.advisory && o.result.verdict === 'fail');
}

/**
 * The outcome the action's `verdict` / `findings-count` outputs describe: the
 * original GDPR stream when present (so those outputs mean what they always did),
 * else the first.
 */
export function primaryOutcome(outcomes: readonly FrameworkOutcome[]): FrameworkOutcome | undefined {
  return outcomes.find((o) => o.framework === DEFAULT_FRAMEWORK) ?? outcomes[0];
}
