/**
 * PR E · `scan-mode: baseline`, provider-neutral: fetch the EU AI Act ruleset, walk the checkout (baseline.ts) and
 * POST the aggregate inventory to ci-inventory-result.
 *
 * Policy: a baseline run is a scheduled inventory, not a gate. It publishes no check run and no verdict, ignores
 * `fail-on`, and NEVER fails the step: an unreachable PulseCheck, a token without `inventory:write`, an org that
 * has not switched AI change control on, or a server that predates PR E are each logged and the run exits 0.
 * (An invalid `scan-mode` input is the one failure, and it is raised by index.ts before anything runs.)
 */
import { runBaselineScan, selectBaselineRules, type BaselineFileSource, type BaselineOptions, type BaselineScan } from './baseline.js';
import { SUPPORTED_CAPS } from './frameworks.js';
import { fetchRulesets, RulesetFetchError, type FetchedRulesets } from './ruleset.js';

export type ScanMode = 'pr' | 'baseline';

/** A checkout the walker can read, plus the commit it is at. */
export interface BaselineCheckout extends BaselineFileSource {
  headSha(): Promise<string>;
}

export interface BaselineRun {
  url: string;
  token: string;
  /** owner/repo, as PulseCheck stores it. */
  repo: string;
  samplePaths: boolean;
  /** Used when HEAD cannot be read from the checkout (the workflow's own commit). */
  fallbackSha: string;
  limits?: BaselineOptions['limits'];
}

export interface BaselineIo {
  info(message: string): void;
  warning(message: string): void;
}

const EU_AI_ACT = 'EU AI Act';

/** Clamp and de-fang a raw input value before echoing it in an error (no newlines, no workflow commands). */
function echo(raw: string): string {
  const cleaned = raw.replace(/[^A-Za-z0-9 ._-]/g, '_');
  return cleaned.length > 40 ? `${cleaned.slice(0, 40)}…` : cleaned;
}

/** The `scan-mode` input: empty means `pr` (today's behaviour). Case-insensitive. */
export function parseScanMode(raw: string | null | undefined): { mode: ScanMode } | { error: string } {
  const v = (raw ?? '').trim().toLowerCase();
  if (v === '' || v === 'pr') return { mode: 'pr' };
  if (v === 'baseline') return { mode: 'baseline' };
  return { error: `scan-mode must be 'pr' or 'baseline' (got "${echo((raw ?? '').trim())}").` };
}

/** The `baseline-sample-paths` input. Anything but true/false stays OFF (the privacy-safe default) with a warning. */
export function parseSamplePaths(raw: string | null | undefined): { value: boolean; warning?: string } {
  const v = (raw ?? '').trim().toLowerCase();
  if (v === '' || v === 'false') return { value: false };
  if (v === 'true') return { value: true };
  return { value: false, warning: `baseline-sample-paths must be 'true' or 'false' (got "${echo((raw ?? '').trim())}"); sample paths stay off.` };
}

const message = (err: unknown) => (err instanceof Error ? err.message : String(err));

/** The `error.code` of an errorResponse body ({ error: { code, message }, success: false }), or null. Never throws. */
async function errorCodeOf(res: Response): Promise<string | null> {
  try {
    const body = (await res.json()) as { error?: { code?: unknown } } | null;
    return typeof body?.error?.code === 'string' ? body.error.code : null;
  } catch {
    return null;
  }
}

/**
 * The explanation for a 401/403 from ci-inventory-result, chosen by status and the allowlisted error code. The
 * server's own message is never echoed (it is not ours to print into a workflow log).
 */
export function refusalReason(status: number, code: string | null): string {
  if (status === 401) {
    return 'the CI token is invalid or has been revoked. Create a new token with inventory:write in PulseCheck (Organization settings → CI Gate) and update the workflow secret.';
  }
  if (code === 'org_expired') {
    return "the organization's PulseCheck subscription or trial has ended, so it cannot record new data. Renew it in PulseCheck (Billing); the token itself is fine.";
  }
  return 'the CI token lacks the inventory:write scope. Create a token with inventory:write in PulseCheck (Organization settings → CI Gate).';
}

export async function runBaseline(run: BaselineRun, checkout: BaselineCheckout, io: BaselineIo): Promise<void> {
  // The same fetch, caps and repository parameter as a PR scan: the baseline rules need `context` to be served.
  let fetched: FetchedRulesets;
  try {
    fetched = await fetchRulesets(run.url, run.token, SUPPORTED_CAPS, run.repo);
  } catch (err) {
    const reason = err instanceof RulesetFetchError ? err.message : String(err);
    io.warning(`Could not reach PulseCheck to fetch the ruleset (${reason}). No AI usage inventory was recorded this run.`);
    return;
  }

  const eu = fetched.rulesets.find((r) => r.framework === EU_AI_ACT);
  if (!eu) {
    io.info('PulseCheck did not serve an EU AI Act ruleset for this organization (AI change control is not switched on), so there is nothing to inventory.');
    return;
  }
  const rules = selectBaselineRules(eu);
  if (rules.length === 0) {
    io.info('The EU AI Act ruleset PulseCheck served has no baseline rules (the server predates the AI usage inventory), so there is nothing to inventory.');
    return;
  }

  let commitSha: string;
  try {
    commitSha = await checkout.headSha();
  } catch {
    commitSha = run.fallbackSha;
  }

  let result: BaselineScan;
  try {
    result = await runBaselineScan(rules, checkout, { repo: run.repo, commitSha, samplePaths: run.samplePaths, limits: run.limits });
  } catch (err) {
    io.warning(
      `Could not list the repository's files (${message(err)}). A baseline scan needs the code checked out: add an actions/checkout step before this action. No AI usage inventory was recorded this run.`,
    );
    return;
  }

  const { payload, stats, warnings } = result;
  for (const w of warnings) io.warning(`AI usage inventory: ${w}`);
  io.info(
    `Baseline scan: ${stats.listed} tracked file(s), ${payload.files_scanned} scanned ` +
      `(${stats.outOfScope} out of scope, ${stats.skippedSize} over the size cap, ${stats.skippedBinary} binary, ` +
      `${stats.skippedUnreadable} unreadable), ${payload.observations.length} observation(s). ` +
      `Sample paths: ${run.samplePaths ? 'on' : 'off'}.`,
  );
  if (payload.truncated) {
    io.warning(
      'The baseline scan is incomplete (it stopped at its file or time budget, or could not run a rule or read the files in its scope; see the warnings above), so the AI usage counts are a lower bound and PulseCheck keeps the previous detections.',
    );
  }

  const endpoint = `${run.url.replace(/\/+$/, '')}/functions/v1/ci-inventory-result`;
  let res: Response;
  try {
    res = await fetch(endpoint, {
      method: 'POST',
      headers: { Authorization: `Bearer ${run.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    io.warning(`Could not record the AI usage inventory with PulseCheck: ${message(err)}`);
    return;
  }

  if (res.status === 401 || res.status === 403) {
    io.warning(`PulseCheck refused the AI usage inventory (HTTP ${res.status}): ${refusalReason(res.status, await errorCodeOf(res))}`);
    return;
  }
  if (!res.ok) {
    io.warning(`Could not record the AI usage inventory with PulseCheck: ci-inventory-result returned HTTP ${res.status}.`);
    return;
  }

  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  if (body && typeof body === 'object' && (body as { stored?: unknown }).stored === false) {
    io.info('PulseCheck did not store this AI usage inventory: AI change control is not switched on for this organization.');
    return;
  }
  io.info(`Recorded ${payload.observations.length} observation(s) of AI usage with PulseCheck.`);
}
