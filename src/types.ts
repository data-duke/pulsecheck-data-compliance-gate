/**
 * Shared type contracts for the PulseCheck Data Compliance Gate action.
 *
 * These mirror — exactly — the JSON returned by GET /functions/v1/ci-ruleset
 * and the body POSTed to /functions/v1/ci-scan-result. Do not loosen these
 * without updating the PulseCheck edge-function contract in lock-step.
 */

export type RuleAction = 'block' | 'review' | 'advise';
export type RuleTier = 1 | 2 | 3;

export type DetectMethod = 'pattern' | 'checksum' | 'signature';
export type DetectTarget = 'diff' | 'pr_description';
export type DiffSide = 'added' | 'removed' | 'either';
export type PairWindow = 'same_hunk' | 'same_file';

export type ValidatorName = 'iban' | 'svnr' | 'steuer_id' | 'credit_card';

export interface PairedSpec {
  minus: string;
  plus: string;
  window: PairWindow;
}

export interface DetectSpec {
  method: DetectMethod;
  target: DetectTarget;
  /** Optional — defaults to 'either' when not specified. */
  diff_side?: DiffSide;
  pattern?: string;
  paired?: PairedSpec;
  validator?: ValidatorName[];
  /**
   * Softening hint, NOT a filter: it can only downgrade a `block`, and only in
   * evaluateLinePattern. See `gradeAction` in scan.ts, and prefer
   * `require_pattern` below when the intent is "do not report this at all".
   */
  require_context?: string;
  /**
   * Suppressor. When this matches the scanned text, the finding is dropped
   * outright — no finding, no downgrade. Honoured in every evaluation path.
   */
  exclude_pattern?: string;
  /**
   * Precondition. When set, a finding is only emitted if this ALSO matches the
   * scanned text. Honoured in every evaluation path.
   */
  require_pattern?: string;
  signature?: string;
  file_scope?: string[];
  exclude_paths?: string[];
  /** Currently only the literal "synthetic" allowlist mode is supported. */
  allowlist?: 'synthetic';
  /** Human-readable masking hint, e.g. "IBAN-pattern". */
  mask: string;
}

export interface Rule {
  id: string;
  name: string;
  gdpr_article: string[];
  action: RuleAction;
  tier: RuleTier;
  detect: DetectSpec;
}

export interface AllowlistSpec {
  emails: string[];
  names: string[];
  domains: string[];
  ip_ranges: string[];
  ibans: string[];
  /**
   * Synthetic card numbers. Added because there was NO way to declare one: the
   * card networks' published test numbers are Luhn-valid by design, so a repo
   * that documents or tests against them had a tier-1 rule blocking on values
   * that are not personal data and never were. `ibans` already existed for
   * exactly this reason; this is its missing twin. Optional so an older served
   * ruleset without the key keeps working unchanged.
   */
  cards?: string[];
}

export interface SignaturesSpec {
  'telemetry-sdks': string[];
  'pii-datastore-credentials': string[];
  'processor-jurisdiction': string[];
  [key: string]: string[];
}

export interface Ruleset {
  ruleset_version: number;
  ruleset_hash: string;
  rules: Rule[];
  allowlist: AllowlistSpec;
  signatures: SignaturesSpec;
}

export type Verdict = 'pass' | 'fail' | 'needs_review';

export interface Finding {
  rule_id: string;
  gdpr_article: string[];
  action: string;
  masked_evidence: string;
}

export interface ScanResult {
  verdict: Verdict;
  findings: Finding[];
  /** Non-fatal warnings (e.g. diff truncation). Never contains raw evidence. */
  warnings: string[];
}

export interface ScanResultPayload {
  repo: string;
  pr_number: number;
  commit_sha: string;
  ruleset_version: number;
  ruleset_hash: string;
  verdict: Verdict;
  findings: Finding[];
}
