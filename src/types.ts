/**
 * Shared type contracts for the PulseCheck Data Compliance Gate action.
 *
 * These mirror — exactly — the JSON returned by GET /functions/v1/ci-ruleset
 * and the body POSTed to /functions/v1/ci-scan-result. Do not loosen these
 * without updating the PulseCheck edge-function contract in lock-step.
 */

import type { FrameworkId } from './frameworks.js';
import type { GateProvider } from './provider.js';

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
  /**
   * Grading by the registry context (capability `context`). The first entry whose every `when` key equals the
   * context value applies; it can only LOWER a finding's action. Served only with `requires_caps: ['context']`.
   */
  applies_when?: AppliesWhen[];
  /** Human-readable masking hint, e.g. "IBAN-pattern". */
  mask: string;
}

export interface AppliesWhen {
  when: Record<string, boolean>;
  action: 'review' | 'advise';
}

export interface Rule {
  id: string;
  name: string;
  /** The original GDPR stream's article references. Absent on a schema-2 framework's rules. */
  gdpr_article?: string[];
  /** Schema-2 frameworks' article references ("may be relevant to"). */
  articles?: string[];
  /** What a hit may affect: the AI system's assessment, specific controls, or both. */
  relevance?: Array<'assessment' | 'control'>;
  action: RuleAction;
  tier: RuleTier;
  detect: DetectSpec;
  /**
   * PR E: set by ci-ruleset on the EU AI Act rules a baseline scan (`scan-mode: baseline`) runs. A PR scan ignores
   * it; a baseline scan runs a rule only when this is literally `true` AND its id is in BASELINE_RULE_IDS.
   */
  baseline?: boolean;
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
  /** Registry context served with a schema-2 ruleset when the Action announced `context`. Never part of ruleset_hash. */
  context?: Record<string, unknown>;
  /** SHA-256 of the canonical context, echoed back unchanged with the verdict. */
  context_hash?: string;
}

/** One framework's ruleset, as served by ci-ruleset. A legacy server's single ruleset is read as 'Data Compliance'. */
export interface FrameworkRuleset extends Ruleset {
  framework: FrameworkId;
  /** Rules the server withheld because this Action did not announce a capability they need. */
  dropped_rules?: Array<{ id: string; missing_caps: string[] }>;
  /** True when the server sent a context (or hash) this Action refused as malformed: graded without it, not posted. */
  context_rejected?: boolean;
}

export type Verdict = 'pass' | 'fail' | 'needs_review';

export interface Finding {
  rule_id: string;
  /** Present on the original GDPR stream's findings. */
  gdpr_article?: string[];
  /** Present on a schema-2 framework's findings, instead of `gdpr_article`. */
  articles?: string[];
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

/** One framework's verdict inside a schema-2 post. */
export interface FrameworkResultPayload {
  framework: FrameworkId;
  ruleset_version: number;
  ruleset_hash: string;
  verdict: Verdict;
  findings: Finding[];
  /** Echoed unchanged from the ruleset, both or neither (ci-scan-result recomputes and compares the hash). */
  context?: Record<string, unknown>;
  context_hash?: string;
}

/** The multi-framework body of ci-scan-result. */
export interface ScanResultPayloadV2 {
  repo: string;
  pr_number: number;
  commit_sha: string;
  provider: GateProvider;
  results: FrameworkResultPayload[];
}
