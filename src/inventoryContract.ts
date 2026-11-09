/**
 * The AI usage inventory contract (PR E), as this Action sees it.
 *
 * This is a deliberate COPY of supabase/functions/_shared/ciInventoryContract.ts, not an
 * import: the Action is published as a standalone mirror and cannot reach into `supabase/`.
 * The root test `ciInventoryContract.actionParity.test.ts` fails if a rule id, a signature
 * key or a limit ever disagrees, so the copy cannot drift. Same values, same order.
 *
 * Aggregates only: a count per (rule, signature), never a code line.
 */

/** EU AI Act rules that run in a baseline scan. A rule outside this list is never scanned or accepted there. */
export const BASELINE_RULE_IDS = [
  'eaa-ci-ai-sdk-manifest',
  'eaa-ci-ai-import',
  'eaa-ci-ai-endpoint',
  'eaa-ci-emotion-biometric',
] as const;
export type BaselineRuleId = (typeof BASELINE_RULE_IDS)[number];

/**
 * What a detection is, as a small closed vocabulary the Action derives from the matched text and the server re-checks.
 * Never free text: a key outside this list is rejected, so no customer string reaches the inventory.
 */
export const SIGNATURE_KEYS = [
  'openai',
  'anthropic',
  'google-ai',
  'mistral',
  'cohere',
  'langchain',
  'llamaindex',
  'huggingface',
  'groq',
  'replicate',
  'ollama',
  'aws-bedrock',
  'azure-openai',
  'vercel-ai-sdk',
  'litellm',
  'other-ai',
  'emotion-biometric',
] as const;
export type SignatureKey = (typeof SIGNATURE_KEYS)[number];

export const INVENTORY_LIMITS = {
  /** Observation rows per post: 3 SDK rules x 16 AI keys + the emotion rule x its one key = 49, the most that can be distinct. */
  maxObservations: 49,
  /** Largest count stored for one (rule, signature); a larger one is clamped, never rejected. */
  maxCount: 1_000_000,
  /** Sample paths per observation, only ever stored when the organization switched them on (default off, D7). */
  maxSamplePaths: 3,
  maxPathChars: 300,
  /** Scan runs kept per repository; older ones are deleted by ci-inventory-result after each post. */
  keepRunsPerRepo: 10,
  /**
   * Largest request body ci-inventory-result reads (128 KB), checked on Content-Length and again on the bytes read.
   * A full post (49 observations x 3 paths of 300 characters) is about 50 KB, so a real scan never comes near it.
   */
  maxBodyBytes: 131072,
} as const;

/** One aggregate in a baseline post. */
export interface InventoryObservation {
  rule_id: BaselineRuleId;
  signature_key: SignatureKey;
  /** Number of matching lines across the tree (not files): a cheap, stable aggregate. */
  count: number;
  /** At most `maxSamplePaths` repo-relative paths. Sent only when the Action was told to; stored only when the org allows it. */
  sample_paths?: string[];
}

/** Body of POST /functions/v1/ci-inventory-result (Bearer ci token with scope `inventory:write`). */
export interface InventoryResultPayload {
  repo: string; // owner/repo: provider is always 'github', so exactly two segments (the server lower-cases it)
  provider: 'github';
  commit_sha: string;
  /** Tracked files read / skipped (size, binary, excluded). Informational. */
  files_scanned: number;
  /** True when the walk stopped at its file, size or time budget: the counts are a lower bound. */
  truncated: boolean;
  observations: InventoryObservation[];
}

export function isBaselineRuleId(value: unknown): value is BaselineRuleId {
  return typeof value === 'string' && (BASELINE_RULE_IDS as readonly string[]).includes(value);
}

export function isSignatureKey(value: unknown): value is SignatureKey {
  return typeof value === 'string' && (SIGNATURE_KEYS as readonly string[]).includes(value);
}

/** The emotion rule has exactly one key, and no other rule may use it: a rule/key pair outside this is never stored or counted. */
export function isValidRuleSignaturePair(rule: BaselineRuleId, key: SignatureKey): boolean {
  return (rule === 'eaa-ci-emotion-biometric') === (key === 'emotion-biometric');
}
