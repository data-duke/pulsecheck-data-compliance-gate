/**
 * PR E · the baseline walker behind `scan-mode: baseline` (AI usage inventory).
 *
 * Walks every tracked file of the checkout, runs the EU AI Act baseline rules over each line and returns
 * AGGREGATES ONLY: a count of matching lines per (rule, signature key), plus optionally up to three example paths.
 * No code line, no matched text and no file content ever reaches the result; the signature key is chosen from a
 * fixed vocabulary (inventoryContract.ts), never copied from the code.
 *
 * Pure: the file lister/reader and the clock are injected, so the whole walk is unit-tested without a checkout.
 * Path filtering and pattern compilation are the PR scan's own helpers (scan.ts), so a rule means the same thing in
 * both modes: same ALWAYS_EXCLUDE, same file_scope / exclude_paths glob semantics, same `(?i)` prefix handling.
 *
 * Design: docs/plans/ai-change-control-pr-e-plan.md.
 */
import {
  compile,
  globRefusal,
  isExcluded,
  matchesFileScope,
  MAX_SCAN_LINE_CHARS,
  stripStatefulFlags,
  unusablePatternFields,
} from './scan.js';
import {
  INVENTORY_LIMITS,
  isBaselineRuleId,
  type BaselineRuleId,
  type InventoryObservation,
  type InventoryResultPayload,
  type SignatureKey,
} from './inventoryContract.js';
import type { Rule, Ruleset } from './types.js';

/**
 * The walk's budgets. Hitting the file cap or the time budget sets `truncated`: the counts are then a lower bound.
 *
 * `truncated` is ALSO set whenever the scan could not look where it was meant to, because the server reads
 * "complete (not truncated) and nothing found" as "this repository no longer uses AI" and deletes its previous
 * detections. So a run never posts complete-and-clean when a baseline rule did not compile, when a rule's file_scope
 * holds a glob the scanner refuses (that part of the scope matched nothing), or when a rule had files in its scope
 * and none of them could be read (all over the size cap, not regular files, failed reads, a sparse checkout). A file
 * that was read and judged binary counts as read.
 */
export const BASELINE_LIMITS = {
  /** Files opened (after exclusions). One more candidate than this marks the result truncated. */
  maxFiles: 5000,
  /** A larger file is skipped unread (generated bundles, data dumps). */
  maxFileBytes: 512 * 1024,
  /** A NUL byte in this prefix marks a file binary (git's own heuristic). */
  binarySniffBytes: 8192,
  /** Wall-clock budget for the whole walk. */
  budgetMs: 60_000,
} as const;

/** Lines between two clock reads inside one file. */
const BUDGET_SAMPLE_LINES = 512;

/** What the walker needs from a checkout. index.ts supplies git ls-files + fs; tests supply memory. */
export interface BaselineFileSource {
  /** Repo-relative paths of the tracked files. */
  listFiles(): Promise<string[]>;
  /** Size in bytes of a REGULAR file, or null for anything else (symlink, submodule, missing). */
  size(path: string): Promise<number | null>;
  read(path: string): Promise<Uint8Array>;
}

export interface BaselineOptions {
  repo: string;
  commitSha: string;
  /** Send up to INVENTORY_LIMITS.maxSamplePaths example paths per observation. Off by default (D7). */
  samplePaths: boolean;
  limits?: Partial<{ maxFiles: number; maxFileBytes: number; budgetMs: number }>;
  now?: () => number;
}

/** Informational counters for the log. Never posted. */
export interface BaselineStats {
  listed: number;
  /** Files no baseline rule covers (ALWAYS_EXCLUDE, file_scope, exclude_paths): never opened. */
  outOfScope: number;
  skippedSize: number;
  skippedBinary: number;
  /** Not a regular file, or the read failed. */
  skippedUnreadable: number;
  /** Lines longer than MAX_SCAN_LINE_CHARS, scanned up to the clamp only (as in the PR scan). */
  clampedLines: number;
}

export interface BaselineScan {
  payload: InventoryResultPayload;
  stats: BaselineStats;
  /** Rule problems (a pattern or glob the scanner refuses). Rule ids are allowlisted, so nothing customer-written. */
  warnings: string[];
}

/**
 * The rules a baseline scan runs: served with `baseline: true` (by ci-ruleset, PR E) AND on the contract's list.
 * Both, so neither an old server (no flag) nor a server flagging a rule the contract does not know can widen it.
 */
export function selectBaselineRules(ruleset: Pick<Ruleset, 'rules'>): Rule[] {
  return (ruleset.rules ?? []).filter(
    (r): r is Rule => !!r && typeof r === 'object' && r.baseline === true && isBaselineRuleId(r.id),
  );
}

/**
 * The signature family table: first match wins, tested against the LOWERCASED matched text of an AI rule
 * (eaa-ci-ai-sdk-manifest, eaa-ci-ai-import, eaa-ci-ai-endpoint). A match no entry claims is `other-ai`.
 * The emotion rule always yields `emotion-biometric` and nothing else does.
 *
 * Order matters and is deliberate:
 *  - orchestration SDKs first (Vercel AI SDK, LangChain, LlamaIndex, and Spring AI / Semantic Kernel as `other-ai`),
 *    because their package names embed the provider they wrap (`@ai-sdk/openai`, `langchain-openai`,
 *    `spring-ai-openai`) and the inventory records the SDK the code depends on;
 *  - Azure OpenAI and AWS Bedrock before the providers whose names they contain;
 *  - Anthropic before Google (`@anthropic-ai/vertex-sdk` is Anthropic's SDK), OpenAI last.
 */
export const SIGNATURE_FAMILIES: ReadonlyArray<readonly [SignatureKey, RegExp]> = [
  ['vercel-ai-sdk', /@ai-sdk\/|["'`]ai(?:\/[a-z0-9._/-]*)?["'`]/],
  ['langchain', /langchain/],
  ['llamaindex', /llama[-_]?index/],
  ['other-ai', /springframework\.ai|spring-ai-|semantickernel/],
  ['azure-openai', /azure[./]openai|azure\.ai\.openai|\.openai\.azure\.com/],
  ['aws-bedrock', /bedrock-runtime/],
  ['anthropic', /anthropic/],
  ['google-ai', /google|vertexai/],
  ['huggingface', /huggingface|transformers/],
  ['mistral', /mistral/],
  ['cohere', /cohere/],
  ['groq', /groq/],
  ['replicate', /replicate/],
  ['ollama', /ollama/],
  ['litellm', /litellm/],
  ['openai', /openai/],
];

const EMOTION_RULE: BaselineRuleId = 'eaa-ci-emotion-biometric';

/** The signature key of one match. Only ever a contract key: the matched text itself is dropped right here. */
export function signatureKeyFor(ruleId: string, matchedText: string): SignatureKey {
  if (ruleId === EMOTION_RULE) return 'emotion-biometric';
  const lower = matchedText.toLowerCase();
  for (const [key, re] of SIGNATURE_FAMILIES) if (re.test(lower)) return key;
  return 'other-ai';
}

interface Accumulator {
  ruleId: string;
  key: SignatureKey;
  count: number;
  paths: string[];
}

const byCodeUnit = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** Accumulated counts to wire observations: sorted by rule_id then signature_key, clamped, capped. */
export function aggregateObservations(acc: ReadonlyMap<string, Accumulator>, samplePaths: boolean): InventoryObservation[] {
  return [...acc.values()]
    .filter((a) => a.count > 0)
    .sort((a, b) => byCodeUnit(a.ruleId, b.ruleId) || byCodeUnit(a.key, b.key))
    .slice(0, INVENTORY_LIMITS.maxObservations)
    .map((a) => ({
      rule_id: a.ruleId as BaselineRuleId,
      signature_key: a.key,
      count: Math.min(a.count, INVENTORY_LIMITS.maxCount),
      ...(samplePaths ? { sample_paths: a.paths.slice(0, INVENTORY_LIMITS.maxSamplePaths) } : {}),
    }));
}

interface CompiledRule {
  rule: Rule;
  re: RegExp;
  excludeRe: RegExp | null;
  requireRe: RegExp | null;
  /** Files of this rule's scope the walk reached, and how many of them were actually read. */
  inScope: number;
  read: number;
}

/** Compile a rule as the PR scan would; anything it would refuse is reported, never silently dropped. */
function compileRule(rule: Rule, warnings: string[]): CompiledRule | null {
  const unusable = unusablePatternFields(rule);
  if (unusable.length > 0) {
    warnings.push(`Rule "${rule.id}" declares ${unusable.join(', ')} that could not be compiled; that part of the rule did not run.`);
  }
  const refused = [...(rule.detect.file_scope ?? []), ...(rule.detect.exclude_paths ?? [])].filter((g) => globRefusal(g) !== null);
  if (refused.length > 0) {
    warnings.push(`Rule "${rule.id}" declares ${refused.length} path glob(s) the scanner refuses (they match every path or are too complex); they matched nothing.`);
  }
  const re = compile(rule.detect.pattern);
  if (!re) {
    if (unusable.length === 0) warnings.push(`Rule "${rule.id}" has no pattern a baseline scan can run; it was skipped.`);
    return null;
  }
  // Tier-1 controls cannot be gated away (same refusal as scan.ts compileGating).
  if (rule.tier === 1 && (rule.detect.exclude_pattern || rule.detect.require_pattern)) {
    warnings.push(`Tier-1 rule "${rule.id}" declares exclude_pattern/require_pattern; a tier-1 control cannot be gated, so those fields were ignored.`);
    return { rule, re, excludeRe: null, requireRe: null, inScope: 0, read: 0 };
  }
  return {
    rule,
    re,
    excludeRe: stripStatefulFlags(compile(rule.detect.exclude_pattern, '')),
    requireRe: stripStatefulFlags(compile(rule.detect.require_pattern, '')),
    inScope: 0,
    read: 0,
  };
}

const INCOMPLETE_SUFFIX = 'The scan is marked incomplete, so PulseCheck keeps the previous detections instead of clearing them.';

function hasNulPrefix(bytes: Uint8Array, sniff: number): boolean {
  const end = Math.min(bytes.length, sniff);
  for (let i = 0; i < end; i++) if (bytes[i] === 0) return true;
  return false;
}

/** Walk the tree and aggregate. Never throws for a single bad file; the lister's failure propagates to the caller. */
export async function runBaselineScan(rules: readonly Rule[], source: BaselineFileSource, opts: BaselineOptions): Promise<BaselineScan> {
  const limits = { ...BASELINE_LIMITS, ...opts.limits };
  const now = opts.now ?? Date.now;
  const started = now();
  const outOfTime = () => now() - started >= limits.budgetMs;

  const warnings: string[] = [];
  const results = rules.map((r) => compileRule(r, warnings));
  const compiled = results.filter((c): c is CompiledRule => c !== null);
  const stats: BaselineStats = { listed: 0, outOfScope: 0, skippedSize: 0, skippedBinary: 0, skippedUnreadable: 0, clampedLines: 0 };
  const acc = new Map<string, Accumulator>();
  let opened = 0;
  let scanned = 0;
  let truncated = false;

  // A rule that did not run, or runs over a narrower scope than it declares, cannot vouch for "nothing found".
  const notRun = rules.filter((_, i) => results[i] === null).map((r) => r.id);
  if (notRun.length > 0) {
    truncated = true;
    warnings.push(`${notRun.length} baseline rule(s) did not run (${notRun.map((id) => `"${id}"`).join(', ')}). ${INCOMPLETE_SUFFIX}`);
  }
  for (const c of compiled) {
    if ((c.rule.detect.file_scope ?? []).some((g) => globRefusal(g) !== null)) {
      truncated = true;
      warnings.push(`Rule "${c.rule.id}" did not scan part of its file scope (a refused glob). ${INCOMPLETE_SUFFIX}`);
    }
  }

  const files = compiled.length > 0 ? await source.listFiles() : [];
  stats.listed = files.length;
  const decoder = new TextDecoder('utf-8');

  walk: for (const path of files) {
    const inScope = compiled.filter(
      (c) => matchesFileScope(path, c.rule.detect.file_scope) && !isExcluded(path, c.rule.detect.exclude_paths),
    );
    if (inScope.length === 0) {
      stats.outOfScope++;
      continue;
    }
    if (opened >= limits.maxFiles || outOfTime()) {
      truncated = true;
      break;
    }
    opened++;
    for (const c of inScope) c.inScope++;

    let bytes: Uint8Array;
    try {
      const size = await source.size(path);
      if (size === null) {
        stats.skippedUnreadable++;
        continue;
      }
      if (size > limits.maxFileBytes) {
        stats.skippedSize++;
        continue;
      }
      bytes = await source.read(path);
    } catch {
      stats.skippedUnreadable++;
      continue;
    }
    // Re-checked on the bytes actually read: the file may have changed between stat and read.
    if (bytes.length > limits.maxFileBytes) {
      stats.skippedSize++;
      continue;
    }
    for (const c of inScope) c.read++;
    if (hasNulPrefix(bytes, BASELINE_LIMITS.binarySniffBytes)) {
      stats.skippedBinary++;
      continue;
    }
    scanned++;

    const lines = decoder.decode(bytes).split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      if (i > 0 && i % BUDGET_SAMPLE_LINES === 0 && outOfTime()) {
        truncated = true;
        break walk;
      }
      let text = lines[i];
      if (text.length === 0) continue;
      if (text.length > MAX_SCAN_LINE_CHARS) {
        stats.clampedLines++;
        text = text.slice(0, MAX_SCAN_LINE_CHARS);
      }
      for (const c of inScope) {
        if (c.excludeRe && c.excludeRe.test(text)) continue;
        if (c.requireRe && !c.requireRe.test(text)) continue;
        const keys = new Set<SignatureKey>();
        c.re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = c.re.exec(text)) !== null) {
          if (c.re.lastIndex === m.index) c.re.lastIndex++; // zero-width guard
          keys.add(signatureKeyFor(c.rule.id, m[0]));
          if (!c.re.global) break;
        }
        for (const key of keys) {
          const id = `${c.rule.id}|${key}`;
          let a = acc.get(id);
          if (!a) acc.set(id, (a = { ruleId: c.rule.id, key, count: 0, paths: [] }));
          a.count++;
          if (
            opts.samplePaths &&
            a.paths.length < INVENTORY_LIMITS.maxSamplePaths &&
            path.length <= INVENTORY_LIMITS.maxPathChars &&
            !a.paths.includes(path)
          ) {
            a.paths.push(path);
          }
        }
      }
    }
  }

  for (const c of compiled) {
    if (c.inScope > 0 && c.read === 0) {
      truncated = true;
      warnings.push(
        `Rule "${c.rule.id}": ${c.inScope} file(s) in its scope, none could be read (over the ${Math.round(limits.maxFileBytes / 1024)} KB size cap, ` +
          `not a regular file, or the read failed: is the checkout sparse or partial?). ${INCOMPLETE_SUFFIX}`,
      );
    }
  }

  return {
    payload: {
      repo: opts.repo,
      provider: 'github',
      commit_sha: opts.commitSha,
      files_scanned: scanned,
      truncated,
      observations: aggregateObservations(acc, opts.samplePaths),
    },
    stats,
    warnings,
  };
}
