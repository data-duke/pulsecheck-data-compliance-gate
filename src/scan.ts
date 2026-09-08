/**
 * The scanner. Pure, deterministic, side-effect free: it takes a ruleset plus
 * the (already-fetched) diff text and PR description, and returns a verdict +
 * masked findings. No network, no GitHub, no raw evidence in the output.
 */
import {
  ParsedDiff,
  parseDiff,
  addedLines,
  removedLines,
  minusPlusPairs,
  MAX_MINUS_PLUS_PAIRS,
  DiffLine,
} from './diff.js';
import { maskFinding, maskEmail } from './mask.js';
import { runValidators } from './validators.js';
import {
  Ruleset,
  Rule,
  Finding,
  Verdict,
  ScanResult,
  AllowlistSpec,
} from './types.js';

/**
 * Paths always excluded regardless of a rule's own `exclude_paths`. These are
 * lockfiles, build output, vendored deps and minified bundles — high-noise,
 * low-signal surfaces where a "match" is almost never a real PII leak.
 */
const ALWAYS_EXCLUDE: RegExp[] = [
  /(^|\/)package-lock\.json$/,
  /(^|\/)yarn\.lock$/,
  /(^|\/)dist\//,
  /(^|\/)build\//,
  /(^|\/)vendor\//,
  /\.min\.[^/]*$/,
  /(^|\/)node_modules\//,
];

export interface ScanInput {
  /** Raw unified diff text. */
  diff: string;
  /** PR description / body text. */
  prDescription?: string;
  /**
   * Set when the diff was capped/truncated upstream (over diff-cap-bytes).
   * Forces a needs_review floor and a warning — never a silent pass.
   */
  truncated?: boolean;
  /**
   * Wall-clock budget for the whole scan, in milliseconds. Default BUDGET_MS.
   * Exceeding it stops further work, warns, and floors the verdict to
   * needs_review — the same contract as `truncated`, for the same reason: a scan
   * that did not finish must never render as a clean pass.
   */
  budgetMs?: number;
}

interface RawFinding {
  rule: Rule;
  /** Effective action after any downgrade (block→review etc). */
  effectiveAction: 'block' | 'review' | 'advise';
  maskedEvidence: string;
}

const JS_REGEX_FLAGS = new Set(['g', 'i', 'm', 's', 'u', 'y', 'd']);
const PCRE_INLINE_FLAG_PREFIX = /^\(\?([a-z]+)\)/;

/**
 * Ruleset patterns may carry a PCRE-style leading inline-flag prefix like "(?i)"
 * (see supabase/migrations/20260621120000_data_compliance_ruleset.sql), which JS's
 * RegExp doesn't parse as a modifier group -- compile() would otherwise throw and
 * silently drop the rule (zero findings, no warning). Strip a recognized prefix and
 * apply it as real RegExp flags instead. Mirrors src/lib/dataComplianceRuleSchema.ts's
 * toJsRegExp in the main app; kept as a local duplicate rather than a cross-package
 * import since this Action is bundled standalone (ncc build, its own dependency tree).
 * Returns null (same as an unparseable pattern) for an unrecognized inline flag or a
 * prefix with nothing left to match, rather than silently compiling a degenerate regex.
 */
function resolvePattern(pattern: string, extraFlags: string): { source: string; flags: string } | null {
  const prefixMatch = pattern.match(PCRE_INLINE_FLAG_PREFIX);
  if (!prefixMatch) return { source: pattern, flags: extraFlags };
  const remainder = pattern.slice(prefixMatch[0].length);
  if (!remainder) return null;
  const prefixFlags = [...prefixMatch[1]];
  if (prefixFlags.some((f) => !JS_REGEX_FLAGS.has(f))) return null;
  return { source: remainder, flags: [...new Set([...prefixFlags, ...extraFlags])].join('') };
}

/** Compile a regex from a rule pattern; returns null if absent/invalid. */
function compile(pattern: string | undefined, flags = 'g'): RegExp | null {
  if (!pattern) return null;
  const resolved = resolvePattern(pattern, flags);
  if (!resolved) return null;
  try {
    return new RegExp(resolved.source, resolved.flags);
  } catch {
    return null;
  }
}

/**
 * A rule's `exclude_pattern` (suppressor) and `require_pattern` (precondition),
 * compiled ready to apply. Together they decide whether a candidate finding is
 * emitted at all.
 *
 * These exist because `require_context` cannot do this job: it is read only by
 * evaluateLinePattern (evaluateSignature and evaluatePaired ignore it,
 * evaluatePrDescription hardcodes context-present), and even there it only
 * downgrades a `block` — so on a `review` rule with no validators it is inert.
 * Rather than redefine that field in place (which would silently change
 * dc-pii-weak-checksum, the one rule where it does bite), these two are
 * additive and honoured in every evaluation path.
 */
interface GatingSpec {
  excludeRe: RegExp | null;
  requireRe: RegExp | null;
  /** Carried so a suppression can be attributed to a rule in the scan warnings. */
  ruleId: string;
}

/**
 * Compile a rule's gating patterns ONCE, before its per-line loop.
 *
 * Compiling inside the loop instead is correct but costly: at the Action's
 * default 5 MB diff cap a scan walks ~60k lines, so a per-line `new RegExp()`
 * pair costs ~120k compilations per rule. Measured on a 4.3 MB diff, the
 * per-line form took 4602 ms against 2437 ms for the pre-gating scanner — a
 * 1.9x regression on every large PR. Hoisting removes it.
 *
 * BOTH FIELDS FAIL OPEN, which is why `compile` returning null is not an error
 * here. An uncompilable pattern is treated as absent, so a typo in a suppressor
 * cannot silently mute a rule and a typo in a precondition cannot silently gate
 * one away. A rule that reports nothing with no warning reads as an all-clear,
 * which is worse than the noise this gating replaces.
 *
 * Every gating regex must be STATELESS, because hoisting shares one instance
 * across every line. Passing '' here is not sufficient on its own — see
 * stripStatefulFlags, which is what actually enforces it.
 */
/**
 * Rules whose gating fields this scan REFUSED to honour, because they are tier-1.
 * Reset by scan(); surfaced as a warning that also floors the verdict.
 */
const refusedTierOneGating = new Set<string>();

/** Rules whose before/after pair enumeration hit MAX_MINUS_PLUS_PAIRS. */
const truncatedPairRules = new Set<string>();

/**
 * Tier-1 rules do not get to be gated (SEC6).
 *
 * `exclude_pattern` is a suppressor and `require_pattern` is a precondition, so
 * either one can silence a rule completely — `exclude_pattern: "."` matches every
 * line, and a `require_pattern` that matches nothing has the same effect from the
 * other direction. On a tier-1 BLOCKING control that is not configuration, it is
 * a kill switch, and it would leave no trace beyond a green check.
 *
 * `DomainTemplateService.saveDataComplianceRule` already refuses any change to
 * these fields from the rule editor (GATING_NOT_EDITABLE), which closes the
 * authoring path an org admin actually has. This is the second line: the Action
 * refuses to honour such a gate no matter how it reached the ruleset — a hand-run
 * UPDATE, a future migration, a bug in the serving path. A control that can be
 * disabled by editing a row is not much of a control.
 *
 * It is inert against the shipped ruleset (only dc-select-star, tier 3, declares
 * a gating field), so this costs nothing today and exists for the day it would.
 */
function compileGating(rule: Rule): GatingSpec {
  if (rule.tier === 1 && (rule.detect.exclude_pattern || rule.detect.require_pattern)) {
    refusedTierOneGating.add(rule.id);
    return { excludeRe: null, requireRe: null, ruleId: rule.id };
  }
  return {
    excludeRe: stripStatefulFlags(compile(rule.detect.exclude_pattern, '')),
    requireRe: stripStatefulFlags(compile(rule.detect.require_pattern, '')),
    ruleId: rule.id,
  };
}

/**
 * How many candidate lines each rule's gating fields suppressed in the in-flight
 * scan, so `scan()` can say so in its warnings.
 *
 * WHY THIS EXISTS. `exclude_pattern` is a total suppressor: measured, setting it to
 * `.` on tier-1 blocking `dc-pii-iban` turns a `fail` into a `pass` with zero
 * findings AND ZERO WARNINGS — a silenced control that renders as a clean
 * all-clear, which is strictly worse than the noise this precision pass removed.
 *
 * Deliberately counts ACTUAL suppressions rather than warning on every rule that
 * merely declares a gating field. `dc-select-star` ships with one, so a
 * declaration-based warning would fire on every scan forever and train readers to
 * ignore warnings — the same failure as a gate that always says needs_review.
 */
const suppressionCounts = new Map<string, number>();

function noteSuppression(ruleId: string): void {
  suppressionCounts.set(ruleId, (suppressionCounts.get(ruleId) ?? 0) + 1);
}

/**
 * Remove `g` and `y` from a gating regex. NOT cosmetic — without this the
 * hoisted, reused instance is STATEFUL and silently scans half the diff.
 *
 * Passing '' as compile()'s extraFlags only controls the flags WE add. A rule
 * may declare its own via the PCRE-style inline prefix (`(?gi)…`), and
 * resolvePattern accepts `g` because it is a real JS flag — so `(?gi)ok` as an
 * exclude_pattern yields a global regex. `RegExp.test` on one advances
 * lastIndex, so across a diff the gate matches line 1, misses line 2, matches
 * line 3… Measured before this fix: an exclude_pattern that should suppress
 * all 4 of 4 identical lines suppressed 2, and a require_pattern that should
 * admit 4 admitted 2. Sticky (`y`) is stateful for the same reason.
 *
 * That is worse than a plain bug in a compliance control: on `require_pattern`
 * it drops real findings on alternate lines, silently and intermittently, and
 * the rule still looks like it is running. An org admin can reach it — the
 * rule editor's `isValidRegex` accepts `(?gi)` — so it is not merely
 * theoretical.
 *
 * Found by independent review; the author's own review asserted "no `g` flag"
 * from reading the call site and missed that the pattern can supply one.
 */
function stripStatefulFlags(re: RegExp | null): RegExp | null {
  if (!re) return null;
  if (!re.global && !re.sticky) return re;
  return new RegExp(re.source, re.flags.replace(/[gy]/g, ''));
}

/** Apply a pre-compiled gate to one piece of text. False = drop the finding. */
function passesGate(gate: GatingSpec, text: string): boolean {
  if (gate.excludeRe && gate.excludeRe.test(text)) {
    noteSuppression(gate.ruleId);
    return false;
  }
  if (gate.requireRe && !gate.requireRe.test(text)) {
    noteSuppression(gate.ruleId);
    return false;
  }
  return true;
}

/**
 * Apply a gate across the two halves of a minus/plus pair, testing each side
 * independently rather than a joined string.
 *
 * Joining with "\n" and testing once looks equivalent and is not: without the
 * `m` flag an anchored pattern like `^new` can only ever match the FIRST half,
 * so a gate anchored to the added line was unreachable. Per-side keeps the
 * intended meaning — an exclusion naming either half suppresses the pair, and
 * a precondition is satisfied by either half — while letting anchors work.
 */
function passesPairGate(gate: GatingSpec, minusText: string, plusText: string): boolean {
  if (gate.excludeRe && (gate.excludeRe.test(minusText) || gate.excludeRe.test(plusText))) {
    noteSuppression(gate.ruleId);
    return false;
  }
  if (gate.requireRe && !(gate.requireRe.test(minusText) || gate.requireRe.test(plusText))) {
    noteSuppression(gate.ruleId);
    return false;
  }
  return true;
}

/**
 * Names the pattern fields a rule declares that could not be compiled.
 *
 * A rule whose pattern does not compile contributes zero findings and, before
 * this, said nothing about it — an unrecognised inline flag such as `(?x)` was
 * enough to retire a rule in total silence, which renders as a clean pass. That
 * is the exact failure this whole change exists to avoid, so it is now surfaced
 * as a scan warning instead.
 */
/**
 * Clamp and de-fang an org-controlled rule id before it goes into a warning.
 *
 * Warnings are rendered into check-run markdown (`- ${w}` in checkRun.ts) and
 * `rule.id` is any non-empty string an org admin chooses, with no length bound —
 * unlike `masked_evidence`, which already passes through sanitizeLabel's clamp. A
 * `|` breaks the findings table; an unbounded id bloats the body.
 */
/**
 * Make a contributor-controlled FILE PATH safe to name in check-run markdown.
 *
 * `sanitizeRuleId` was reused for this at first and is not adequate: it strips
 * `|`, backticks and newlines, which stops table and list breakout, but leaves
 * `[ ] ( ) < >` intact. An independent review turned a path into a clickable
 * attacker-authored link rendered inside the official gate summary —
 * `src/[APPROVED - click to view report](https://evil.example/pwn).ts` — and an
 * `<img>` that survives GitHub's markdown sanitiser as an external fetch.
 * Reviewers trust that surface, so an allowlist is the right shape here: real
 * paths only need these characters, and anything else becomes `_`.
 */
function sanitizePathLabel(path: string): string {
  // Unicode letters and digits are KEPT: mapping them to `_` reduced
  // `src/café/x.ts` — and every CJK or Cyrillic path — to underscores, so the
  // warning named a file nobody could find. What must not survive is anything
  // markdown gives meaning to.
  const cleaned = path.replace(/[^\p{L}\p{N}._/@+-]/gu, '_');
  const clamped = cleaned.length > 120 ? `${cleaned.slice(0, 120)}…` : cleaned;
  // Wrapped in a code span, which is what makes the surviving `@` and any
  // `www.`-prefixed host inert: GFM autolinks a bare `www.host/x` and turns
  // `@name` into a real mention that pings a real user from the gate summary.
  // `@` is kept because npm scopes are legitimate path segments; the code span
  // is what defuses it. Backticks cannot survive the allowlist above, so the
  // span cannot be broken out of.
  return `\`${clamped}\``;
}

function sanitizeRuleId(id: string): string {
  // ALLOWLIST, matching sanitizePathLabel. This was a four-character denylist
  // (`|`, backtick, CR, LF) while the path sanitiser right above it was moved to
  // an allowlist for precisely the reason a denylist is inadequate — it leaves
  // `[ ] ( ) < >` intact, which is what let a review render an attacker-authored
  // link inside the gate summary. Rule ids are org-controlled and reach five
  // different warnings, so the same reasoning applies to them.
  const cleaned = id.replace(/[^A-Za-z0-9._:/@+-]/g, '_');
  return cleaned.length > 120 ? `${cleaned.slice(0, 120)}…` : cleaned;
}

/**
 * Every regex-bearing field on a rule that the Action would DROP — i.e. `compile`
 * returns null, so the field is silently inert and, for `pattern`, the whole rule
 * is dead. Exported so tests can assert against the Action's REAL acceptance rule
 * instead of reimplementing it: a guard that merely strips `^\(\?[a-z]+\)` and
 * compiles the remainder accepts `(?x)foo` and a flag-only `(?i)`, both of which
 * `resolvePattern` rejects outright (CR10). It also covers `require_context`, which
 * such a guard forgets.
 */
export function unusablePatternFields(rule: Rule): string[] {
  const declared: Array<[string, string | undefined]> = [
    ['pattern', rule.detect.pattern],
    ['exclude_pattern', rule.detect.exclude_pattern],
    ['require_pattern', rule.detect.require_pattern],
    ['require_context', rule.detect.require_context],
    ['paired.minus', rule.detect.paired?.minus],
    ['paired.plus', rule.detect.paired?.plus],
  ];
  return declared
    .filter(([, value]) => typeof value === 'string' && value.length > 0 && compile(value) === null)
    .map(([field]) => field);
}

/** A line is in scope if it matches any file_scope glob (or scope is empty). */
function matchesFileScope(file: string, fileScope: string[] | undefined): boolean {
  if (!fileScope || fileScope.length === 0) return true;
  return fileScope.some((glob) => globToRegExp(glob).test(file));
}

/** A line is excluded if any rule exclude path OR any always-exclude matches. */
function isExcluded(file: string, excludePaths: string[] | undefined): boolean {
  if (ALWAYS_EXCLUDE.some((re) => re.test(file))) return true;
  if (excludePaths && excludePaths.some((glob) => globToRegExp(glob).test(file))) {
    return true;
  }
  return false;
}

/**
 * Default wall-clock budget for one scan.
 *
 * WHY A BUDGET AND NOT ONLY A LENGTH CAP. Catastrophic backtracking is a property
 * of a pattern's STRUCTURE, not its size: `(a+)+$` is six characters and took
 * ~150 s on a 32-character line when measured. A length cap therefore cannot
 * prevent it — and `pattern` is a legitimately editable field in the rule editor,
 * so an org admin reaches this through a supported form, with no console call.
 *
 * HONEST LIMIT, stated because it matters: JavaScript cannot interrupt a regex
 * mid-match. The engine blocks the event loop, which is why an external
 * `timeout 60` was measured failing to kill it. This budget bounds how much MORE
 * work happens once the deadline passes; it cannot cut short a single pathological
 * match already running. It turns "19 rules each overrunning" into "one rule
 * overruns, then stop", and it bounds the polynomial shape (many lines, each
 * individually cheap) tightly — which is the shape a repo CONTRIBUTOR can trigger
 * with one long crafted line, as opposed to the exponential shape, which needs an
 * org admin to author the pattern. A hard kill needs a worker or subprocess.
 */
const BUDGET_MS = 20_000;

/**
 * Deadline for the in-flight scan, set on every entry to `scan()`.
 *
 * Module state rather than a threaded parameter: `scan()` is synchronous and
 * single-threaded, so there is exactly one scan in flight, and threading a budget
 * through all four evaluation paths and their inner loops would touch far more code
 * than the check itself. Same trade-off `GLOB_CACHE` below already makes. Both
 * values are reset on entry, so nothing leaks between calls.
 */
let scanDeadline = Number.POSITIVE_INFINITY;
let budgetExceeded = false;

/** True once the in-flight scan has run out of budget. */
function outOfBudget(): boolean {
  if (budgetExceeded) return true;
  // `>=`, not `>`: a budgetMs of 0 must mean "no time at all", and with `>` the
  // deadline equals Date.now() so nothing triggers within the same millisecond.
  if (Date.now() >= scanDeadline) budgetExceeded = true;
  return budgetExceeded;
}

/**
 * Minimal glob -> RegExp (supports `*`, `**`, `?`). Matches as a SUBSTRING of the
 * path unless anchored: a leading `^` pins to the start of the path and a
 * trailing `$` to the end. `^` / `$` elsewhere in the glob stay literal, as they
 * always were — before anchors existed both characters were escaped everywhere,
 * and no real path glob contains one, so this extension is backward compatible.
 *
 * The anchors are not cosmetic. Substring matching alone cannot express a path
 * segment, which shipped two live defects (SEC4): `docs/` in an `exclude_paths`
 * also suppressed `sdkdocs/` and `packages/mydocs/`, and `.md` also suppressed
 * `.mdx`, `.mdb` and `latest.md.ts` — real code files, silently unscanned by a
 * tier-1 rule. `^docs/` and `.md$` say what was meant. Conversely a leading-slash
 * glob like `/fixtures/` cannot match a REPO-ROOT `fixtures/…`, because diff paths
 * carry no leading slash; write `^fixtures/` alongside it to cover both.
 *
 * There is no escape mechanism, and none is planned: a glob of `\\$` peels the
 * `$` as an anchor and escapes the backslash, so it silently means "path ends
 * with a backslash". No real path glob needs a literal `^` or `$`.
 *
 * MEMOISED, and that is load-bearing rather than a micro-optimisation.
 * `matchesFileScope`/`isExcluded` call this once per glob PER DIFF LINE, so at
 * the Action's 5 MB cap (~60k lines) a ruleset where 7 rules each carry ~6
 * `exclude_paths` entries costs ~2.5M `new RegExp()` calls in a single scan.
 * Measured on a 4.3 MB diff that was the difference between 2.3 s and 4.9 s;
 * the tier-2 precision pass is what made this path hot by giving most rules an
 * exclusion list for the first time.
 *
 * The cache is keyed by the glob string and is bounded in practice by the
 * number of distinct globs the served ruleset declares (a few dozen). No `g`
 * flag, so a shared instance carries no `lastIndex` state between calls and is
 * safe to reuse across lines.
 */
/**
 * Longest single diff line any rule regex is run over (SEC7).
 *
 * WHY A PER-LINE CAP AND NOT ONLY THE WALL-CLOCK BUDGET. The shipped PII patterns
 * are quadratic in LINE LENGTH, not in line count: `[A-Za-z0-9._%+-]+@` has to
 * retry from every offset of a long in-class run before it can fail, and
 * `(//|#).*(…@…)` backtracks `.*` across the whole line for each of them.
 * Measured on 20 lines of in-class characters with no `@`, both dc-pii-bare and
 * dc-pii-in-comments came out at a clean x4.0 per doubling:
 *
 *      500 chars    12 ms        4000 chars    550 ms
 *     1000 chars    35 ms        8000 chars   2209 ms
 *     2000 chars   137 ms
 *
 * `BUDGET_MS` cannot rescue this, and that is the whole point: JavaScript cannot
 * interrupt a regex mid-match, so a budget checked BETWEEN lines is powerless
 * inside one. This is not theoretical — THIS repository checks in 1.8 MB
 * single-line HTML files (`public/preview-app.html`, `claude-design/*.html`,
 * `src/marketing-landing-page/*.html`) that ALWAYS_EXCLUDE does not cover.
 * Extrapolating the curve above, one such line costs ~94 MINUTES for ONE rule,
 * uninterruptible. A PR touching one of those files would hang the gate until
 * the job timeout killed it.
 *
 * 8192 was chosen by measuring the repo rather than guessing: of 382,247
 * scannable lines (after ALWAYS_EXCLUDE), just 73 — 0.019% — are longer, and
 * they are all generated bundles. The cap costs essentially nothing on real
 * source and removes the entire pathological tail.
 *
 * The remainder of an oversized line is NOT silently dropped: the prefix is
 * still scanned, the file is recorded, and the scan is marked incomplete so the
 * verdict floors to needs_review. Not scanning something must never read as a
 * clean pass — the same rule the truncated-diff and budget paths already follow.
 */
const MAX_SCAN_LINE_CHARS = 8192;

/**
 * Characters scanned between wall-clock budget checks.
 *
 * The line-count sample below (every 256 lines) assumes lines are short. On a run
 * of long lines it lets the scan overshoot the budget by 256 x the per-line cost —
 * at 8 KB lines that is ~28 s past a 20 s budget. Sampling by WORK as well bounds
 * the overshoot to roughly one 64 KB block whatever the line lengths are.
 */
const BUDGET_SAMPLE_CHARS = 65_536;

/** Files that had at least one line over the cap, for this scan. Reset by scan(). */
const oversizedLineFiles = new Set<string>();

/**
 * Whether the PR description itself was clamped this scan.
 *
 * Tracked separately rather than as a pseudo-entry in `oversizedLineFiles`: it
 * is not a file, and folding it in produced the nonsense warning "1 file(s)
 * contain lines longer than 8192 characters (PR_description)".
 */
let oversizedPrDescription = false;

/**
 * The text a rule is actually run against: the line, clamped to
 * MAX_SCAN_LINE_CHARS. Records the file when it clamps so scan() can warn and
 * floor the verdict.
 */
function scannableText(line: { file: string; text: string }): string {
  if (line.text.length <= MAX_SCAN_LINE_CHARS) return line.text;
  oversizedLineFiles.add(line.file);
  return line.text.slice(0, MAX_SCAN_LINE_CHARS);
}

/**
 * A compiled glob plus WHY it was refused, if it was.
 *
 * The refusal has to live in the cache entry, not only in the per-scan set. The
 * first version recorded the refusal on the code path that BUILDS the entry, so
 * on the second scan in the same process the cache hit returned early and the
 * warning was never re-recorded — the verdict flipped from needs_review to pass
 * purely because the cache was warm. Measured: same ruleset, same process, two
 * consecutive scans, different verdicts.
 */
interface CachedGlob {
  re: RegExp;
  refusal: 'complex' | 'blanket' | null;
}

const GLOB_CACHE = new Map<string, CachedGlob>();

/** Matches nothing, for a glob whose payload is empty (e.g. a bare "^"). */
const NEVER = /(?!)/;

/**
 * Most wildcards one glob may contain.
 *
 * `*` compiles to `[^/]*`, so `*a*a*a…X` becomes a chain of greedy quantifiers
 * that backtracks catastrophically against a path that never completes the
 * match. Measured on a 67-character path: a 13-character glob with 6 stars took
 * 6714 ms, and 8 stars ran past 120 s without finishing. `MAX_SCAN_LINE_CHARS`
 * does nothing here — this runs on the PATH, not the line — and the wall-clock
 * budget cannot interrupt a single `test()`.
 *
 * Real globs are far below this: the widest list any shipped rule declares uses
 * zero wildcards, and 4 is already generous for something like `a/**\/b/*.ts`.
 */
const MAX_GLOB_WILDCARDS = 4;

/** Globs this scan refused to compile as too complex. Reset by scan(). */
const refusedComplexGlobs = new Set<string>();

/**
 * Globs this scan refused because they match every path. Reset by scan().
 *
 * Tracked and WARNED ABOUT, which the first version did not do — and the comment
 * justifying that said `file_scope` was harmless here because it is an inclusion
 * list. That was exactly backwards: refusing a `file_scope` glob turns the field
 * from "scan everything" into "scan NOTHING", so a tier-1 block rule with
 * `file_scope: ["*"]` reported a clean green pass with no finding and no trace —
 * the same kill switch the guard was written to close, moved one field over.
 */
const refusedBlanketGlobs = new Set<string>();

/** Re-record a cached refusal, so a warm cache cannot swallow the warning. */
function noteGlobRefusal(glob: string, refusal: CachedGlob['refusal']): void {
  if (refusal === 'complex') refusedComplexGlobs.add(glob);
  else if (refusal === 'blanket') refusedBlanketGlobs.add(glob);
}

function globToRegExp(glob: string): RegExp {
  const cached = GLOB_CACHE.get(glob);
  if (cached) {
    noteGlobRefusal(glob, cached.refusal);
    return cached.re;
  }

  const remember = (re: RegExp, refusal: CachedGlob['refusal']): RegExp => {
    GLOB_CACHE.set(glob, { re, refusal });
    noteGlobRefusal(glob, refusal);
    return re;
  };

  // Peel the anchors BEFORE escaping — the escape below would otherwise turn
  // them into the literal characters they used to be.
  const anchorStart = glob.startsWith('^');
  const anchorEnd = glob.endsWith('$');
  const body = glob.slice(anchorStart ? 1 : 0, anchorEnd ? glob.length - 1 : undefined);

  // Refuse a glob with more wildcards than any real path pattern needs, BEFORE
  // compiling it — see MAX_GLOB_WILDCARDS. Recorded rather than silent, because
  // refusing changes behaviour in opposite directions for the two fields that
  // use globs (a dropped `exclude_paths` entry reports more, a dropped
  // `file_scope` entry reports less), so the operator has to be told either way.
  // `**` is ONE logical wildcard, not two. Counting characters refused ordinary
  // globs: `**/**/*.ts` is three wildcards but five characters, and so was
  // rejected — which for a `file_scope` silently disabled the rule (see
  // refusedBlanketGlobs).
  const wildcards = (body.replace(/\*\*/g, '*').match(/[*?]/g) ?? []).length;
  if (wildcards > MAX_GLOB_WILDCARDS) {
    return remember(NEVER, 'complex');
  }

  // A glob with no payload at all ("^", "$", "^$") would compile to /^/ or /$/.
  const compiled = body.length === 0
    ? NEVER
    : new RegExp(
        (anchorStart ? '^' : '') +
          body
            .replace(/[.+^${}()|[\]\\]/g, '\\$&')
            .replace(/\*\*/g, '\u0000') // placeholder for **
            .replace(/\*/g, '[^/]*')
            .replaceAll('\u0000', '.*')
            .replace(/\?/g, '.') +
          (anchorEnd ? '$' : ''),
      );

  // FAIL CLOSED ON ANY MATCH-EVERYTHING GLOB, not just an empty one.
  //
  // The first version of this guard tested `body.length === 0`, which is the
  // wrong thing to test — it is the COMPILED regex that decides what matches,
  // not the source text. An independent security review found nine more
  // spellings that all match every path and so disable a rule outright:
  //   *   **   ?   ***   ^*   *$   **$   ^**$   ^?
  // Four of them (^*, *$, **$, ^**$) became expressible only because this
  // function learned anchors, so the anchoring change widened the very hole the
  // guard was added to close.
  //
  // `exclude_paths` is a SUPPRESSOR, so a glob that matches everything turns a
  // tier-1 blocking control into a clean green pass — no finding, no warning,
  // which is the worst output this component can produce. Testing the compiled
  // regex against the empty string catches every spelling at once, now and in
  // future, rather than blocklisting the nine that are known today.
  //
  // `file_scope` is an inclusion list where match-everything is harmless ("scan
  // everything"), but refusing it there too costs nothing real and keeps this to
  // one rule instead of two: a glob that cannot discriminate is a mistake in
  // either field, and an EMPTY `file_scope` is already how you say "everything"
  // deliberately (see matchesFileScope).
  // Two independent ways a glob fails to discriminate, and BOTH are needed.
  //
  //  - matches the empty string: `^`, `$`, `^$`, `*`, `**`, `*$`, `^*`, `^**$`.
  //  - has no literal character at all: `?` and `^?` compile to `.`, which does
  //    NOT match '' and so slips past the first test, yet matches every real
  //    (non-empty) path just the same. Caught by asking whether the glob
  //    contains anything besides wildcards and separators.
  //
  // The first cut of this guard used only the empty-string test and let `?`
  // through — still a silent kill switch on a tier-1 rule, just a narrower one.
  const discriminates = /[^*?/]/.test(body);
  if (!discriminates || compiled.test('')) {
    return remember(NEVER, 'blanket');
  }

  return remember(compiled, null);
}

/**
 * Is the matched value an allowlisted synthetic / known-safe value?
 *
 * When a rule sets `allowlist: "synthetic"`, we suppress the finding entirely
 * if the value matches the ruleset's global allowlist (emails / domains /
 * ibans / names) or looks like a canonical test value (example.com,
 * test@example.com, RFC-reserved ranges, etc.).
 */
function isAllowlisted(value: string, allowlist: AllowlistSpec | undefined): boolean {
  const v = value.trim();
  const lower = v.toLowerCase();

  // Canonical synthetic / reserved values.
  const SYNTHETIC = [
    /@example\.(com|org|net)$/i,
    /(^|@)example\.(com|org|net)$/i,
    /^test@/i,
    /@test\./i,
    /\bexample\.(com|org|net)\b/i,
    /\blocalhost\b/i,
  ];
  if (SYNTHETIC.some((re) => re.test(lower))) return true;

  if (!allowlist) return false;

  const inList = (list: string[] | undefined) =>
    Array.isArray(list) && list.some((entry) => entry.toLowerCase() === lower);

  if (inList(allowlist.emails)) return true;
  if (inList(allowlist.names)) return true;

  // IBANs compare on a GROUPING-INSENSITIVE form, and that asymmetry with the lists
  // above is the point rather than an inconsistency.
  //
  // The validator already strips whitespace and hyphens (isValidIban normalises
  // before calling ibantools), so an IBAN written in groups of four validates as a real
  // IBAN. The allowlist did an exact lowercase string compare, so the SAME value in
  // its canonical grouped presentation did NOT match the unspaced entry sitting in
  // the list — and a documented example IBAN blocked a PR. Verified against the
  // shipped STATIC_ALLOWLIST: the unspaced forms of both seeded entries produced 0
  // findings while their grouped forms produced 1 each.
  //
  // Latent until now, and made reachable by the SEC8 sub-candidate search in the
  // same release: before it, a grouped IBAN inside prose was never offered to the
  // validator at all, so it could not reach the allowlist check either. Emails,
  // names and domains keep the exact compare — whitespace is not a presentation
  // detail in those.
  const groupingInsensitive = (value: string) => value.replace(/[\s-]/g, '').toLowerCase();
  if (
    Array.isArray(allowlist.ibans) &&
    allowlist.ibans.some((entry) => groupingInsensitive(entry) === groupingInsensitive(v))
  ) {
    return true;
  }

  // Cards get the same grouping-insensitive compare as IBANs, and for the same
  // reason: a card is written in groups of four, the validator strips the spaces
  // before Luhn, so an exact compare would miss the canonical presentation. (No
  // example inline — the gate blocks its own source for carrying one.)
  if (
    Array.isArray(allowlist.cards) &&
    allowlist.cards.some((entry) => groupingInsensitive(entry) === groupingInsensitive(v))
  ) {
    return true;
  }

  if (Array.isArray(allowlist.domains)) {
    const at = lower.lastIndexOf('@');
    const domain = at >= 0 ? lower.slice(at + 1) : lower;
    if (allowlist.domains.some((d) => d.toLowerCase() === domain)) return true;
  }

  return false;
}

/** Lines to scan for a given target/side. */
function targetLines(
  rule: Rule,
  parsed: ParsedDiff,
): DiffLine[] {
  const side = rule.detect.diff_side ?? 'either';
  if (side === 'added') return addedLines(parsed);
  if (side === 'removed') return removedLines(parsed);
  return [...addedLines(parsed), ...removedLines(parsed)];
}

/** Build a masked evidence token for a value found on a diff line. */
function maskLineEvidence(rule: Rule, value: string, line: DiffLine): string {
  // Email findings get an extra masked email preview prepended to the label
  // so reviewers get a hint, while still never leaking the address.
  const isEmailish = value.includes('@') && /\./.test(value);
  const label = isEmailish ? `${rule.detect.mask} (${maskEmail(value)})` : rule.detect.mask;
  return maskFinding(label, value, line.file, line.lineNo);
}

/**
 * Evaluate a single rule against the parsed diff + PR description.
 * Returns zero or more raw (pre-aggregation) findings.
 */
function evaluateRule(
  rule: Rule,
  parsed: ParsedDiff,
  prDescription: string,
  allowlist: AllowlistSpec | undefined,
  signatures: Ruleset['signatures'],
): RawFinding[] {
  const { detect } = rule;

  // ---- PR description target -------------------------------------------------
  if (detect.target === 'pr_description') {
    return evaluatePrDescription(rule, prDescription, allowlist);
  }

  // ---- signature method (e.g. telemetry SDK imports in package.json) ---------
  if (detect.method === 'signature') {
    return evaluateSignature(rule, parsed, signatures);
  }

  // ---- paired (minus/plus) detection ----------------------------------------
  if (detect.paired) {
    return evaluatePaired(rule, parsed, allowlist);
  }

  // ---- single-line pattern / checksum ---------------------------------------
  return evaluateLinePattern(rule, parsed, allowlist);
}

/** Pattern match against the PR description text. */
function evaluatePrDescription(
  rule: Rule,
  prDescription: string,
  allowlist: AllowlistSpec | undefined,
): RawFinding[] {
  const re = compile(rule.detect.pattern);
  if (!re || !prDescription) return [];

  // Clamped exactly like a diff line (SEC7). The PR body is fully
  // contributor-controlled and runs to GitHub's 64 KB cap, and the same
  // quadratic-in-length curve applies here — measured at 8 ms / 27 ms / 109 ms /
  // 434 ms / 1745 ms for 2 KB / 4 KB / 8 KB / 16 KB / 32 KB. The first cut of
  // SEC7 clamped two of the four evaluators and left this one, so the stated
  // invariant ("bound scan cost by input length") did not actually hold.
  let body = prDescription;
  if (body.length > MAX_SCAN_LINE_CHARS) {
    oversizedPrDescription = true;
    body = body.slice(0, MAX_SCAN_LINE_CHARS);
  }

  // The PR description is one unit, so its gate is evaluated once against the
  // whole body rather than per match: an exclude_pattern anywhere in the
  // description suppresses this rule for the description entirely.
  if (!passesGate(compileGating(rule), body)) return [];

  const findings: RawFinding[] = [];
  let m: RegExpExecArray | null;
  re.lastIndex = 0;
  while ((m = re.exec(body)) !== null) {
    const value = m[0];
    if (re.lastIndex === m.index) re.lastIndex++; // avoid zero-width loop
    if (rule.detect.allowlist === 'synthetic' && isAllowlisted(value, allowlist)) {
      continue;
    }
    const { outcome: validatorHit, matched } = applyValidators(rule, value);
    if (validatorHit === 'rejected') continue;
    // Judge the allowlist against what actually validated, not the whole match.
    if (rule.detect.allowlist === 'synthetic' && matched && isAllowlisted(matched, allowlist)) {
      continue;
    }

    findings.push({
      rule,
      effectiveAction: gradeAction(rule, value, body, validatorHit, true),
      maskedEvidence: maskFinding(rule.detect.mask, value, 'PR description', null),
    });
  }
  return findings;
}

/** Detect a signature value (exact substring) within in-scope lines. */
function evaluateSignature(
  rule: Rule,
  parsed: ParsedDiff,
  signatures: Ruleset['signatures'],
): RawFinding[] {
  // A signature rule names either an explicit `signature` group key or carries
  // the list inline via pattern. We resolve the list from `signatures` keyed by
  // the rule's `signature` field; fall back to treating `signature` as a single
  // literal token.
  const key = rule.detect.signature;
  let tokens: string[] = [];
  if (key && signatures && Array.isArray(signatures[key])) {
    tokens = signatures[key];
  } else if (key) {
    tokens = [key];
  }
  if (tokens.length === 0) return [];

  const findings: RawFinding[] = [];
  const lines = targetLines(rule, parsed);
  const gate = compileGating(rule);
  let sinceBudgetCheck = 0;
  for (let i = 0; i < lines.length; i++) {
    // Sampled, not every iteration: Date.now() per line would be ~1.1M calls on a
    // 60k-line diff across 19 rules. Sampled by WORK as well as by line count, so
    // a run of very long lines cannot overshoot the budget by 256x their cost.
    if ((i & 0xff) === 0 || sinceBudgetCheck >= BUDGET_SAMPLE_CHARS) {
      sinceBudgetCheck = 0;
      if (outOfBudget()) break;
    }
    sinceBudgetCheck += lines[i].text.length;
    const line = lines[i];
    if (!matchesFileScope(line.file, rule.detect.file_scope)) continue;
    if (isExcluded(line.file, rule.detect.exclude_paths)) continue;
    const text = scannableText(line);
    if (!passesGate(gate, text)) continue;
    for (const token of tokens) {
      if (token && text.includes(token)) {
        findings.push({
          rule,
          effectiveAction: rule.action,
          maskedEvidence: maskFinding(`${rule.detect.mask}:${sigLabel(token)}`, token, line.file, line.lineNo),
        });
        break; // one finding per line is enough
      }
    }
  }
  return findings;
}

/** A short, masked-safe label for a signature token (e.g. an npm pkg name). */
function sigLabel(token: string): string {
  // Signature tokens are SDK/package identifiers, not PII — safe to surface,
  // but clamp length defensively.
  return token.length > 60 ? `${token.slice(0, 60)}…` : token;
}

/**
 * Paired minus/plus detection. Same-hunk pair = block-grade; a cross-hunk
 * (same_file) pair is downgraded to review.
 */
function evaluatePaired(
  rule: Rule,
  parsed: ParsedDiff,
  allowlist: AllowlistSpec | undefined,
): RawFinding[] {
  const paired = rule.detect.paired!;
  const minusRe = compile(paired.minus);
  const plusRe = compile(paired.plus);
  if (!minusRe || !plusRe) return [];

  const window = paired.window;
  const { pairs, truncated } = minusPlusPairs(parsed, window);
  if (truncated) {
    // Enumeration was cut short, so this rule did not see the whole diff.
    truncatedPairRules.add(rule.id);
  }
  const findings: RawFinding[] = [];
  const seen = new Set<string>();
  const gate = compileGating(rule);

  // Compiled once, not per pair (see the allowlist branch below).
  const minusValueRe = compile(paired.minus)!;

  let sinceBudgetCheck = 0;
  for (let pi = 0; pi < pairs.length; pi++) {
    const pair = pairs[pi];
    // This evaluator had NO budget check at all — the only one of the four
    // without one, which is why a quadratic pair set could run for minutes and
    // still report `pass`. Same sampling as the other loops: by line count and
    // by work, so long lines cannot stretch the interval between checks.
    if ((pi & 0xff) === 0 || sinceBudgetCheck >= BUDGET_SAMPLE_CHARS) {
      sinceBudgetCheck = 0;
      if (outOfBudget()) break;
    }
    sinceBudgetCheck += pair.minus.text.length + pair.plus.text.length;
    if (!matchesFileScope(pair.minus.file, rule.detect.file_scope)) continue;
    if (isExcluded(pair.minus.file, rule.detect.exclude_paths)) continue;

    // CLAMPED, like the other three evaluators. SEC7 bounded evaluateSignature,
    // evaluateLinePattern and evaluatePrDescription and left this one running
    // regexes over raw line text — so the invariant it claimed ("bound scan cost
    // by input length") did not hold where it mattered most. Measured on a
    // single 300,000-character removed line with the shipped email pattern as
    // `paired.minus`: 153 SECONDS, verdict `pass`, zero warnings. That is six
    // times SMALLER than the 1.8 MB single-line files this repo checks in, and
    // because `scannableText` is what populates `oversizedLineFiles`, the
    // needs_review floor never fired either.
    const minusText = scannableText(pair.minus);
    const plusText = scannableText(pair.plus);

    minusRe.lastIndex = 0;
    plusRe.lastIndex = 0;
    if (!minusRe.test(minusText) || !plusRe.test(plusText)) continue;

    // Each half is tested independently — see passesPairGate for why joining
    // them would make an anchored gate unable to see the added line.
    if (!passesPairGate(gate, minusText, plusText)) continue;

    // Optional allowlist on the removed value (e.g. synthetic secret).
    if (rule.detect.allowlist === 'synthetic') {
      // Hoisted: this used to call compile() INSIDE the loop, the exact
      // per-iteration cost compileGating's docstring says was lifted out.
      minusValueRe.lastIndex = 0;
      const mm = minusValueRe.exec(minusText);
      const matched = mm ? mm[0] : minusText;
      if (isAllowlisted(matched, allowlist)) continue;
    }

    // Same-hunk → keep rule.action (block); cross-hunk → downgrade to review.
    const effectiveAction: 'block' | 'review' | 'advise' = pair.sameHunk
      ? rule.action
      : downgrade(rule.action);

    const key = `${pair.minus.file}:${pair.minus.lineNo}->${pair.plus.lineNo}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const suffix = pair.sameHunk ? 'same-hunk' : 'cross-hunk';
    findings.push({
      rule,
      effectiveAction,
      maskedEvidence: maskFinding(
        `${rule.detect.mask} (${suffix})`,
        pair.minus.text,
        pair.plus.file,
        pair.plus.lineNo,
      ),
    });
  }
  return findings;
}

/** Single-line pattern (optionally checksum-validated, optionally context-gated). */
/**
 * Default candidate extractor for checksum rules that declare validators but no
 * explicit `pattern`: alphanumeric runs (optionally space/hyphen grouped, as in
 * "GB82 WEST …" or "4111 1111 …"). The validators then accept/reject each token,
 * so over-capture is harmless. Without this, a `validator`-only rule would never
 * find a candidate to validate.
 */
const CHECKSUM_CANDIDATE_RE = '[A-Za-z0-9][A-Za-z0-9 \\-]{7,}[A-Za-z0-9]';

function evaluateLinePattern(
  rule: Rule,
  parsed: ParsedDiff,
  allowlist: AllowlistSpec | undefined,
): RawFinding[] {
  const hasValidators = Array.isArray(rule.detect.validator) && rule.detect.validator.length > 0;
  const re = compile(rule.detect.pattern) ?? (hasValidators ? compile(CHECKSUM_CANDIDATE_RE) : null);
  if (!re) return [];

  const findings: RawFinding[] = [];
  const lines = targetLines(rule, parsed);
  const contextRe = compile(rule.detect.require_context, 'i');
  const gate = compileGating(rule);

  let sinceBudgetCheck = 0;
  for (let i = 0; i < lines.length; i++) {
    // Sampled, not every iteration: Date.now() per line would be ~1.1M calls on a
    // 60k-line diff across 19 rules. Sampled by WORK as well as by line count, so
    // a run of very long lines cannot overshoot the budget by 256x their cost.
    if ((i & 0xff) === 0 || sinceBudgetCheck >= BUDGET_SAMPLE_CHARS) {
      sinceBudgetCheck = 0;
      if (outOfBudget()) break;
    }
    sinceBudgetCheck += lines[i].text.length;
    const line = lines[i];
    if (!matchesFileScope(line.file, rule.detect.file_scope)) continue;
    if (isExcluded(line.file, rule.detect.exclude_paths)) continue;
    const text = scannableText(line);
    if (!passesGate(gate, text)) continue;

    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const value = m[0];
      if (re.lastIndex === m.index) re.lastIndex++;

      if (rule.detect.allowlist === 'synthetic' && isAllowlisted(value, allowlist)) {
        continue;
      }

      const { outcome: validatorHit, matched } = applyValidators(rule, value);
      if (validatorHit === 'rejected') continue;
      // Judge the allowlist against what actually validated, not the whole match.
      if (rule.detect.allowlist === 'synthetic' && matched && isAllowlisted(matched, allowlist)) {
        continue;
      }

      // require_context: present near the match (same line) to count as block.
      const contextPresent = contextRe ? contextRe.test(text) : true;

      const effectiveAction = gradeAction(
        rule,
        value,
        text,
        validatorHit,
        contextPresent,
      );

      findings.push({
        rule,
        effectiveAction,
        maskedEvidence: maskLineEvidence(rule, value, line),
      });
    }
  }
  return findings;
}

type ValidatorOutcome = 'none' | 'passed' | 'rejected';

/**
 * Apply checksum validators when the rule declares them.
 *  - 'none'     → no validators on this rule
 *  - 'passed'   → at least one validator confirmed the value
 *  - 'rejected' → validators declared but none passed (drop the match)
 */
/**
 * Shortest and longest identifier any validator can accept, measured on the
 * whitespace/punctuation-stripped value: SVNR is 10 digits, an IBAN is at most 34
 * characters. Used to skip a sub-candidate before paying for a validator call.
 */
const CHECKSUM_MIN_LEN = 10;
const CHECKSUM_MAX_LEN = 34;

/**
 * Most space-separated groups a real identifier is written in: an IBAN grouped in
 * fours reaches 9. Bounds the contiguous-run search to O(tokens x 9).
 */
const CHECKSUM_MAX_GROUPS = 9;

/**
 * Candidate substrings to offer the checksum validators, in the order tried.
 *
 * SEC8. `CHECKSUM_CANDIDATE_RE` includes the space character and is greedy, so on a
 * prose line the match is the whole phrase. The validators strip whitespace
 * internally, so "Wire to DE89… for the payout" normalises to
 * "WIRETODE89…FORTHEPAYOUT" and correctly fails mod-97 — and nothing ever offered
 * the bare IBAN inside it. A bare identifier on its own line was caught; the same
 * identifier in a sentence was not. That gap matters more since the precision pass,
 * because `.md` and `docs/` are now excluded from the tier-2 prose rules, leaving
 * these tier-1 checksum rules as the last line of defence on exactly the paths
 * where identifiers turn up inside sentences.
 *
 * The whole value is still tried FIRST and unchanged, because that is what makes a
 * space-grouped identifier work (an IBAN written in groups of four). Only if it fails
 * do we look inside — single tokens, then contiguous RUNS of tokens, which is the
 * case where a grouped identifier sits inside prose and neither the whole phrase
 * nor any single token validates.
 *
 * Bounded deliberately: runs are capped at CHECKSUM_MAX_GROUPS and every candidate
 * is length-filtered before a validator is called, so a long prose line does not
 * turn into a quadratic pile of mod-97 checks.
 */
/** Digits in a string — cheap pre-filter before paying for a checksum validator. */
function countDigits(value: string): number {
  let n = 0;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 48 && c <= 57) n++;
  }
  return n;
}

function* checksumCandidates(value: string): Generator<string> {
  yield value;
  // Cheapest exit first: if the WHOLE value carries fewer than two digits, no
  // substring of it can either, so there is nothing to look inside for. This is
  // what keeps prose-heavy diffs cheap — without it we still split and build runs
  // on every digit-free line, which measured 725 ms on a 1000-line prose diff
  // against a 77 ms baseline. With it, ~90 ms.
  if (countDigits(value) < 2) return;
  const tokens = value.split(/\s+/).filter(Boolean);
  if (tokens.length < 2) return;

  const seen = new Set<string>([value]);
  for (let start = 0; start < tokens.length; start++) {
    let run = '';
    for (let n = 0; n < CHECKSUM_MAX_GROUPS && start + n < tokens.length; n++) {
      run = n === 0 ? tokens[start] : `${run} ${tokens[start + n]}`;
      const stripped = run.replace(/[\s-]/g, '');
      if (stripped.length > CHECKSUM_MAX_LEN) break; // longer runs only get longer
      if (stripped.length < CHECKSUM_MIN_LEN) continue;
      // Digit pre-filter, and it is load-bearing for performance rather than
      // correctness. EVERY validator needs digits: an IBAN's two check characters
      // are always numeric, and SVNR/Steuer-ID/card are all-digit. Without this,
      // ordinary prose generates a run for nearly every 2-4 word window and pays
      // for a mod-97 call on each — measured at 1415 ms on a 1000-line prose diff
      // versus 77 ms before the sub-candidate search existed. With it, digit-free
      // prose costs nothing and the same diff is back to ~90 ms.
      if (countDigits(stripped) < 2) continue;
      if (seen.has(run)) continue;
      seen.add(run);
      yield run;
    }
  }
}

/**
 * Validate `value`, reporting WHICH candidate substring actually passed.
 *
 * The matched candidate matters to the caller, not just the yes/no: the allowlist
 * must be judged against the identifier that was really found, not against the
 * whole greedy match. "Wire GB82 WEST … today" is not in anyone's allowlist, but the
 * grouped IBAN inside it may well be — and before this, a checksum rule with
 * `allowlist: 'synthetic'` would report a finding on an explicitly allowlisted
 * value the moment it appeared inside a sentence.
 */
function applyValidators(rule: Rule, value: string): { outcome: ValidatorOutcome; matched: string | null } {
  const validators = rule.detect.validator;
  if (!validators || validators.length === 0) return { outcome: 'none', matched: null };
  for (const candidate of checksumCandidates(value)) {
    if (runValidators(validators, candidate)) return { outcome: 'passed', matched: candidate };
  }
  return { outcome: 'rejected', matched: null };
}

/**
 * Decide the effective action for a single-line / pr_description finding.
 *
 * A checksum-backed `block` rule only stays `block` when its `require_context`
 * co-occurs; otherwise it is downgraded to `review`. Pattern-only rules keep
 * their declared action (subject to context if specified).
 */
function gradeAction(
  rule: Rule,
  _value: string,
  _surroundingText: string,
  validatorOutcome: ValidatorOutcome,
  contextPresent: boolean,
): 'block' | 'review' | 'advise' {
  let action = rule.action;

  const usesChecksum =
    rule.detect.method === 'checksum' || validatorOutcome !== 'none';

  // For checksum matches, a block requires context to co-occur.
  if (usesChecksum && rule.detect.require_context && !contextPresent) {
    action = downgrade(action);
  }

  // For any rule with require_context but no context present, never escalate
  // to block.
  if (rule.detect.require_context && !contextPresent && action === 'block') {
    action = 'review';
  }

  return action;
}

/** Downgrade an action one severity step. */
function downgrade(action: 'block' | 'review' | 'advise'): 'block' | 'review' | 'advise' {
  if (action === 'block') return 'review';
  if (action === 'review') return 'advise';
  return 'advise';
}

/** Map an effective action to the verdict it implies. */
function actionToVerdict(action: 'block' | 'review' | 'advise'): Verdict {
  if (action === 'block') return 'fail';
  if (action === 'review') return 'needs_review';
  return 'pass'; // advise does not gate
}

/**
 * Run the full scan.
 *
 * Verdict aggregation: any fired block → fail; else any review → needs_review;
 * else pass. Truncation/oversize forces at least needs_review with a warning.
 */
export function scan(ruleset: Ruleset, input: ScanInput): ScanResult {
  const warnings: string[] = [];
  const parsed = parseDiff(input.diff ?? '');
  const prDescription = input.prDescription ?? '';

  // Reset per call — see the note on scanDeadline.
  budgetExceeded = false;
  scanDeadline = Date.now() + (input.budgetMs ?? BUDGET_MS);
  suppressionCounts.clear();
  oversizedLineFiles.clear();
  refusedTierOneGating.clear();
  truncatedPairRules.clear();
  refusedComplexGlobs.clear();
  refusedBlanketGlobs.clear();
  oversizedPrDescription = false;

  // Every one of these means part of the ruleset did not run. They are tracked
  // separately from `findings` because they must FLOOR the verdict, not add to it:
  // a rule that contributed nothing because it could not run is not evidence of
  // absence, and reporting `pass` on that basis is the exact failure this whole
  // change exists to prevent.
  let incompleteScan = false;

  const raw: RawFinding[] = [];
  const rules = ruleset.rules ?? [];
  for (let r = 0; r < rules.length; r++) {
    const rule = rules[r];
    if (outOfBudget()) {
      warnings.push(
        `Scan exceeded its ${input.budgetMs ?? BUDGET_MS} ms budget; ` +
        `${rules.length - r} of ${rules.length} rules did not run. ` +
        'Verdict floored to needs_review.',
      );
      incompleteScan = true;
      break;
    }
    try {
      // A rule whose pattern cannot compile fires nothing and used to say so
      // nowhere, which reads as a clean pass. Name it AND floor the verdict.
      const unusable = unusablePatternFields(rule);
      if (unusable.length > 0) {
        warnings.push(
          `Rule "${sanitizeRuleId(rule.id)}" declares ${unusable.join(', ')} that could not be compiled; ` +
          'that part of the rule did not run. Verdict floored to needs_review.',
        );
        incompleteScan = true;
      }
      raw.push(
        ...evaluateRule(rule, parsed, prDescription, ruleset.allowlist, ruleset.signatures),
      );
    } catch {
      // A malformed rule must never crash the gate; record and continue — but a
      // rule that threw ran even less than one that failed to compile, so it
      // floors too.
      warnings.push(
        `Rule "${sanitizeRuleId(rule?.id ?? 'unknown')}" failed to evaluate and was skipped. ` +
        'Verdict floored to needs_review.',
      );
      incompleteScan = true;
    }
  }

  if (refusedTierOneGating.size > 0) {
    // Loud, and it floors the verdict: a ruleset trying to gate a tier-1 control
    // is either a mistake or an attempt to disable it, and both need a human.
    warnings.push(
      `Tier-1 rule(s) ${[...refusedTierOneGating].map(sanitizeRuleId).join(', ')} declare ` +
      'exclude_pattern/require_pattern; a tier-1 control cannot be gated, so those fields were ' +
      'IGNORED. Verdict floored to needs_review.',
    );
    incompleteScan = true;
  }

  if (budgetExceeded && !incompleteScan) {
    // `budgetExceeded` is set inside the evaluators but was only ever READ at the
    // top of the rule loop, so a deadline reached during the final rule broke the
    // inner loop, returned partial findings, exited the loop normally and left
    // incompleteScan false — a truncated scan reported as a clean pass. Every
    // other incompleteness flag has a post-loop consumer; this one did not.
    warnings.push(
      'Scan exceeded its time budget partway through the final rule, so its results are ' +
      'partial. Verdict floored to needs_review.',
    );
    incompleteScan = true;
  }

  if (refusedBlanketGlobs.size > 0) {
    warnings.push(
      `${refusedBlanketGlobs.size} path glob(s) match EVERY path ` +
      `(${[...refusedBlanketGlobs].slice(0, 5).map(sanitizePathLabel).join(', ')}) and were ` +
      'REFUSED: as an exclusion they would suppress the whole rule, as a scope they would ' +
      'select nothing. Verdict floored to needs_review.',
    );
    incompleteScan = true;
  }

  if (refusedComplexGlobs.size > 0) {
    warnings.push(
      `${refusedComplexGlobs.size} path glob(s) declare more than ${MAX_GLOB_WILDCARDS} wildcards ` +
      `(${[...refusedComplexGlobs].slice(0, 5).map(sanitizePathLabel).join(', ')}) and were REFUSED ` +
      'as a backtracking risk; they matched nothing. Verdict floored to needs_review.',
    );
    incompleteScan = true;
  }

  if (truncatedPairRules.size > 0) {
    warnings.push(
      `Rule(s) ${[...truncatedPairRules].map(sanitizeRuleId).join(', ')} compare removed/added line ` +
      `pairs, and this diff exceeded the ${MAX_MINUS_PLUS_PAIRS} pair ceiling; the comparison was ` +
      'truncated. Verdict floored to needs_review.',
    );
    incompleteScan = true;
  }

  if (oversizedPrDescription) {
    warnings.push(
      `The PR description is longer than ${MAX_SCAN_LINE_CHARS} characters; only the first ` +
      `${MAX_SCAN_LINE_CHARS} were scanned. Verdict floored to needs_review.`,
    );
    incompleteScan = true;
  }

  if (oversizedLineFiles.size > 0) {
    // Scanned in part, so it must not read as a clean pass — same rule the
    // truncated-diff and budget paths follow.
    const named = [...oversizedLineFiles].slice(0, 5).map(sanitizePathLabel).join(', ');
    const more = oversizedLineFiles.size > 5 ? ` and ${oversizedLineFiles.size - 5} more` : '';
    warnings.push(
      `${oversizedLineFiles.size} file(s) contain lines longer than ${MAX_SCAN_LINE_CHARS} characters ` +
      `(${named}${more}); only the first ${MAX_SCAN_LINE_CHARS} characters of each such line were scanned. ` +
      'Verdict floored to needs_review.',
    );
    incompleteScan = true;
  }

  // De-dupe identical (rule + masked evidence) findings.
  const findings: Finding[] = [];
  const seen = new Set<string>();
  let anyBlock = false;
  let anyReview = false;

  for (const f of raw) {
    const key = `${f.rule.id}|${f.maskedEvidence}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const verdict = actionToVerdict(f.effectiveAction);
    if (verdict === 'fail') anyBlock = true;
    if (verdict === 'needs_review') anyReview = true;

    findings.push({
      rule_id: f.rule.id,
      gdpr_article: f.rule.gdpr_article ?? [],
      action: f.effectiveAction,
      masked_evidence: f.maskedEvidence,
    });
  }

  let verdict: Verdict = anyBlock ? 'fail' : anyReview ? 'needs_review' : 'pass';

  // Truncation safety: never silently pass an incompletely-scanned diff.
  if (input.truncated) {
    warnings.push(
      'Diff exceeded the configured size cap and was truncated; verdict floored to needs_review.',
    );
    if (verdict === 'pass') verdict = 'needs_review';
  }

  // A gating field that actually suppressed something is named, so a silenced
  // control can never render as a clean all-clear. This does NOT floor the verdict:
  // suppression is the feature working as configured, and the shipped ruleset uses
  // it legitimately on dc-select-star. Visibility is the point, not a verdict change.
  for (const [ruleId, count] of suppressionCounts) {
    warnings.push(
      `Rule "${sanitizeRuleId(ruleId)}" suppressed ${count} candidate line(s) via ` +
      'its exclude_pattern/require_pattern gating.',
    );
  }

  // SEC12. The same floor, for the same reason, on the OTHER ways a scan can be
  // incomplete: a rule whose pattern would not compile, a rule that threw, or a
  // scan that ran out of budget. Before this, `truncated` floored but those three
  // only warned — so a tier-1 `block` rule could die silently and the gate still
  // reported a green `pass`. The asymmetry was the bug: all four mean the same
  // thing, that the ruleset did not fully run.
  if (incompleteScan && verdict === 'pass') verdict = 'needs_review';

  return { verdict, findings, warnings };
}
