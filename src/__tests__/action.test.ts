import { describe, it, expect } from 'vitest';
import { isValidIban, isValidCreditCard, isValidSvnr, isValidSteuerId, runValidators } from '../validators.js';
import { maskEmail, maskFinding, maskGeneric } from '../mask.js';
import { parseDiff, addedLines, removedLines, minusPlusPairs } from '../diff.js';
import { buildSummary } from '../checkRun.js';
import { scan } from '../scan.js';
import { verdictToConclusion, buildSummary } from '../checkRun.js';
import type { Ruleset, Rule } from '../types.js';

describe('validators', () => {
  it('IBAN blocks only real IBANs (country+length+mod-97)', () => {
    expect(isValidIban('GB82 WEST 1234 5698 7654 32')).toBe(true);
    expect(isValidIban('DE89370400440532013000')).toBe(true);
    expect(isValidIban('GB00WEST12345698765432')).toBe(false);
    expect(isValidIban('not-an-iban')).toBe(false);
  });

  it('credit card requires IIN match + Luhn, not bare Luhn', () => {
    expect(isValidCreditCard('4111 1111 1111 1111')).toBe(true); // Visa test
    expect(isValidCreditCard('4111111111111112')).toBe(false); // Luhn fail
    expect(isValidCreditCard('0000000000000000')).toBe(false); // no IIN
  });

  it('SVNR needs mod-11 check AND a real embedded birth date', () => {
    expect(isValidSvnr('1237010180')).toBe(true); // valid vector (chk 7, DOB 01/01/80)
    expect(isValidSvnr('1234010180')).toBe(false); // wrong check digit
    expect(isValidSvnr('0000000000')).toBe(false); // checksum ok but DOB 00/00/00 invalid
    expect(isValidSvnr('12370101800')).toBe(false); // wrong length
  });

  it('Steuer-ID validates ISO/IEC 7064 MOD 11,10 and rejects leading zero', () => {
    expect(isValidSteuerId('86095742719')).toBe(true); // computed valid vector
    expect(isValidSteuerId('86095742710')).toBe(false); // wrong check digit
    expect(isValidSteuerId('02476291358')).toBe(false); // leading zero never issued
    expect(isValidSteuerId('8609574271')).toBe(false); // wrong length
  });

  it('runValidators returns the first matching name or null', () => {
    expect(runValidators(['iban'], 'GB82WEST12345698765432')).toBe('iban');
    expect(runValidators(['iban', 'credit_card'], 'nope')).toBeNull();
    expect(runValidators([], 'x')).toBeNull();
  });
});

describe('masking — the raw value never survives', () => {
  it('maskEmail reveals only first char + TLD', () => {
    expect(maskEmail('jane.doe@acme.co.uk')).toBe('j***@***.uk');
    expect(maskGeneric('supersecret')).toBe('s***');
  });

  it('maskFinding emits a label + location, never the raw value', () => {
    const raw = 'GB82WEST12345698765432';
    const out = maskFinding('IBAN-pattern', raw, 'fixtures/users.sql', 88);
    expect(out).toBe('IBAN-pattern @ fixtures/users.sql:88');
    expect(out.includes(raw)).toBe(false);
  });

  it('maskFinding strips the raw value even if it leaks into the label/path', () => {
    const raw = 'SECRETVALUE';
    const out = maskFinding(`leak ${raw}`, raw, `path-${raw}`, 1);
    expect(out.includes(raw)).toBe(false);
  });
});

describe('diff parsing', () => {
  const diff = [
    'diff --git a/src/auth.ts b/src/auth.ts',
    '--- a/src/auth.ts',
    '+++ b/src/auth.ts',
    '@@ -1,3 +1,3 @@',
    ' const a = 1;',
    '-const p = bcrypt(pw);',
    '+const p = pw; // plaintext',
    ' export default a;',
  ].join('\n');

  it('attributes added/removed lines and same-hunk pairs', () => {
    const parsed = parseDiff(diff);
    expect(addedLines(parsed).map((l) => l.text)).toContain('const p = pw; // plaintext');
    expect(removedLines(parsed).map((l) => l.text)).toContain('const p = bcrypt(pw);');
    const { pairs, truncated } = minusPlusPairs(parsed, 'same_hunk');
    expect(truncated).toBe(false);
    expect(pairs.length).toBeGreaterThan(0);
    expect(pairs[0].sameHunk).toBe(true);
    expect(pairs[0].minus.file).toBe('src/auth.ts');
  });
});

// ---- scan end-to-end ------------------------------------------------------

function ruleset(rules: Rule[]): Ruleset {
  return {
    ruleset_version: 1,
    ruleset_hash: 'test',
    rules,
    allowlist: { emails: [], names: [], domains: ['example.com'], ip_ranges: [], ibans: [] },
    signatures: { 'telemetry-sdks': ['google-analytics'], 'pii-datastore-credentials': [], 'processor-jurisdiction': [] },
  };
}

function fileDiff(file: string, added: string[], removed: string[] = []): string {
  const body = [...removed.map((l) => `-${l}`), ...added.map((l) => `+${l}`)];
  return [
    `diff --git a/${file} b/${file}`,
    `--- a/${file}`,
    `+++ b/${file}`,
    `@@ -1,${removed.length + 1} +1,${added.length + 1} @@`,
    ' context',
    ...body,
  ].join('\n');
}

describe('scan verdicts', () => {
  it('blocks a checksum-valid IBAN added in a fixtures file', () => {
    const rs = ruleset([{
      id: 'dc-pii-iban', name: 'IBAN', gdpr_article: ['Art 32'], action: 'block', tier: 1,
      detect: { method: 'checksum', target: 'diff', diff_side: 'added', validator: ['iban'], allowlist: 'synthetic', mask: 'IBAN-pattern' },
    }]);
    const res = scan(rs, { diff: fileDiff('fixtures/users.sql', ["INSERT INTO u VALUES ('GB82WEST12345698765432');"]) });
    expect(res.verdict).toBe('fail');
    expect(res.findings[0].action).toBe('block');
    expect(res.findings[0].masked_evidence).not.toContain('GB82WEST12345698765432');
  });

  it('suppresses an allowlisted synthetic email', () => {
    const rs = ruleset([{
      id: 'dc-pii-bare', name: 'PII', gdpr_article: [], action: 'review', tier: 1,
      detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}', allowlist: 'synthetic', mask: 'email' },
    }]);
    const res = scan(rs, { diff: fileDiff('seed.ts', ['const u = "test@example.com";']) });
    expect(res.verdict).toBe('pass');
    expect(res.findings).toHaveLength(0);
  });

  it('blocks a bcrypt→plaintext swap in the same hunk, downgrades across hunks', () => {
    const rule: Rule = {
      id: 'dc-safeguard-removed', name: 'safeguard', gdpr_article: ['Art 32'], action: 'block', tier: 1,
      detect: { method: 'pattern', target: 'diff', diff_side: 'either', paired: { minus: 'bcrypt', plus: 'plaintext', window: 'same_hunk' }, mask: 'safeguard' },
    };
    const sameHunk = scan(ruleset([rule]), {
      diff: fileDiff('src/auth.ts', ['const p = pw; // plaintext'], ['const p = bcrypt(pw);']),
    });
    expect(sameHunk.verdict).toBe('fail');

    // same_file window: pair exists but is cross-hunk → downgraded to review.
    const crossRule: Rule = { ...rule, detect: { ...rule.detect, paired: { minus: 'bcrypt', plus: 'plaintext', window: 'same_file' } } };
    const crossDiff = [
      'diff --git a/src/auth.ts b/src/auth.ts',
      '--- a/src/auth.ts',
      '+++ b/src/auth.ts',
      '@@ -1,1 +1,1 @@',
      '-const p = bcrypt(pw);',
      '@@ -20,1 +20,1 @@',
      '+const p = pw; // plaintext',
    ].join('\n');
    const cross = scan(ruleset([crossRule]), { diff: crossDiff });
    expect(cross.verdict).toBe('needs_review');
  });

  it('flags a telemetry SDK added to package.json as needs_review', () => {
    const rs = ruleset([{
      id: 'dc-pii-telemetry-sdks', name: 'sdk', gdpr_article: ['Art 44'], action: 'review', tier: 1,
      detect: { method: 'signature', target: 'diff', diff_side: 'added', signature: 'telemetry-sdks', file_scope: ['package.json'], mask: 'SDK' },
    }]);
    const res = scan(rs, { diff: fileDiff('package.json', ['    "google-analytics": "^1.0.0",']) });
    expect(res.verdict).toBe('needs_review');
    expect(res.findings[0].action).toBe('review');
  });

  it('never silently passes a truncated diff', () => {
    const res = scan(ruleset([]), { diff: '', truncated: true });
    expect(res.verdict).toBe('needs_review');
    expect(res.warnings.join(' ')).toMatch(/truncat/i);
  });

  // Regression: the seeded ruleset's PCRE-style leading "(?i)" prefix (e.g.
  // dc-pii-in-logs) used to make compile() throw, get caught, and return null —
  // silently dropping the rule to zero findings on every PR with no warning.
  it('matches a seeded rule pattern carrying a leading "(?i)" case-insensitive prefix', () => {
    const rs = ruleset([{
      id: 'dc-pii-in-logs', name: 'PII in logs', gdpr_article: ['Art 32'], action: 'block', tier: 1,
      detect: {
        method: 'pattern', target: 'diff', diff_side: 'added',
        pattern: '(?i)(log(ger)?|console)\\.[a-z]+\\([^)]*(user\\.email|request\\.body|\\bpassword\\b)',
        mask: 'log call',
      },
    }]);
    const res = scan(rs, { diff: fileDiff('src/handler.ts', ['Logger.info(`sending ${user.email}`);']) });
    expect(res.verdict).toBe('fail');
    expect(res.findings).toHaveLength(1);
  });

  it('floors to needs_review when a pattern has no JS RegExp equivalent (SEC12)', () => {
    // THIS TEST USED TO PIN `pass`, AND THAT PIN WAS THE BUG. The rule below is
    // tier 1 / `block` — the strongest control the ruleset has — and an
    // unrecognised inline flag makes it contribute nothing. Reporting `pass` on
    // that basis says "we looked and found nothing" when the truth is "we did not
    // look", which is the single failure mode this whole precision pass exists to
    // avoid. `truncated` in the same function had always floored for exactly this
    // reason; the asymmetry was the defect.
    const rs = ruleset([{
      id: 'dc-bad-flag', name: 'bad flag', gdpr_article: [], action: 'block', tier: 1,
      detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: '(?x)foo bar', mask: 'x' },
    }]);
    const res = scan(rs, { diff: fileDiff('f.ts', ['foo bar']) });
    expect(res.verdict).toBe('needs_review');
    expect(res.findings).toHaveLength(0);
    expect(res.warnings.join(' ')).toContain('floored to needs_review');
  });

  it('floors to needs_review when a rule throws rather than merely failing to compile', () => {
    // A rule that threw ran even less than one that failed to compile, so it must
    // floor too. Previously it only warned.
    const rs = ruleset([{
      id: 'dc-throws', name: 'throws', gdpr_article: [], action: 'block', tier: 1,
      // A getter on `detect` that throws when the evaluator reads it.
      get detect(): never { throw new Error('boom'); },
    } as unknown as Rule]);
    const res = scan(rs, { diff: fileDiff('f.ts', ['anything']) });
    expect(res.verdict).toBe('needs_review');
    expect(res.warnings.join(' ')).toContain('failed to evaluate');
  });

  it('floors to needs_review and names how many rules did not run when the budget is exceeded', () => {
    // The budget exists because catastrophic backtracking is a property of a
    // pattern's STRUCTURE, not its length: `(a+)+$` is six characters and was
    // measured at ~150 s on a 32-char line. A length cap cannot prevent that, and
    // `pattern` is an editable field in the rule editor, so an org admin reaches it
    // through a supported form. budgetMs: 0 makes the deadline already past.
    const rules: Rule[] = Array.from({ length: 4 }, (_, i) => ({
      id: `dc-r${i}`, name: `r${i}`, gdpr_article: [], action: 'review', tier: 2,
      detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: 'anything', mask: 'm' },
    }));
    const res = scan(ruleset(rules), { diff: fileDiff('f.ts', ['anything']), budgetMs: 0 });
    expect(res.verdict).toBe('needs_review');
    expect(res.warnings.join(' ')).toContain('4 of 4 rules did not run');
  });

  it('does not leak an exceeded budget into the next scan', () => {
    // scanDeadline/budgetExceeded are module-scoped, so a stale `true` would make
    // every later scan in the same process report needs_review with no rules run.
    const rs = ruleset([{
      id: 'dc-ok', name: 'ok', gdpr_article: [], action: 'review', tier: 2,
      detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: 'secret', mask: 'm' },
    }]);
    expect(scan(rs, { diff: fileDiff('f.ts', ['secret']), budgetMs: 0 }).verdict).toBe('needs_review');
    const after = scan(rs, { diff: fileDiff('f.ts', ['secret']) });
    expect(after.verdict).toBe('needs_review');
    expect(after.findings).toHaveLength(1);
    expect(after.warnings.join(' ')).not.toContain('did not run');
  });

  it('REFUSES to let gating silence a tier-1 rule, and names it (SEC6)', () => {
    // THE MEASURED ATTACK. `exclude_pattern: '.'` on tier-1 blocking dc-pii-iban
    // turned `fail` into `pass` with zero findings AND ZERO WARNINGS — a silenced
    // control rendering as a clean all-clear, strictly worse than the noise this
    // precision pass removed.
    //
    // This assertion used to be `findings === []` plus a warning, i.e. suppression
    // still happened but was no longer silent. That was only HALF of what SEC6
    // asked for — it also asked to reject gating fields on tier-1 rules outright —
    // and half is not enough here: a warning on a check nobody blocks on is still a
    // disabled control. The rule now fires anyway and the gate says why.
    const rs = ruleset([{
      id: 'dc-pii-iban', name: 'iban', gdpr_article: ['Art 32'], action: 'block', tier: 1,
      detect: {
        method: 'pattern', target: 'diff', diff_side: 'added',
        pattern: 'DE[0-9]{20}', exclude_pattern: '.', mask: 'IBAN @ <file>:<line>',
      },
    }]);
    // DELIBERATELY NOT a checksum-valid IBAN. The first version of this test used a
    // real mod-97-valid one, and the gate BLOCKED this very PR for it — correctly:
    // dc-pii-iban is tier-1 `block`, committing a valid IBAN is exactly what it
    // exists to stop, and the rule under test here is a `pattern` rule matching
    // DE[0-9]{20}, so checksum validity was never needed. The gate catching its own
    // author is the system working; leaving a valid IBAN in to make a test read
    // nicer would be the tail wagging the dog.
    const res = scan(rs, { diff: fileDiff('x.ts', ['DE00000000000000000000']) });
    expect(res.findings.map((f) => f.rule_id)).toEqual(['dc-pii-iban']);
    expect(res.warnings.join(' ')).toContain('dc-pii-iban');
    expect(res.warnings.join(' ')).toContain('cannot be gated');
  });

  it('still names a TIER-2 rule whose gating actually suppressed something (SEC6)', () => {
    // The visibility half of SEC6, kept, on a tier where gating is legitimate
    // configuration rather than a kill switch.
    const rs = ruleset([{
      id: 'dc-select-star', name: 'select *', gdpr_article: ['Art 5(1)(c)'], action: 'review', tier: 2,
      detect: {
        method: 'pattern', target: 'diff', diff_side: 'added',
        pattern: '(?i)select\\s+\\*', exclude_pattern: '.', mask: 'SELECT * @ <file>:<line>',
      },
    }]);
    const res = scan(rs, { diff: fileDiff('x.sql', ['SELECT * FROM users;']) });
    expect(res.findings).toEqual([]);
    expect(res.warnings.join(' ')).toContain('dc-select-star');
    expect(res.warnings.join(' ')).toContain('suppressed');
  });

  it('stays silent when a gating field is declared but suppresses nothing', () => {
    // Deliberate: dc-select-star ships with an exclude_pattern, so warning on mere
    // DECLARATION would fire on every scan forever and train readers to ignore
    // warnings — the same failure as a gate that always says needs_review.
    const rs = ruleset([{
      id: 'dc-select-star', name: 'select star', gdpr_article: [], action: 'advise', tier: 3,
      detect: {
        method: 'pattern', target: 'diff', diff_side: 'added',
        pattern: '(?i)select\\s+\\*', exclude_pattern: '(?i)pg_catalog', mask: 'm',
      },
    }]);
    const res = scan(rs, { diff: fileDiff('q.sql', ['SELECT * FROM public.patients;']) });
    expect(res.findings).toHaveLength(1);
    expect(res.warnings.join(' ')).not.toContain('suppressed');
  });

  it('does not leak suppression counts into the next scan', () => {
    const gated = ruleset([{
      id: 'dc-gated', name: 'gated', gdpr_article: [], action: 'review', tier: 2,
      detect: {
        method: 'pattern', target: 'diff', diff_side: 'added',
        pattern: 'secret', exclude_pattern: '.', mask: 'm',
      },
    }]);
    expect(scan(gated, { diff: fileDiff('a.ts', ['secret']) }).warnings.join(' ')).toContain('suppressed');
    const plain = ruleset([{
      id: 'dc-plain', name: 'plain', gdpr_article: [], action: 'review', tier: 2,
      detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: 'secret', mask: 'm' },
    }]);
    expect(scan(plain, { diff: fileDiff('a.ts', ['secret']) }).warnings.join(' ')).not.toContain('suppressed');
  });

  it('clamps an org-controlled rule id before it reaches check-run markdown', () => {
    // rule.id is any non-empty string an org admin chooses, and warnings render as
    // `- ${w}` into markdown. A `|` breaks the findings table; the id had no length
    // bound, unlike masked_evidence which already passes sanitizeLabel's clamp.
    const rs = ruleset([{
      id: `dc-|-${'x'.repeat(400)}`, name: 'long', gdpr_article: [], action: 'block', tier: 1,
      detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: '(?x)bad', mask: 'm' },
    }]);
    const w = scan(rs, { diff: fileDiff('f.ts', ['bad']) }).warnings.join(' ');
    expect(w).not.toContain('|');
    expect(w).not.toContain('x'.repeat(200));
  });
});

/**
 * `exclude_pattern` / `require_pattern` — the two gating fields added for the
 * tier-2 precision work.
 *
 * Why NEW fields rather than repairing `require_context`: that field is
 * honoured in exactly ONE of the four evaluation paths (evaluateLinePattern).
 * evaluateSignature and evaluatePaired never read it, and
 * evaluatePrDescription hardcodes "context present = true". Even where it is
 * read, it only DOWNGRADES a block — so on a rule already declared `review`
 * with no validators it has no effect whatsoever. Redefining it in place
 * would silently change dc-pii-weak-checksum (a checksum rule where it does
 * bite). These two fields are preconditions/suppressors instead, honoured in
 * every path, leaving all 19 existing rules byte-identical in behaviour.
 */
/**
 * SEC8 — a checksum identifier sitting inside a sentence.
 *
 * `CHECKSUM_CANDIDATE_RE` includes the space character and is greedy, so on a prose
 * line it hands the validator the WHOLE phrase. The validators strip whitespace
 * internally, so "Wire to DE44… for the payout" normalises to
 * "WIRETODE44…FORTHEPAYOUT" and correctly fails mod-97 — and nothing ever offered
 * the bare IBAN inside it. The bare value on its own line was caught; the same value
 * in a sentence was not.
 *
 * This matters more since the precision pass, because `.md` and `docs/` are now
 * excluded from the tier-2 prose rules, leaving the tier-1 checksum rules as the
 * last line of defence on exactly the paths where identifiers appear in sentences.
 *
 * The greedy whole-candidate attempt is KEPT and tried first, because that is what
 * makes a space-grouped identifier work (an IBAN written in groups of four).
 */
describe('SEC8 — checksum identifiers inside prose', () => {
  const ibanRule: Rule = {
    id: 'dc-pii-iban', name: 'iban', gdpr_article: ['Art 32'], action: 'block', tier: 1,
    detect: {
      method: 'checksum', target: 'diff', diff_side: 'added',
      validator: ['iban'], mask: 'IBAN-pattern @ <file>:<line> (masked)',
    },
  };
  const hits = (line: string) => scan(ruleset([ibanRule]), { diff: fileDiff('notes.md', [line]) }).findings.length;

  /**
   * Assembled at runtime, deliberately. A literal space-grouped IBAN written out on
   * a diff line is itself a blocking finding under the SHIPPED ruleset — the gate
   * blocked this very PR for exactly that. (This used to add that the action was
   * pinned `@main`, so a branch was graded by main's bundle. STALE:
   * `data-compliance.yml` now references it by LOCAL path, so a PR is graded by its
   * OWN committed dist/index.js. The conclusion is unchanged and if anything
   * stronger — a branch that WIDENS detection blocks on its own new literals.)
   * The quotes and commas break the scanner's candidate run, so the value
   * only ever exists at runtime while the test still exercises a real mod-97-valid
   * grouped identifier — which is the whole point of the contiguous-run search.
   */
  const GROUPED = ['GB82', 'WEST', '1234', '5698', '7654', '32'].join(' ');

  it('still catches a bare identifier on its own (regression guard)', () => {
    expect(hits('DE89370400440532013000')).toBe(1);
  });

  it('catches one inside a sentence', () => {
    expect(hits('Wire to DE89370400440532013000 for the payout.')).toBe(1);
  });

  it('catches one followed by punctuation', () => {
    expect(hits('Send DE89370400440532013000, then confirm.')).toBe(1);
  });

  it('catches a SPACE-GROUPED identifier inside a sentence', () => {
    // The hard case: the whole phrase fails, every single token fails, and only a
    // contiguous RUN of tokens validates.
    expect(hits(`Please pay ${GROUPED} by Friday.`)).toBe(1);
  });

  it('still catches a space-grouped identifier on its own (regression guard)', () => {
    expect(hits(GROUPED)).toBe(1);
  });

  /**
   * HYPHEN-grouped, assembled at runtime for the same reason `GROUPED` is.
   *
   * This spelling escaped the gate ENTIRELY until v2.184.2 — verdict `pass`, zero
   * findings — while the compact and space-grouped spellings of the same IBAN both
   * hard-blocked. `isValidIban` stripped only whitespace, even though the candidate
   * length filter and the allowlist's `groupingInsensitive` compare had both always
   * stripped `[\s-]`, and the allowlist's own comment asserted the validator did too.
   */
  const HYPHENATED = ['AT61', '1904', '3002', '3457', '3201'].join('-');

  it('catches a HYPHEN-grouped identifier — it used to escape entirely', () => {
    expect(hits(HYPHENATED)).toBe(1);
  });

  it('catches a hyphen-grouped identifier inside a sentence', () => {
    expect(hits(`Please pay ${HYPHENATED} by Friday.`)).toBe(1);
  });

  /**
   * A SHORT-BBAN country (LB), whose numeric run is 6-10 digits and so fits
   * entirely inside what `DATE_LIKE_RE` can cover. The date guard suppressed
   * these, silently cancelling the hyphen fix directly above for LB/UA/GR/AD/CH/
   * LI/TR/AL/CY — `dc-pii-iban` is `block` with no `require_context`, so that was
   * a straight hard-block bypass, not a downgrade.
   */
  const SHORT_BBAN = ['LB3812', '3', '4ABCDEFGHIJKLMNOPQRST'].join('-');

  it('catches a short-BBAN IBAN whose digits fit inside a date shape', () => {
    expect(hits(`const account = "${SHORT_BBAN}";`)).toBe(1);
  });

  it('does not invent a finding from ordinary prose', () => {
    expect(hits('We should document the retention window for this table.')).toBe(0);
    expect(hits('The quick brown fox jumps over the lazy dog repeatedly today.')).toBe(0);
  });

  it('treats an allowlisted IBAN as synthetic regardless of grouping', () => {
    // The mirror of SEC8, and a real bug this release made reachable. isValidIban
    // strips whitespace and hyphens, so a grouped IBAN validates — but isAllowlisted
    // did an exact lowercase compare, so the SAME value in its canonical grouped
    // presentation did not match the unspaced entry in the list, and a documented
    // example blocked a PR. Before the sub-candidate search above, a grouped IBAN in
    // prose was never offered to the validator at all, so it never reached the
    // allowlist check either.
    const allowlisted: Rule = {
      ...ibanRule,
      detect: { ...ibanRule.detect, allowlist: 'synthetic' },
    };
    const withAllowlist = (line: string) =>
      scan({ rules: [allowlisted], signatures: {}, allowlist: { ibans: ['GB82WEST12345698765432'] } } as never,
           { diff: fileDiff('notes.md', [line]) }).findings.length;

    expect(withAllowlist('GB82WEST12345698765432')).toBe(0);   // always worked
    expect(withAllowlist(GROUPED)).toBe(0);                     // used to be 1
    expect(withAllowlist(`Wire ${GROUPED} today.`)).toBe(0);    // and inside prose
  });

  it('does not fabricate one by stitching unrelated numbers together', () => {
    // Guard against an over-eager sub-candidate search: concatenating separate
    // numbers must not manufacture a checksum-valid value.
    expect(hits('Bump 1904 to 3000 and 2011 to 1234 in the config.')).toBe(0);
  });
});

describe('exclude_pattern / require_pattern gating', () => {
  const line = 'ALTER TABLE public.applicants ADD COLUMN credit_score numeric;';

  function patternRule(detect: Partial<Rule['detect']>): Rule {
    return {
      id: 'r', name: 'r', gdpr_article: [], action: 'review', tier: 2,
      detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: 'credit_score', mask: 'm', ...detect },
    };
  }

  it('fires with neither field set (baseline)', () => {
    expect(scan(ruleset([patternRule({})]), { diff: fileDiff('x.sql', [line]) }).findings).toHaveLength(1);
  });

  it('exclude_pattern suppresses the finding entirely, not merely downgrades it', () => {
    const res = scan(ruleset([patternRule({ exclude_pattern: 'ALTER TABLE' })]), { diff: fileDiff('x.sql', [line]) });
    expect(res.findings).toEqual([]);
    expect(res.verdict).toBe('pass');
  });

  it('exclude_pattern that does not match leaves the finding intact', () => {
    const res = scan(ruleset([patternRule({ exclude_pattern: 'DROP TABLE' })]), { diff: fileDiff('x.sql', [line]) });
    expect(res.findings).toHaveLength(1);
  });

  it('require_pattern suppresses when absent and permits when present', () => {
    const absent = scan(ruleset([patternRule({ require_pattern: 'ZZZ_NOT_PRESENT' })]), { diff: fileDiff('x.sql', [line]) });
    expect(absent.findings).toEqual([]);
    const present = scan(ruleset([patternRule({ require_pattern: 'ADD\\s+COLUMN' })]), { diff: fileDiff('x.sql', [line]) });
    expect(present.findings).toHaveLength(1);
  });

  it('both fields are honoured on a signature rule (a path require_context never reached)', () => {
    const sig = (detect: Partial<Rule['detect']>): Rule => ({
      id: 's', name: 's', gdpr_article: [], action: 'review', tier: 2,
      detect: { method: 'signature', target: 'diff', diff_side: 'added', signature: 'telemetry-sdks', mask: 'm', ...detect },
    });
    const hit = fileDiff('package.json', ['    "google-analytics": "^1.0.0",']);
    expect(scan(ruleset([sig({})]), { diff: hit }).findings).toHaveLength(1);
    expect(scan(ruleset([sig({ exclude_pattern: 'google-analytics' })]), { diff: hit }).findings).toEqual([]);
    expect(scan(ruleset([sig({ require_pattern: 'ZZZ' })]), { diff: hit }).findings).toEqual([]);
  });

  it('both fields are honoured on a paired rule (the other path require_context never reached)', () => {
    const paired = (detect: Partial<Rule['detect']>): Rule => ({
      // tier 2, not 1: gating on a tier-1 rule is refused outright (SEC6), and what
      // these cases exercise is the paired-gate mechanism, not tier semantics.
      id: 'p', name: 'p', gdpr_article: [], action: 'block', tier: 2,
      detect: {
        method: 'pattern', target: 'diff', diff_side: 'either',
        paired: { minus: 'bcrypt', plus: 'plaintext', window: 'same_hunk' }, mask: 'm', ...detect,
      },
    });
    const swap = fileDiff('src/auth.ts', ['const p = pw; // plaintext'], ['const p = bcrypt(pw);']);
    expect(scan(ruleset([paired({})]), { diff: swap }).findings).toHaveLength(1);
    expect(scan(ruleset([paired({ exclude_pattern: 'plaintext' })]), { diff: swap }).findings).toEqual([]);
    expect(scan(ruleset([paired({ require_pattern: 'ZZZ' })]), { diff: swap }).findings).toEqual([]);
  });

  it('accepts a PCRE-style "(?i)" prefix on both fields, like every other pattern field', () => {
    const res = scan(ruleset([patternRule({ exclude_pattern: '(?i)alter\\s+table' })]), { diff: fileDiff('x.sql', [line]) });
    expect(res.findings).toEqual([]);
  });

  it('treats an uncompilable gating pattern as absent rather than silently killing the rule', () => {
    // A malformed exclude_pattern must not suppress everything (fail-open on
    // the SUPPRESSOR), and a malformed require_pattern must not gate
    // everything away (fail-open on the PRECONDITION). Either failing closed
    // would turn a typo into a rule that reports nothing, with no warning —
    // the "clean bill of health" failure this whole change exists to avoid.
    const badExclude = scan(ruleset([patternRule({ exclude_pattern: '([unclosed' })]), { diff: fileDiff('x.sql', [line]) });
    expect(badExclude.findings).toHaveLength(1);
    const badRequire = scan(ruleset([patternRule({ require_pattern: '([unclosed' })]), { diff: fileDiff('x.sql', [line]) });
    expect(badRequire.findings).toHaveLength(1);
  });

  it('applies exclude_paths and file_scope identically on every line, not just the first', () => {
    // globToRegExp is memoised (a 4.3 MB diff otherwise costs ~2.5M RegExp
    // compilations once most rules carry an exclusion list). A shared compiled
    // instance is only safe because it has no `g` flag — with one, `.test()`
    // would advance lastIndex and the SECOND line onward would silently stop
    // matching, quietly un-excluding paths mid-scan. This pins that.
    const rule: Rule = {
      id: 'r', name: 'r', gdpr_article: [], action: 'review', tier: 2,
      detect: {
        method: 'pattern', target: 'diff', diff_side: 'added',
        pattern: 'credit_score', exclude_paths: ['docs/'], mask: 'm',
      },
    };
    const many = Array.from({ length: 25 }, () => line);

    // Every line lives in an excluded path → zero findings, not "all but the first".
    const excluded = scan(ruleset([rule]), { diff: fileDiff('docs/schema.sql', many) });
    expect(excluded.findings).toEqual([]);

    // Same rule, same repeated line, a path that is NOT excluded → all of them fire.
    const scanned = scan(ruleset([rule]), { diff: fileDiff('db/schema.sql', many) });
    expect(scanned.findings).toHaveLength(many.length);
  });

  // ---- found by independent review, not by the author's own read ----------
  //
  // A gating pattern may declare its OWN flags via the PCRE-style inline
  // prefix, and `g`/`y` are real JS flags that resolvePattern accepts. Since
  // the compiled gate is hoisted and shared across every line, a global or
  // sticky instance carries lastIndex between lines and scans half the diff.
  // Before the fix: 4 identical lines that should ALL be suppressed had 2
  // suppressed, and 4 that should ALL fire had 2 fire. Reachable by an org
  // admin — the rule editor's isValidRegex accepts `(?gi)`.
  it('neutralises a `g` flag the gating pattern declares itself', () => {
    const rule = (detect: Partial<Rule['detect']>): Rule => ({
      id: 'r', name: 'r', gdpr_article: [], action: 'review', tier: 2,
      detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: 'SECRET', mask: 'm', ...detect },
    });
    const four = ['SECRET ok', 'SECRET ok', 'SECRET ok', 'SECRET ok'];

    // exclude_pattern must suppress ALL four, not alternate ones.
    const excluded = scan(ruleset([rule({ exclude_pattern: '(?gi)ok' })]), { diff: fileDiff('a.ts', four) });
    expect(excluded.findings).toEqual([]);

    // require_pattern must admit ALL four, not alternate ones. This direction
    // is the dangerous one: it drops real findings, silently.
    const required = scan(ruleset([rule({ require_pattern: '(?gi)ok' })]), { diff: fileDiff('a.ts', four) });
    expect(required.findings).toHaveLength(4);
  });

  it('neutralises a sticky `y` flag the same way', () => {
    const rule: Rule = {
      id: 'r', name: 'r', gdpr_article: [], action: 'review', tier: 2,
      detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: 'SECRET', exclude_pattern: '(?y)ok', mask: 'm' },
    };
    // 'ok' is not at index 0, so a sticky gate would never match and would
    // wrongly let both lines through.
    const res = scan(ruleset([rule]), { diff: fileDiff('a.ts', ['ok SECRET', 'ok SECRET']) });
    expect(res.findings).toEqual([]);
  });

  it('lets a paired gate anchor against the ADDED line, not just the removed one', () => {
    // The two halves are tested independently. Joining them with "\n" and
    // testing once (without the `m` flag) made `^`-anchored gates able to see
    // only the removed line.
    const paired = (detect: Partial<Rule['detect']>): Rule => ({
      // tier 2, not 1: gating on a tier-1 rule is refused outright (SEC6), and what
      // these cases exercise is the paired-gate mechanism, not tier semantics.
      id: 'p', name: 'p', gdpr_article: [], action: 'block', tier: 2,
      detect: {
        method: 'pattern', target: 'diff', diff_side: 'either',
        paired: { minus: 'old', plus: 'new', window: 'same_hunk' }, mask: 'm', ...detect,
      },
    });
    const diff = fileDiff('a.ts', ['new value'], ['old value']);
    expect(scan(ruleset([paired({ require_pattern: '^new' })]), { diff }).findings).toHaveLength(1);
    expect(scan(ruleset([paired({ require_pattern: '^old' })]), { diff }).findings).toHaveLength(1);
    expect(scan(ruleset([paired({ exclude_pattern: '^new' })]), { diff }).findings).toEqual([]);
  });

  it('warns instead of going quiet when a rule pattern cannot be compiled', () => {
    // `(?x)` is not a JS flag, so resolvePattern returns null and the rule
    // contributes nothing. Previously it said so nowhere, which renders as a
    // clean pass — the exact failure this work exists to prevent.
    const rule: Rule = {
      id: 'dc-bad-flag', name: 'bad', gdpr_article: [], action: 'block', tier: 1,
      detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: '(?x)SECRET', mask: 'm' },
    };
    const res = scan(ruleset([rule]), { diff: fileDiff('a.ts', ['SECRET here']) });
    expect(res.findings).toEqual([]);
    expect(res.warnings.join(' ')).toContain('dc-bad-flag');
    expect(res.warnings.join(' ')).toContain('pattern');
  });

  it('leaves require_context semantics untouched (no behaviour change for existing rules)', () => {
    // Unchanged contract: on a pattern rule declared `review` with no
    // validators, require_context has no effect. Pinned so a future
    // "cleanup" of that field is a deliberate, visible decision.
    const res = scan(
      ruleset([patternRule({ require_context: 'ZZZ_NOT_PRESENT' })]),
      { diff: fileDiff('x.sql', [line]) },
    );
    expect(res.findings).toHaveLength(1);
    expect(res.findings[0].action).toBe('review');
  });
});

describe('check run conclusion mapping', () => {
  it('maps verdict → conclusion', () => {
    expect(verdictToConclusion('fail')).toBe('failure');
    expect(verdictToConclusion('pass')).toBe('success');
    expect(verdictToConclusion('needs_review')).toBe('neutral');
  });

  it('summary lists masked evidence only', () => {
    const summary = buildSummary({ verdict: 'fail', findings: [{ rule_id: 'r', gdpr_article: ['Art 32'], action: 'block', masked_evidence: 'IBAN-pattern @ x:1' }], warnings: [] });
    expect(summary).toContain('IBAN-pattern @ x:1');
    expect(summary).toContain('Verdict: fail');
  });
});

/**
 * SEC7 — cost is bounded by LINE LENGTH, not just by line count.
 *
 * The shipped PII patterns are quadratic in the length of a single line:
 * `[A-Za-z0-9._%+-]+@` must retry from every offset of a long in-class run before
 * it can fail, and `(//|#).*(…@…)` backtracks `.*` across the line for each of
 * them. Measured before the fix, on 20 lines of in-class characters with no `@`,
 * both rules came out at a clean x4.0 per doubling of line length:
 *
 *      500 -> 12 ms, 1000 -> 35 ms, 2000 -> 137 ms, 4000 -> 550 ms, 8000 -> 2209 ms
 *
 * `BUDGET_MS` cannot save this — JavaScript cannot interrupt a regex mid-match,
 * so a budget sampled BETWEEN lines is powerless inside one. And it is reachable:
 * THIS repository checks in 1.8 MB single-line HTML files that ALWAYS_EXCLUDE
 * does not cover, which extrapolate to ~94 minutes for one rule on one line.
 */
describe('SEC7 — a single very long line cannot hang the scan', () => {
  const EMAIL_RULE: Rule = {
    id: 'r-email',
    name: 'email',
    gdpr_article: [],
    action: 'review',
    tier: 2,
    detect: {
      method: 'pattern',
      target: 'diff',
      diff_side: 'added',
      // The real dc-pii-bare local-part class: the source of the backtracking.
      pattern: '([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,})',
      mask: 'email @ <file>:<line>',
    },
  } as unknown as Rule;

  /** `len` characters that are all inside the local-part class, with no "@". */
  const inClass = (len: number) => 'a.b-c_d'.repeat(Math.ceil(len / 7)).slice(0, len);

  it('scans an oversized line only in part, and says so instead of passing', () => {
    const res = scan(ruleset([EMAIL_RULE]), { diff: fileDiff('src/big.ts', [inClass(50_000)]) });
    expect(res.verdict).toBe('needs_review');
    expect(res.warnings.join(' ')).toContain('longer than 8192 characters');
    expect(res.warnings.join(' ')).toContain('src/big.ts');
  });

  it('still reports a real finding that falls inside the scanned prefix', () => {
    const line = `x@example.org ${inClass(50_000)}`;
    const res = scan(ruleset([EMAIL_RULE]), { diff: fileDiff('src/big.ts', [line]) });
    expect(res.findings.map((f) => f.rule_id)).toContain('r-email');
  });

  it('leaves a normal-length line completely alone — no warning, no floor', () => {
    const res = scan(ruleset([EMAIL_RULE]), { diff: fileDiff('src/small.ts', [inClass(4_000)]) });
    expect(res.verdict).toBe('pass');
    expect(res.warnings.join(' ')).not.toContain('longer than');
  });

  it('costs the same at 1.8 MB as at the cap — the quadratic tail is gone', () => {
    // A wall-clock assertion, deliberately: the defect IS the wall clock, and a
    // behavioural assertion alone would still pass if the cap were applied after
    // the regex ran. Threshold is ~50x the measured 117 ms so it cannot flake on a
    // slow runner, while the pre-fix cost of this exact input was ~94 MINUTES.
    const started = Date.now();
    const res = scan(ruleset([EMAIL_RULE]), { diff: fileDiff('src/huge.html', [inClass(1_811_456)]) });
    const elapsed = Date.now() - started;
    expect(res.verdict).toBe('needs_review');
    expect(elapsed).toBeLessThan(6_000);
  });

  it('names every oversized file, and summarises past five', () => {
    const files = Array.from({ length: 7 }, (_, i) => `src/gen-${i}.ts`);
    const diff = files.map((f) => fileDiff(f, [inClass(20_000)])).join('\n');
    const res = scan(ruleset([EMAIL_RULE]), { diff });
    const warning = res.warnings.find((w) => w.includes('longer than 8192 characters'))!;
    expect(warning).toContain('7 file(s)');
    expect(warning).toContain('and 2 more');
  });
});

/**
 * SEC6 (completing it) — a tier-1 control cannot be gated.
 *
 * `exclude_pattern` silences a rule from one side (`"."` matches every line) and
 * `require_pattern` from the other (a precondition that never matches). On a
 * tier-1 BLOCKING rule either is a kill switch that leaves no trace but a green
 * check. `saveDataComplianceRule` already refuses to author these fields from the
 * editor (GATING_NOT_EDITABLE); this is the Action-side second line, so the gate
 * holds no matter how the field reached the ruleset.
 */
describe('SEC6 — tier-1 rules cannot be gated', () => {
  const tier1 = (detect: Record<string, unknown>): Rule => ({
    id: 'r-tier1',
    name: 'tier1',
    gdpr_article: [],
    action: 'block',
    tier: 1,
    detect: {
      method: 'pattern',
      target: 'diff',
      diff_side: 'added',
      pattern: 'SECRETVALUE',
      mask: 'hit @ <file>:<line>',
      ...detect,
    },
  } as unknown as Rule);

  it('ignores an exclude_pattern that would silence a tier-1 rule, and says so', () => {
    const res = scan(ruleset([tier1({ exclude_pattern: '.' })]), {
      diff: fileDiff('src/a.ts', ['const x = "SECRETVALUE";']),
    });
    expect(res.findings.map((f) => f.rule_id)).toContain('r-tier1');
    expect(res.warnings.join(' ')).toContain('cannot be gated');
    expect(res.warnings.join(' ')).toContain('r-tier1');
  });

  it('ignores a require_pattern that would silence a tier-1 rule from the other side', () => {
    const res = scan(ruleset([tier1({ require_pattern: 'NEVER_MATCHES_ANYTHING' })]), {
      diff: fileDiff('src/a.ts', ['const x = "SECRETVALUE";']),
    });
    expect(res.findings.map((f) => f.rule_id)).toContain('r-tier1');
    expect(res.warnings.join(' ')).toContain('cannot be gated');
  });

  it('still honours gating on a tier-2 or tier-3 rule — this is a tier-1 rule only', () => {
    const tier3 = { ...tier1({ exclude_pattern: '.' }), id: 'r-tier3', tier: 3, action: 'advise' } as unknown as Rule;
    const res = scan(ruleset([tier3]), { diff: fileDiff('src/a.ts', ['const x = "SECRETVALUE";']) });
    expect(res.findings).toHaveLength(0);
    expect(res.warnings.join(' ')).not.toContain('cannot be gated');
  });
});

/**
 * Findings from the independent security review of the SEC4/SEC7 commits.
 *
 * Each case here is one the review DEMONSTRATED against the shipped code, not a
 * hypothetical. Several are defects the SEC4 anchoring change introduced or
 * widened, which is the reason this block exists rather than a note in a doc.
 */
describe('security review follow-ups', () => {
  const tier1 = (detect: Record<string, unknown>): Rule => ({
    id: 'r-t1', name: 't1', gdpr_article: [], action: 'block', tier: 1,
    detect: {
      method: 'pattern', target: 'diff', diff_side: 'added',
      pattern: 'SECRETVALUE', mask: 'hit @ <file>:<line>', ...detect,
    },
  } as unknown as Rule);

  // -- a glob that matches every path must never silence a rule ---------------

  it.each([
    '*', '**', '?', '***', '^*', '*$', '**$', '^**$', '^?', '^', '$', '^$',
  ])('refuses the match-everything exclude_paths glob %j', (glob) => {
    // The first guard only caught an EMPTY body, so `^`/`$`/`^$` failed closed
    // while `*`, `**`, `?` and the four anchored spellings the SEC4 change made
    // possible all matched every path — disabling a tier-1 BLOCK rule and
    // reporting a clean green pass with no finding and no warning.
    const res = scan(ruleset([tier1({ exclude_paths: [glob] })]), {
      diff: fileDiff('src/a.ts', ['const x = "SECRETVALUE";']),
    });
    expect(res.findings.map((f) => f.rule_id), `exclude_paths: [${glob}]`).toContain('r-t1');
  });

  it('still honours a glob that genuinely discriminates', () => {
    const suppressed = scan(ruleset([tier1({ exclude_paths: ['^vendor/'] })]), {
      diff: fileDiff('vendor/a.ts', ['const x = "SECRETVALUE";']),
    });
    const kept = scan(ruleset([tier1({ exclude_paths: ['^vendor/'] })]), {
      diff: fileDiff('src/a.ts', ['const x = "SECRETVALUE";']),
    });
    expect(suppressed.findings).toHaveLength(0);
    expect(kept.findings.map((f) => f.rule_id)).toContain('r-t1');
  });

  // -- backtracking through glob-derived regexes ------------------------------

  it('refuses a wildcard-heavy glob instead of backtracking on it', () => {
    // Measured before the cap: a 13-char glob with 6 stars took 6714 ms against
    // one 67-char path, and 8 stars ran past 120 s. Per glob, per diff line.
    const started = Date.now();
    const res = scan(ruleset([tier1({ exclude_paths: ['*a*a*a*a*a*aX'] })]), {
      diff: fileDiff('src/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.ts',
        ['const x = "SECRETVALUE";']),
    });
    expect(Date.now() - started).toBeLessThan(2_000);
    expect(res.findings.map((f) => f.rule_id)).toContain('r-t1');
    expect(res.warnings.join(' ')).toContain('wildcards');
  });

  // -- the PR description is an input like any other --------------------------

  it('clamps an oversized PR description and flags it', () => {
    const rule: Rule = {
      id: 'r-pr', name: 'pr', gdpr_article: [], action: 'review', tier: 2,
      detect: { method: 'pattern', target: 'pr_description', pattern: 'NEEDLE', mask: 'm' },
    } as unknown as Rule;
    const padded = `${'a.b-c_d'.repeat(2000)}NEEDLE`;   // NEEDLE sits past the cap
    const res = scan(ruleset([rule]), { diff: fileDiff('src/a.ts', ['x']), prDescription: padded });
    expect(res.findings).toHaveLength(0);
    expect(res.verdict).toBe('needs_review');
    expect(res.warnings.join(' ')).toContain('PR description');
  });

  it('leaves a normal-length PR description alone', () => {
    const rule: Rule = {
      id: 'r-pr', name: 'pr', gdpr_article: [], action: 'review', tier: 2,
      detect: { method: 'pattern', target: 'pr_description', pattern: 'NEEDLE', mask: 'm' },
    } as unknown as Rule;
    const res = scan(ruleset([rule]), { diff: fileDiff('src/a.ts', ['x']), prDescription: 'has a NEEDLE in it' });
    expect(res.findings.map((f) => f.rule_id)).toEqual(['r-pr']);
    expect(res.warnings.join(' ')).not.toContain('PR description');
  });

  // -- pair enumeration is bucketed, capped and budgeted ----------------------

  it('pairs before/after lines per file instead of across the whole diff', () => {
    // REWRITTEN. The first version asserted only `elapsed < 5000` and
    // `expect(res.verdict).toBeDefined()` — and an independent review ran the
    // PRE-FIX flat nested loop against this exact input: 258 ms. It passed with
    // the fix reverted, i.e. it tested nothing. It also silently tripped the
    // 200k pair ceiling, a state change the tautology could not see.
    //
    // Assert the pair SET instead, which is the thing that actually changed.
    const parsed = parseDiff(
      Array.from({ length: 20 }, (_, i) =>
        fileDiff(`src/f${i}.ts`,
          Array.from({ length: 20 }, (_, j) => `added ${j}`),
          Array.from({ length: 20 }, (_, j) => `removed ${j}`)),
      ).join('\n'),
    );
    const { pairs, truncated } = minusPlusPairs(parsed, 'same_file');
    // 20 files x 20 x 20 = 8,000 same-file pairs. The old flat loop built
    // 400 x 400 = 160,000 candidates and discarded 95% of them inside the loop.
    expect(pairs).toHaveLength(8_000);
    expect(truncated).toBe(false);
    // Every pair is within one file — the property the bucketing guarantees.
    expect(pairs.every((p) => p.minus.file === p.plus.file)).toBe(true);
  });

  it('reports pair-enumeration truncation instead of inferring it from a count', () => {
    const parsed = parseDiff(
      Array.from({ length: 40 }, (_, i) =>
        fileDiff(`src/g${i}.ts`,
          Array.from({ length: 100 }, (_, j) => `added ${j}`),
          Array.from({ length: 100 }, (_, j) => `removed ${j}`)),
      ).join('\n'),
    );
    const { pairs, truncated } = minusPlusPairs(parsed, 'same_file');
    expect(truncated).toBe(true);
    expect(pairs.length).toBe(200_000);
  });


  // -- nothing contributor-controlled restructures the check-run markdown -----

  it('neutralises a file path that would inject markdown into a warning', () => {
    const evil = 'src/[APPROVED - click to view report](https://evil.example/pwn).ts';
    const res = scan(ruleset([tier1({})]), {
      diff: fileDiff(evil, ['a'.repeat(9000)]),
    });
    const warning = res.warnings.find((w) => w.includes('longer than')) ?? '';
    // `/` `.` `-` `_` are legal in a path and survive; everything that gives
    // markdown its meaning does not.
    expect(warning).not.toContain('](');
    expect(warning).not.toContain('[APPROVED');
    expect(warning).not.toContain('https://evil.example');
    expect(warning).toContain('src/_APPROVED');
  });
});

/**
 * Second round of independent-review findings — the ones that were still open
 * after the first round's fixes, several of them introduced BY those fixes.
 */
describe('code review follow-ups (round 2)', () => {
  const tier1 = (detect: Record<string, unknown>): Rule => ({
    id: 'r-t1', name: 't1', gdpr_article: [], action: 'block', tier: 1,
    detect: {
      method: 'pattern', target: 'diff', diff_side: 'added',
      pattern: 'SECRETVALUE', mask: 'hit @ <file>:<line>', ...detect,
    },
  } as unknown as Rule);

  it.each(['*', '**', '?', '^*', '*$'])(
    'a file_scope of %j selects NOTHING, so it must warn and floor, not pass',
    (glob) => {
      // The first guard returned NEVER for these and recorded nothing. For an
      // exclusion that fails safe; for a SCOPE it inverts the field from "scan
      // everything" to "scan nothing" — a tier-1 block rule disabled, green
      // check, no trace. The comment claiming it was harmless here was backwards.
      const res = scan(ruleset([tier1({ file_scope: [glob] })]), {
        diff: fileDiff('src/a.ts', ['const x = "SECRETVALUE";']),
      });
      expect(res.verdict).toBe('needs_review');
      expect(res.warnings.join(' ')).toContain('match EVERY path');
    },
  );

  it('re-warns on a refused glob when the compile cache is already warm', () => {
    // `refusedComplexGlobs` is cleared per scan but GLOB_CACHE is not, and the
    // refusal used to be recorded only on a cache MISS. Two scans of the same
    // ruleset in one process therefore gave different verdicts — the second
    // silently passed because the cache was warm.
    const rs = () => ruleset([tier1({ exclude_paths: ['*a*a*a*a*a*aX'] })]);
    const diff = fileDiff('src/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.ts', ['const x = "SECRETVALUE";']);
    const first = scan(rs(), { diff });
    const second = scan(rs(), { diff });
    expect(first.verdict).toBe(second.verdict);
    expect(second.warnings.join(' ')).toContain('wildcards');
  });

  it.each(['**/**/*.ts', '**/__tests__/**/*.spec.ts'])(
    'accepts the ordinary glob %j — ** is ONE wildcard, not two',
    (glob) => {
      const res = scan(ruleset([tier1({ exclude_paths: [glob] })]), {
        diff: fileDiff('src/a.ts', ['const x = "SECRETVALUE";']),
      });
      expect(res.warnings.join(' ')).not.toContain('wildcards');
      expect(res.findings.map((f) => f.rule_id)).toContain('r-t1');
    },
  );

  it('clamps an oversized line in the PAIRED evaluator too', () => {
    // SEC7 bounded three of four evaluators. This one ran every regex over raw
    // line text: measured 153 SECONDS on one 300k-character removed line, with
    // verdict `pass` and zero warnings, because scannableText is also what
    // populates oversizedLineFiles.
    const paired: Rule = {
      id: 'r-pair', name: 'pair', gdpr_article: [], action: 'block', tier: 2,
      detect: {
        method: 'pattern', target: 'diff', diff_side: 'either',
        paired: {
          minus: '([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,})',
          plus: 'plaintext',
          window: 'same_hunk',
        },
        mask: 'm',
      },
    } as unknown as Rule;
    const huge = 'a.b-c_d'.repeat(43_000); // ~300k chars, no "@"
    const started = Date.now();
    const res = scan(ruleset([paired]), {
      diff: fileDiff('src/big.ts', ['now plaintext'], [huge]),
    });
    expect(Date.now() - started).toBeLessThan(6_000);
    expect(res.verdict).toBe('needs_review');
    expect(res.warnings.join(' ')).toContain('longer than');
  });

  it('floors the verdict when the budget runs out inside the LAST rule', () => {
    // budgetExceeded is set inside the evaluators but was read only at the TOP of
    // the rule loop, so a deadline hit during the final rule returned partial
    // findings and exited normally with incompleteScan still false.
    //
    // budgetMs must be NON-ZERO and the work expensive. My first attempt used
    // budgetMs: 0, which trips the top-of-loop check before any rule runs — that
    // exercises the PRE-EXISTING warning path, so it passed with this fix
    // disabled. Caught by sabotage, not by reading it.
    const backtracker: Rule = {
      id: 'r-slow', name: 'slow', gdpr_article: [], action: 'review', tier: 2,
      detect: {
        method: 'pattern', target: 'diff', diff_side: 'added',
        pattern: '([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,})',
        mask: 'm',
      },
    } as unknown as Rule;
    // 2 KB of in-class characters with no "@" — ~7 ms per line of backtracking,
    // and the budget is sampled every 64 KB, i.e. every ~32 lines.
    const line = 'a.b-c_d'.repeat(285);
    const res = scan(ruleset([backtracker]), {
      diff: fileDiff('src/a.ts', Array.from({ length: 400 }, () => line)),
      budgetMs: 50,
    });
    expect(res.verdict).toBe('needs_review');
    expect(res.warnings.join(' ')).toMatch(/budget/i);
    // Specifically the mid-rule message, not the "N of M rules did not run" one
    // that fires before a rule starts.
    expect(res.warnings.join(' ')).toContain('partway through the final rule');
  });

  it('escapes a backslash before the pipe, so \\| cannot still break a row', () => {
    const res = scan(ruleset([{ ...tier1({}), id: 'a\\|b-FORGED' } as Rule]), {
      diff: fileDiff('src/a.ts', ['const x = "SECRETVALUE";']),
    });
    const table = buildSummary(res).split('\n').filter((l) => l.startsWith('| '));
    const row = table.find((l) => l.includes('FORGED'))!;
    // Four cells means four delimiters plus the leading/trailing ones — a live
    // `|` inside the id would add a fifth and shift every later column.
    expect(row.split(/(?<!\\)\|/).length - 1).toBe(5);
  });

  it('keeps a non-ASCII path readable and renders it inert', () => {
    const res = scan(ruleset([tier1({})]), {
      diff: fileDiff('src/café/файл.ts', ['a'.repeat(9_000)]),
    });
    const warning = res.warnings.find((w) => w.includes('longer than')) ?? '';
    expect(warning).toContain('café');
    expect(warning).toContain('файл');
    expect(warning).toMatch(/`src\/café\/файл\.ts`/);
  });
});

// ---------------------------------------------------------------------------
// A DATE IS NOT AN IDENTIFIER.
//
// `CHECKSUM_CANDIDATE_RE` allows digits, letters, spaces and hyphens but NOT
// `:`, so on an ISO-8601 timestamp the match stops dead at the first colon:
// `YYYY-MM-DDTHH:MM:SSZ` yields the candidate `YYYY-MM-DDTHH`. Strip the
// punctuation and that is TEN DIGITS — exactly an SVNR's length — and roughly
// one such fragment in 26 satisfies both the mod-11 check digit and the
// embedded-DDMMYY rule, because the slice reads the timestamp's month as the
// day, its day as the month and its hour as the year.
//
// So the scanner manufactures an identifier that never appeared in the source
// text and reports it. Measured over a corpus of 6048 ordinary lines carrying
// an ISO timestamp (`created_at:`, an INSERT, a JSON field), 3.9% produced a
// false finding, every one of them an `svnr:YYYY-MM-DDTHH` fragment. The FULL
// timestamp is clean — 17 digits fails the length check — which is the tell
// that the defect is in candidate extraction, not in the validator.
//
// Non-blocking (`require_context` downgrades block->review when no PII keyword
// is nearby) but it still floors the verdict to needs_review, so a seed file of
// timestamps reports as "needs review" forever with nothing to review.
// ---------------------------------------------------------------------------
describe('checksum candidates — a date fragment is not an identifier', () => {
  const p2 = (n: number) => String(n).padStart(2, '0');

  /**
   * Search for a real timestamp whose truncated `YYYY-MM-DDTHH` digits satisfy
   * the SVNR checksum, rather than hardcoding one.
   *
   * Computed for two reasons. It keeps a checksum-valid identifier out of the repo
   * this gate scans — `data-compliance.yml` references the action by LOCAL path, so
   * a PR is graded by its OWN committed bundle and a literal would block it. And it
   * pins the test to the collision CLASS instead of one lucky instance: if the
   * validator's shape ever changes, this throws instead of silently passing.
   */
  function collidingTimestamp(): { date: string; hour: string } {
    for (let mo = 1; mo <= 12; mo++) {
      for (let d = 1; d <= 28; d++) {
        for (let h = 0; h < 24; h++) {
          const date = `2026-${p2(mo)}-${p2(d)}`;
          const hour = p2(h);
          if (isValidSvnr(`${date}T${hour}`)) return { date, hour };
        }
      }
    }
    throw new Error('no colliding timestamp found — the SVNR validator changed shape');
  }

  /** A real SVNR, written the way one actually is: 10 contiguous digits. */
  function realSvnr(): string {
    for (let n = 100; n < 1000; n++) {
      for (let c = 0; c < 10; c++) {
        const candidate = `${n}${c}${'010180'}`;
        if (isValidSvnr(candidate)) return candidate;
      }
    }
    throw new Error('no valid SVNR vector found — the validator changed shape');
  }

  const weakChecksum: Rule = {
    id: 'dc-pii-weak-checksum',
    name: 'weak-checksum PII',
    gdpr_article: ['Art 5(1)(c)', 'Art 32'],
    action: 'block',
    tier: 1,
    detect: {
      method: 'checksum',
      target: 'diff',
      diff_side: 'added',
      validator: ['svnr', 'steuer_id', 'credit_card'],
      allowlist: 'synthetic',
      require_context: '(?i)(svnr|sozialversicherung|steuer-?id|tax-?id|iban|card|kreditkarte)',
      mask: 'SVNR / Steuer-ID / card number (masked)',
    },
  };
  const hits = (line: string) =>
    scan(ruleset([weakChecksum]), { diff: fileDiff('supabase/seeds/e2e_orders.sql', [line]) }).findings;

  it('the collision is real — the premise of every case below', () => {
    const { date, hour } = collidingTimestamp();
    // The truncated fragment validates...
    expect(isValidSvnr(`${date}T${hour}`)).toBe(true);
    // ...while the full timestamp does not, because 17 digits is not 10.
    expect(isValidSvnr(`${date}T${hour}:00:00Z`)).toBe(false);
  });

  it('does not report an ISO timestamp as an SVNR', () => {
    const { date, hour } = collidingTimestamp();
    expect(hits(`  created_at: '${date}T${hour}:00:00Z',`)).toEqual([]);
  });

  it('does not report the space-separated timestamp form either', () => {
    const { date, hour } = collidingTimestamp();
    // `CHECKSUM_CANDIDATE_RE` includes the space, so this cuts at the colon the
    // same way and yields the identical ten digits.
    expect(hits(`INSERT INTO events (at) VALUES ('${date} ${hour}:00:00');`)).toEqual([]);
  });

  it('does not report a bare calendar date', () => {
    const { date } = collidingTimestamp();
    expect(hits(`  effective_from: '${date}',`)).toEqual([]);
  });

  it('does not report a date padded across an aligned column', () => {
    // Still suppressed: the aligned cell IS cut short by `:00:00`, so the
    // truncation evidence is present.
    const { date, hour } = collidingTimestamp();
    expect(hits(`| ${date}  ${hour}:00:00 | ok |`)).toEqual([]);
  });

  it('DOES report a dated filename — no truncation evidence, so it fails safe', () => {
    // Deliberate, and the inverse of what an earlier cut of this guard did.
    // `backup-<date>-<hh>.sql` is not cut short by a time separator, so nothing
    // proves it is a timestamp rather than a ten-digit identifier wearing date
    // punctuation — which is exactly the shape a real SVNR takes. Suppressing it
    // is what opened the bypass below. A little residual noise on dated filenames
    // is the price, and it is the right way round for a security control.
    const { date, hour } = collidingTimestamp();
    expect(hits(`  path: 'backup-${date}-${hour}.sql',`)).toHaveLength(1);
  });

  /**
   * A real SVNR whose 4-2-2-2 layout ALSO parses as a valid calendar date + hour —
   * the hardest case, and the one the component sanity-check alone cannot catch.
   * Reading `SSSC-DD-MM-YY` as a date makes the birth DAY the month (so it must be
   * <= 12) and the birth YEAR the hour (so it must be <= 23). Searched, not written.
   */
  function svnrThatAlsoReadsAsADate(): string {
    for (let n = 100; n < 1000; n++) {
      for (let c = 0; c < 10; c++) {
        for (let bd = 1; bd <= 12; bd++) {
          for (let bm = 1; bm <= 12; bm++) {
            for (let by = 0; by <= 23; by++) {
              const cand = `${n}${c}${p2(bd)}${p2(bm)}${p2(by)}`;
              if (cand.length === 10 && isValidSvnr(cand)) return cand;
            }
          }
        }
      }
    }
    throw new Error('no SVNR found whose 4-2-2-2 layout is also a valid date');
  }
  const four222 = (v: string, sep: string) =>
    `${v.slice(0, 4)}-${v.slice(4, 6)}-${v.slice(6, 8)}${sep}${v.slice(8, 10)}`;

  // BYPASS REGRESSION. `DATE_LIKE_RE` covers at most 4+2+2+2 = ten digits and an
  // SVNR is exactly ten, so a digits-only "is it a date" test suppressed EVERY
  // SVNR written in date punctuation — 48 of 48 valid vectors went from a
  // merge-blocking `fail` to a clean `pass`. These three layouts are that bypass.
  it.each(['-', ' ', 'T'])(
    'STILL reports an SVNR written 4-2-2-2 with %j — the bypass must stay closed',
    (sep) => {
      expect(hits(`INSERT INTO patients (svnr) VALUES ('${four222(realSvnr(), sep)}');`))
        .toHaveLength(1);
    },
  );

  it('STILL reports one whose date reading is entirely valid', () => {
    // Component validation cannot save this one — only the truncation evidence can.
    expect(hits(`INSERT INTO patients (svnr) VALUES ('${four222(svnrThatAlsoReadsAsADate(), '-')}');`))
      .toHaveLength(1);
  });

  it('STILL reports a real SVNR — the guard must not disarm the rule', () => {
    expect(hits(`const svnr = '${realSvnr()}';`)).toHaveLength(1);
  });

  it('STILL reports a real identifier sharing a line with a timestamp', () => {
    const { date, hour } = collidingTimestamp();
    // The guard keys on whether the candidate's digits come ENTIRELY from the
    // date. Here they do not, so the rule must still fire on the SVNR.
    expect(hits(`INSERT INTO p (svnr, at) VALUES ('${realSvnr()}', '${date}T${hour}:00:00Z');`))
      .toHaveLength(1);
  });
});
