/**
 * Masking helpers.
 *
 * CRITICAL INVARIANT: the raw value passed in must NEVER appear verbatim in the
 * returned string. Everything that leaves this module (and therefore the
 * Action — into check-run bodies and the POST payload) is masked. The scanner
 * and reporter only ever handle the output of `maskFinding`.
 */

/**
 * Mask an email to `j***@***.com` shape:
 *  - first char of local part, then `***`
 *  - domain reduced to `***` plus the public suffix (last dotted segment)
 *
 * Non-email input falls back to `maskGeneric`.
 */
export function maskEmail(raw: string): string {
  if (typeof raw !== 'string') return '***';
  const at = raw.indexOf('@');
  if (at <= 0 || at === raw.length - 1) return maskGeneric(raw);

  const local = raw.slice(0, at);
  const domain = raw.slice(at + 1);

  const firstChar = local[0] ?? '';
  const dot = domain.lastIndexOf('.');
  const tld = dot >= 0 && dot < domain.length - 1 ? domain.slice(dot + 1) : '';

  const maskedLocal = `${firstChar}***`;
  const maskedDomain = tld ? `***.${tld}` : '***';
  return `${maskedLocal}@${maskedDomain}`;
}

/**
 * Generic masker: reveals at most the first character and replaces the rest
 * with `***`. For very short strings (<=1 char) reveals nothing. The output is
 * length-independent so it never leaks how long the secret was.
 */
export function maskGeneric(raw: string): string {
  if (typeof raw !== 'string' || raw.length === 0) return '***';
  const trimmed = raw.trim();
  if (trimmed.length <= 1) return '***';
  return `${trimmed[0]}***`;
}

/**
 * Build the masked evidence string for a finding.
 *
 * Shape: `<typeLabel> @ <file>:<line>` — e.g. `IBAN-pattern @ fixtures/users.sql:88`.
 *
 * `type` is the rule's masking hint (DetectSpec.mask), which is a category
 * label like "IBAN-pattern" — NOT the raw value. The raw value is only used to
 * derive a masked token for context and is never emitted verbatim. We
 * additionally guard at the end: if the raw value somehow appears in the
 * assembled string, we strip the value token entirely.
 */
export function maskFinding(
  type: string,
  rawValue: string,
  file: string,
  line: number | null | undefined,
): string {
  const safeType = sanitizeLabel(type);
  const safeFile = sanitizeLabel(file);
  const loc = line === null || line === undefined ? safeFile : `${safeFile}:${line}`;

  let evidence = `${safeType} @ ${loc}`;

  // Defense in depth: ensure the raw value never survives into the output.
  if (typeof rawValue === 'string' && rawValue.length > 0) {
    const raw = rawValue.trim();
    if (raw.length > 0 && evidence.includes(raw)) {
      // Should be impossible given the construction above, but never leak.
      evidence = evidence.split(raw).join('***');
    }
  }
  return evidence;
}

/** Separates the mask part from the location part of masked evidence (see maskFinding). */
const EVIDENCE_SEPARATOR = ' @ ';

/**
 * Break every run of 8 or more digits IN THE LOCATION PART of masked evidence into groups of four joined by
 * U+00B7, e.g. `m @ supabase/migrations/20261003090000_x.sql` -> `m @ supabase/migrations/2026·1003·0900·00_x.sql`.
 *
 * Masked evidence is `<mask> @ <location>`. ci-scan-result refuses any stored string holding an 8+ digit run
 * (looksUnmasked: such a run reads as a raw IBAN, phone number or card), and the location carries the FILE PATH,
 * so one finding in a timestamped file (every Supabase migration) made an older server reject the whole post.
 *
 * ONLY the part after the FIRST ` @ ` is transformed. The mask part is never touched: should it ever carry an
 * unmasked digit run (a scanner bug), it must reach the server as it is so the server backstop can refuse it,
 * instead of being disguised as a grouped run. Evidence with no ` @ ` has no location and is returned unchanged.
 * Applied to the POSTED evidence only (report.ts): the check run keeps the real path. Every digit is kept, so two
 * paths never collapse into one.
 */
export function groupLongDigitRuns(value: string): string {
  const at = value.indexOf(EVIDENCE_SEPARATOR);
  if (at < 0) return value;
  const cut = at + EVIDENCE_SEPARATOR.length;
  return value.slice(0, cut) + value.slice(cut).replace(/\d{8,}/g, (run) => run.replace(/(\d{4})(?=\d)/g, '$1\u00b7'));
}

/**
 * Strip newlines/control chars and clamp length so a crafted label or path can
 * neither break the markdown summary nor smuggle large amounts of raw text.
 */
function sanitizeLabel(value: string): string {
  if (typeof value !== 'string') return '***';
  // `|` and backticks matter as much as newlines here: masked evidence embeds a
  // contributor-controlled FILE PATH, and it is interpolated straight into a
  // markdown TABLE cell in checkRun.ts. A path containing `|` splits the row and
  // shifts every later column, so the rendered table stops meaning what it says.
  // An independent review demonstrated it with a file literally named `a|b\`c.ts`.
  const cleaned = value.replace(/[\r\n\t]+/g, ' ').replace(/[|`]/g, ' ').trim();
  if (cleaned.length === 0) return '***';
  return cleaned.length > 200 ? `${cleaned.slice(0, 200)}…` : cleaned;
}
