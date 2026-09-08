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
