/**
 * Checksum validators. Every function returns a plain boolean and never throws
 * on malformed input — a non-conforming string simply yields `false`.
 *
 * These exist so the scanner can demand a real checksum match (not just a
 * loose regex hit) before escalating a finding to `block`. That keeps the false
 * positive rate low: a 16-digit string that fails Luhn+IIN is not a card.
 */
import { isValidIBAN } from 'ibantools';
import cardValidator from 'card-validator';

/** Strip everything that is not a digit. */
function digitsOnly(value: string): string {
  return value.replace(/\D/g, '');
}

/**
 * IBAN — delegates to ibantools' spec-aware validator (country length +
 * mod-97 check). Whitespace is tolerated; ibantools normalises internally,
 * but we strip spaces defensively so "AT61 1904 ..." validates.
 */
export function isValidIban(value: string): boolean {
  if (typeof value !== 'string') return false;
  const normalised = value.replace(/\s+/g, '').toUpperCase();
  return isValidIBAN(normalised);
}

/**
 * Credit card — requires a real IIN/network match AND a passing Luhn, via
 * card-validator. A bare Luhn-valid 16-digit string with no recognised IIN
 * (e.g. "0000 0000 0000 0000") must NOT validate.
 */
export function isValidCreditCard(value: string): boolean {
  if (typeof value !== 'string') return false;
  const digits = digitsOnly(value);
  if (digits.length < 12 || digits.length > 19) return false;
  const result = cardValidator.number(digits);
  // isValid requires both Luhn and a matched card type (IIN).
  return Boolean(result.isPotentiallyValid && result.isValid && result.card);
}

const SVNR_WEIGHTS = [3, 7, 9, 0, 5, 8, 4, 2, 1, 6];

/**
 * Austrian Sozialversicherungsnummer (SVNR).
 *
 * Layout: 10 digits. Positions 1-3 = running number, position 4 = check digit,
 * positions 5-10 = birth date as DDMMYY.
 *
 * Check digit = ( Σ digit_i * weight_i ) mod 11, summed over the OTHER nine
 * digits (the check-digit position contributes weight 0). If the remainder is
 * 10 the number is invalid (never issued).
 *
 * We additionally require the embedded DDMMYY to be a real calendar date —
 * this is what gates random 10-digit strings that happen to satisfy mod-11.
 */
export function isValidSvnr(value: string): boolean {
  if (typeof value !== 'string') return false;
  const digits = digitsOnly(value);
  if (digits.length !== 10) return false;

  const nums = digits.split('').map((d) => Number(d));
  const checkDigit = nums[3];

  let sum = 0;
  for (let i = 0; i < 10; i++) {
    sum += nums[i] * SVNR_WEIGHTS[i];
  }
  const remainder = sum % 11;
  if (remainder === 10) return false;
  if (remainder !== checkDigit) return false;

  // Validate embedded birth date DD MM YY in positions 5-10 (indices 4..9).
  const dd = nums[4] * 10 + nums[5];
  const mm = nums[6] * 10 + nums[7];
  const yy = nums[8] * 10 + nums[9];
  return isRealDdMmYy(dd, mm, yy);
}

/** True when DD/MM/YY forms a real calendar date (century-agnostic). */
function isRealDdMmYy(dd: number, mm: number, yy: number): boolean {
  if (mm < 1 || mm > 12) return false;
  if (dd < 1 || dd > 31) return false;
  // Resolve the two-digit year against both plausible centuries so leap-day
  // (29 Feb) validation works regardless of issue era.
  const candidateYears = [1900 + yy, 2000 + yy];
  return candidateYears.some((year) => {
    const daysInMonth = new Date(year, mm, 0).getDate();
    return dd <= daysInMonth;
  });
}

/**
 * German Steuer-Identifikationsnummer (Steuer-ID).
 *
 * 11 digits, last digit is an ISO/IEC 7064 MOD 11,10 check digit over the
 * first 10. The leading digit must not be 0 (not issued), which we enforce.
 */
export function isValidSteuerId(value: string): boolean {
  if (typeof value !== 'string') return false;
  const digits = digitsOnly(value);
  if (digits.length !== 11) return false;
  if (digits[0] === '0') return false;

  const nums = digits.split('').map((d) => Number(d));
  const expected = nums[10];

  // ISO/IEC 7064 MOD 11,10
  let product = 10;
  for (let i = 0; i < 10; i++) {
    let sum = (nums[i] + product) % 10;
    if (sum === 0) sum = 10;
    product = (sum * 2) % 11;
  }
  let checkDigit = 11 - product;
  if (checkDigit === 10) checkDigit = 0;

  return checkDigit === expected;
}

/** Map a contract validator name to its implementation. */
export const VALIDATORS: Record<string, (value: string) => boolean> = {
  iban: isValidIban,
  credit_card: isValidCreditCard,
  svnr: isValidSvnr,
  steuer_id: isValidSteuerId,
};

/** Run the named validators; returns the first name that validates, or null. */
export function runValidators(
  names: string[] | undefined,
  value: string,
): string | null {
  if (!names || names.length === 0) return null;
  for (const name of names) {
    const fn = VALIDATORS[name];
    if (fn && fn(value)) return name;
  }
  return null;
}
