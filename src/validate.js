/**
 * Checksum / structural validation for high-confidence detections.
 *
 * A detector pattern alone is not proof: regexes lie. These functions let a rule
 * report `confidence: 'verified'` only when the value actually checks out,
 * which keeps false positives down without hiding real leaks.
 */

/** Luhn mod-10, used by every major card network. */
export function luhn(digits) {
  const clean = digits.replace(/[\s-]/g, '');
  if (!/^\d{12,19}$/.test(clean)) return false;
  let sum = 0;
  let double = false;
  for (let i = clean.length - 1; i >= 0; i--) {
    let d = clean.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

/**
 * Taiwan national ID (身分證字號) checksum.
 * Format: 1 letter + 1 type digit (1/2 domestic, 8/9 foreign) + 8 digits.
 * Weights are 1,9,8,7,6,5,4,3,2 and the final digit is the mod-10 complement.
 */
export function taiwanNationalId(value) {
  const id = value.trim().toUpperCase();
  if (!/^[A-Z][1289]\d{8}$/.test(id)) return false;

  const letterValue = id.charCodeAt(0) - 64; // A=1 … Z=26
  const digits = id
    .slice(1)
    .split('')
    .map(Number);
  const weights = [1, 9, 8, 7, 6, 5, 4, 3, 2];

  const total = digits.reduce((sum, d, i) => sum + d * weights[i], 0);
  const check = (10 - (total % 10)) % 10;
  return check === digits[8] && letterValue >= 1 && letterValue <= 26;
}

/** Structure check: three base64url segments with a decodable JSON header. */
export function isJwt(token) {
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  if (parts.some((p) => p.length < 8)) return false;
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    return typeof header.alg === 'string';
  } catch {
    return false;
  }
}

/** Expired JWTs leak far less value; surfaced separately so users can triage. */
export function jwtExpiry(token) {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
    if (typeof payload.exp !== 'number') return null;
    return new Date(payload.exp * 1000);
  } catch {
    return null;
  }
}

/** RFC-ish email shape check. Deliberately tight: we only redact real addresses. */
export function isEmail(value) {
  if (value.length > 254) return false;
  if (value.includes('..')) return false;
  return /^[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$/.test(value);
}
