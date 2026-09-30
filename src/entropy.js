/**
 * Shannon entropy utilities used to spot high-entropy strings that look like
 * machine-generated secrets even when they don't match a known provider prefix.
 */

/** Shannon entropy in bits per character. Max ~6.5 for base64-ish alphabets. */
export function shannon(input) {
  if (!input.length) return 0;
  const freq = new Map();
  for (const ch of input) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / input.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Candidate string is base64/hex shaped (the alphabets most secret formats use).
 * Deliberately permissive: this is a pre-filter, entropy does the real work.
 */
const CANDIDATE = /^[A-Za-z0-9+/=_-]{16,}$/;

const HEX_ONLY = /^[0-9a-f]+$/i;

/**
 * Long hex strings are legitimately high-entropy (checksums, hashes, git SHAs).
 * They are not secrets, so we require a much higher bar before flagging them.
 */
export function looksRandom(candidate, { minEntropy = 3.3, hexEntropy = 3.85 } = {}) {
  if (!CANDIDATE.test(candidate)) return false;
  const threshold = HEX_ONLY.test(candidate) ? hexEntropy : minEntropy;
  return shannon(candidate) >= threshold;
}

/** Shannon entropy of a 0..1 range, handy for scoring findings in reports. */
export function normalizedEntropy(input) {
  return Math.min(1, shannon(input) / 5);
}
