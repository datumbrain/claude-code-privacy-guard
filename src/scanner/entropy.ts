/**
 * Entropy-based detection of unknown-prefix secrets.
 *
 * Pattern rules only know vendor prefixes (sk-, xox-, ...). A random token
 * from a vendor we don't know sails past them. This layer catches it the way
 * gitleaks does: a keyword in context (token, api_key, secret, ...) AND a
 * high-entropy value. Entropy alone is never enough - UUIDs, hashes and git
 * SHAs are high-entropy too - so the regex below only produces candidates that
 * sit right after a secret-ish keyword, and the validator then applies the
 * entropy gate.
 *
 * Everything tunable lives in ENTROPY_CONFIG so thresholds can be adjusted
 * without touching the logic.
 */

import { DetectionRule } from '../types/findings.js';

export const ENTROPY_CONFIG = {
  /** Candidate values shorter than this are never flagged. */
  minLength: 20,
  /** Shannon entropy (bits/char) required for pure-hex values (32+ char keys). */
  hexMinEntropy: 3.0,
  /** Shannon entropy (bits/char) required for everything else (base64-ish). */
  mixedMinEntropy: 3.8,
  /** Keywords that must precede the value (as a word fragment, e.g. `api_key`, `authToken`). */
  keywords: [
    'api[_-]?key',
    'apikey',
    'access[_-]?key',
    'secret',
    'token',
    'passw(?:or)?d',
    'passwd',
    'credential',
    'private[_-]?key',
    'auth',
    'bearer',
  ],
} as const;

/** Shannon entropy of a string, in bits per character. */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const HEX_ONLY = /^[0-9a-f]+$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PLACEHOLDER = /^(?:x+|\*+|\.+|-+|_+|0+|1+|a+|y?our[_-].*|.*example.*|.*placeholder.*|.*changeme.*|.*redacted.*)$/i;

/**
 * Decide whether a candidate value looks like a random secret. Exported so the
 * thresholds can be unit-tested directly.
 */
export function looksLikeHighEntropySecret(value: string): boolean {
  if (value.length < ENTROPY_CONFIG.minLength) return false;
  if (UUID.test(value) || PLACEHOLDER.test(value)) return false;
  // Random tokens mix letters and digits; plain words and identifiers don't.
  if (!/[A-Za-z]/.test(value) || !/\d/.test(value)) return false;
  // More than one path separator means a file path or URL fragment, not a token.
  if ((value.match(/\//g) ?? []).length > 1) return false;

  const entropy = shannonEntropy(value);
  const threshold = HEX_ONLY.test(value)
    ? ENTROPY_CONFIG.hexMinEntropy
    : ENTROPY_CONFIG.mixedMinEntropy;
  return entropy >= threshold;
}

// keyword (+ short suffix such as `_value`/`Token`) , then `:` / `=` / "is",
// optional quote, then the candidate value (captured). Bounded quantifiers
// only, so the pattern is linear on large prompts.
const KEYWORD_ALTERNATION = ENTROPY_CONFIG.keywords.join('|');
const HIGH_ENTROPY_PATTERN = new RegExp(
  `(?<![A-Za-z0-9])(?:${KEYWORD_ALTERNATION})[A-Za-z0-9_-]{0,20}["'\`]?(?:[ \\t]*[:=][ \\t]*|[ \\t]+(?:is|are|was)[ \\t]+)["'\`]?([A-Za-z0-9+/_=-]{${ENTROPY_CONFIG.minLength},256})(?![A-Za-z0-9+/_=-])`,
  'gi'
);

export const ENTROPY_RULE: DetectionRule = {
  id: 'high-entropy-secret',
  title: 'High-Entropy Secret',
  description:
    'Detects random-looking tokens with no known vendor prefix when they follow a secret keyword (token, api_key, secret, password, ...)',
  severity: 'high',
  category: 'secret',
  pattern: HIGH_ENTROPY_PATTERN,
  examples: ['token: q8Zx3vL0pRt7NwB2kYh9Fd4JsMa6Ue1C'],
  redactionStrategy: 'token-replace',
  enabled: true,
  validate: (_match, groups) => looksLikeHighEntropySecret(groups[1] ?? ''),
};
