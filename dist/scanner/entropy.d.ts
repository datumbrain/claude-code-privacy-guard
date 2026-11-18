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
export declare const ENTROPY_CONFIG: {
    /** Candidate values shorter than this are never flagged. */
    readonly minLength: 20;
    /** Shannon entropy (bits/char) required for pure-hex values (32+ char keys). */
    readonly hexMinEntropy: 3;
    /** Shannon entropy (bits/char) required for everything else (base64-ish). */
    readonly mixedMinEntropy: 3.8;
    /** Keywords that must precede the value (as a word fragment, e.g. `api_key`, `authToken`). */
    readonly keywords: readonly ["api[_-]?key", "apikey", "access[_-]?key", "secret", "token", "passw(?:or)?d", "passwd", "credential", "private[_-]?key", "auth", "bearer"];
};
/** Shannon entropy of a string, in bits per character. */
export declare function shannonEntropy(value: string): number;
/**
 * Decide whether a candidate value looks like a random secret. Exported so the
 * thresholds can be unit-tested directly.
 */
export declare function looksLikeHighEntropySecret(value: string): boolean;
export declare const ENTROPY_RULE: DetectionRule;
