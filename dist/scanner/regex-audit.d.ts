/**
 * Catastrophic-backtracking probe for detection regexes.
 *
 * safe-regex2 only catches nested-quantifier shapes like (a+)+. It misses the
 * far more common quadratic case: an unbounded class that can start a match
 * at every character of a long run and then scans to the end of it before
 * failing (e.g. /\b[\w.-]+@.../ on "1-1-1-..."). Each scan is linear, but one
 * per start position makes the whole thing O(n^2), which at 200k characters is
 * tens of seconds and blows the hook's timeout.
 *
 * This probe times a regex against repeated short "shapes" built from the
 * characters such patterns typically consume. A linear regex finishes each
 * probe in well under a millisecond; a quadratic one takes tens to hundreds.
 *
 * It is too slow to run at hook time, so it is used by the gitleaks conversion
 * script (to drop slow rules before they ship) and by the test suite (to keep
 * every shipped rule honest).
 */
/** Short fragments repeated to build adversarial inputs. */
export declare const PROBE_SHAPES: readonly ["a", "A", "1", "-", ".", "_", " ", "\t", "=", "/", ":", "\"", "'", "@", "%", "+", "\\", "<", ">", "1-", "a.", "a@", "a-", "a_", "a ", "a:", "a=", "a/", "a\"", "A1", "ab12", "a.b@", "@a.", "--", "KEY=", "key=", "token ", "token=", "secret:", "sk-", "eyJ", "xox", "ghp_", "AKIA", "-----", "+1 ", "1 ", "123-45-", "0x", "://", "a://", "Bearer ", "password=", "api_key: ", "\"key\": \""];
export interface ProbeResult {
    /** Slowest probe time in milliseconds. */
    worstMs: number;
    /** The shape that produced it. */
    shape: string;
}
/**
 * Run `pattern` (cloned with the g flag) over each probe shape repeated to
 * `length` characters and report the slowest one.
 */
export declare function probeRegex(pattern: RegExp, length?: number): ProbeResult;
export interface GrowthVerdict {
    quadratic: boolean;
    shape: string;
    /** Slowest single probe at the base length, in ms. */
    worstMs: number;
    /** Time ratio for a 4x longer input on the slowest shape (about 4 if linear, 16 if quadratic). */
    ratio?: number;
}
/**
 * Decide whether a regex goes quadratic, robustly on slow or noisy machines
 * (shared CI runners can stall a single run by 100+ ms).
 *
 * A fast first pass probes every shape once. Only if the slowest one exceeds
 * `budgetMs` is that shape re-measured, taking the fastest of several runs at
 * `length / 2` and `length * 2`. A linear regex grows about 4x over that 4x
 * input increase; a quadratic one about 16x. Growth above `maxRatio` (with a
 * meaningful absolute time) is the verdict, not a single slow run.
 */
export declare function checkGrowth(pattern: RegExp, { length, budgetMs, maxRatio }?: {
    length?: number;
    budgetMs?: number;
    maxRatio?: number;
}): GrowthVerdict;
