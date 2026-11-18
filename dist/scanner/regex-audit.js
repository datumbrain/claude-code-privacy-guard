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
export const PROBE_SHAPES = [
    'a', 'A', '1', '-', '.', '_', ' ', '\t', '=', '/', ':', '"', "'", '@', '%', '+', '\\', '<', '>',
    '1-', 'a.', 'a@', 'a-', 'a_', 'a ', 'a:', 'a=', 'a/', 'a"', 'A1', 'ab12', 'a.b@', '@a.', '--',
    'KEY=', 'key=', 'token ', 'token=', 'secret:', 'sk-', 'eyJ', 'xox', 'ghp_', 'AKIA', '-----', '+1 ',
    '1 ', '123-45-', '0x', '://', 'a://', 'Bearer ', 'password=', 'api_key: ', '"key": "',
];
/**
 * Run `pattern` (cloned with the g flag) over each probe shape repeated to
 * `length` characters and report the slowest one.
 */
export function probeRegex(pattern, length = 20_000) {
    const flags = pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g';
    let worstMs = 0;
    let shape = '';
    for (const s of PROBE_SHAPES) {
        const input = s.repeat(Math.ceil(length / s.length));
        const re = new RegExp(pattern.source, flags);
        const start = process.hrtime.bigint();
        let m;
        let guard = 0;
        while ((m = re.exec(input)) !== null) {
            if (m[0].length === 0)
                re.lastIndex += 1;
            if (++guard > length)
                break;
        }
        const ms = Number(process.hrtime.bigint() - start) / 1e6;
        if (ms > worstMs) {
            worstMs = ms;
            shape = s;
        }
    }
    return { worstMs, shape };
}
