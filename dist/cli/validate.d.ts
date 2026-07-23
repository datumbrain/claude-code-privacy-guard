/**
 * Validation for allowlist entries coming from the rules-picker UI. The
 * scanner already skips bad allowedPatterns at load time (with a console
 * warning nobody sees), so the UI validates up front instead - a pattern that
 * would be silently dropped should never make it into the config file.
 */
export interface AllowlistPayload {
    allowedDomains: string[];
    allowedValues: string[];
    allowedPatterns: string[];
}
/**
 * Returns an error message for a single allowedPatterns entry, or null when
 * it's fine. Mirrors ScannerEngine.compileAllowedPatterns so the UI accepts
 * exactly the patterns the scanner would actually use.
 */
export declare function validateAllowedPattern(pattern: string): string | null;
/**
 * Normalizes and validates the three allowlists from a /save payload. Throws
 * on anything the scanner could not use, so a failed save leaves the existing
 * config untouched.
 */
export declare function parseAllowlists(input: {
    allowedDomains?: unknown;
    allowedValues?: unknown;
    allowedPatterns?: unknown;
}): AllowlistPayload;
