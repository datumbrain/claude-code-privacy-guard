/**
 * Validation for allowlist entries coming from the rules-picker UI. The
 * scanner already skips bad allowedPatterns at load time (with a console
 * warning nobody sees), so the UI validates up front instead - a pattern that
 * would be silently dropped should never make it into the config file.
 */

import safeRegex from 'safe-regex2';

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
export function validateAllowedPattern(pattern: string): string | null {
  if (!pattern) return 'Pattern must not be empty';

  try {
    new RegExp(pattern);
  } catch (error) {
    return `Invalid regex: ${(error as Error).message}`;
  }

  if (!safeRegex(pattern)) {
    return 'Regex looks unsafe (possible catastrophic backtracking)';
  }

  return null;
}

/**
 * Normalizes and validates the three allowlists from a /save payload. Throws
 * on anything the scanner could not use, so a failed save leaves the existing
 * config untouched.
 */
export function parseAllowlists(input: {
  allowedDomains?: unknown;
  allowedValues?: unknown;
  allowedPatterns?: unknown;
}): AllowlistPayload {
  const allowedDomains = asStringArray(input.allowedDomains, 'allowedDomains')
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean);
  const allowedValues = asStringArray(input.allowedValues, 'allowedValues').filter(Boolean);
  const allowedPatterns = asStringArray(input.allowedPatterns, 'allowedPatterns').filter(Boolean);

  for (const pattern of allowedPatterns) {
    const error = validateAllowedPattern(pattern);
    if (error) throw new Error(`allowedPatterns entry ${JSON.stringify(pattern)}: ${error}`);
  }

  return {
    allowedDomains: dedupe(allowedDomains),
    allowedValues: dedupe(allowedValues),
    allowedPatterns: dedupe(allowedPatterns),
  };
}

function asStringArray(value: unknown, field: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) {
    throw new Error(`${field} must be a string array`);
  }
  return value as string[];
}

function dedupe(values: string[]): string[] {
  return [...new Set(values)];
}
