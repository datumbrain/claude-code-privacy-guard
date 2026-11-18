/**
 * Core type definitions for privacy findings and rules
 */

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type Category =
  | 'pii'
  | 'secret'
  | 'credential'
  | 'internal-data'
  | 'financial'
  | 'auth-token';

export type RedactionStrategy =
  | 'full-mask'      // Replace entire value with placeholder
  | 'partial-mask'   // Show first/last chars, mask middle
  | 'token-replace'  // Replace with typed token like <API_KEY>
  | 'semantic';      // Replace with semantic placeholder like <EMAIL_1>

export interface DetectionRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: Category;
  pattern: string | RegExp;
  examples: string[];
  redactionStrategy: RedactionStrategy;
  enabled: boolean;
  /**
   * Optional post-match check. The scanner runs it on every regex match and
   * drops the match when it returns false, so a rule can pair a cheap
   * candidate regex with a precise validator (Luhn checksum, entropy
   * threshold, ...). `groups` is the raw exec result, so the validator can read
   * capture groups. Not serialized: rules loaded from JSON never have one.
   */
  validate?: (match: string, groups: RegExpExecArray) => boolean;
  /**
   * Regex flags for a string `pattern` (e.g. "i"). "g" is always added by the
   * scanner. Ignored when `pattern` is a RegExp. Serializable, unlike
   * `validate`, so rules loaded from JSON (and the on-disk rule cache) can
   * carry it.
   */
  flags?: string;
  /**
   * Minimum Shannon entropy (bits/char) the secret must have, gitleaks-style.
   * The secret is capture group `secretGroup` when set, otherwise the first
   * non-empty capture group, otherwise the whole match. Serializable.
   */
  minEntropy?: number;
  secretGroup?: number;
  /**
   * gitleaks-style prefilter: when set, the rule only runs if the scanned text
   * contains at least one of these (case-insensitive). Cuts false positives
   * from broad patterns (e.g. a bare 40-hex token rule that only means
   * anything near "sourcegraph"/"sgp_") and skips most rules on most prompts.
   * Serializable.
   */
  keywords?: string[];
  /**
   * Report only the secret (capture group `secretGroup`, else the first
   * non-empty group) as the finding span, not the whole match. gitleaks
   * patterns include surrounding context and a terminator such as a closing
   * quote; without this the redaction would eat that context. Serializable.
   */
  secretOnly?: boolean;
}

export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  category: Category;
  match: string;
  startIndex: number;
  endIndex: number;
  redactedValue: string;
  context?: string; // Surrounding text for display
}

export interface ScanResult {
  findings: Finding[];
  originalText: string;
  redactedText: string;
  riskScore: number;
  hasHighRisk: boolean;
  hasCriticalRisk: boolean;
  summary: {
    [key in Category]?: number;
  };
}

export type PromptGuardMode = 'block' | 'redact' | 'warn';

export interface PrivacyGuardConfig {
  enabled: boolean;
  mode: PromptGuardMode;
  allowedDomains: string[];
  disabledRules: string[];
  externalRulesJsonPath?: string;
  externalRulesMode?: 'coding-only' | 'all';
  allowedValues: string[];
  allowedPatterns: string[];
  piiProfile?: PiiProfile;
  toolGuard?: ToolGuardConfig;
}

/** Tool I/O scanning (PreToolUse / PostToolUse hooks). */
export interface ToolGuardConfig {
  /** Master switch for both tool hooks. Default true. */
  enabled?: boolean;
  /** What to do before a tool call that would expose secrets. Default "ask". */
  preToolUse?: 'ask' | 'deny' | 'off';
  /** What to do when tool output contained secrets. Default "warn". */
  postToolUse?: 'warn' | 'off';
  /** Extra sensitive path globs, added to the built-in list. */
  sensitivePaths?: string[];
  /** Path globs that are never treated as sensitive. */
  allowedPaths?: string[];
  /** Max characters of a file or tool output that get scanned. Default 200000. */
  maxScanBytes?: number;
}

/**
 * Opt-in PII detectors. Every flag defaults to off so the tool stays
 * coding-focused unless a user asks for more.
 */
export interface PiiProfile {
  creditCard?: boolean;
  ssn?: boolean;
  phone?: boolean;
}
