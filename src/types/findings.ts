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
