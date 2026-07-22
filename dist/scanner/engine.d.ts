/**
 * Core scanning engine
 */
import { DetectionRule, ScanResult } from '../types/findings.js';
export interface ScannerOptions {
    /**
     * Email domains to allowlist. Findings from the `email-address` rule whose
     * domain matches one of these (exact match or a subdomain) are dropped
     * before scoring, so documented example addresses like `user@example.com`
     * don't trip the guard. Matching is case-insensitive.
     */
    allowedDomains?: string[];
    /**
     * Exact finding values that are always allowed, regardless of which rule
     * matched (e.g. a documented example key). Compared against the raw
     * matched text, case-sensitively.
     */
    allowedValues?: string[];
    /**
     * Regex patterns; a finding whose matched text satisfies any of these is
     * always allowed, regardless of which rule matched. Each pattern is vetted
     * before use and skipped with a console warning if it fails to compile or
     * looks prone to catastrophic backtracking.
     */
    allowedPatterns?: string[];
    /**
     * Maximum number of characters scanned by the rule engine. Text beyond this
     * length is appended to the output untouched (and unscanned). Defaults to
     * {@link DEFAULT_MAX_SCAN_LENGTH}.
     */
    maxScanLength?: number;
}
export declare class PrivacyScanner {
    private rules;
    private counterMap;
    private allowedDomains;
    private allowedValues;
    private allowedPatterns;
    private maxScanLength;
    constructor(rules?: DetectionRule[], options?: ScannerOptions);
    /**
     * Compile allowedPatterns entries, skipping (with a console warning) any
     * that fail to parse as a regex or look prone to catastrophic backtracking -
     * these come from user config, but they still run against every scanned
     * prompt, so an unsafe one deserves the same treatment as an external rule.
     */
    private compileAllowedPatterns;
    /**
     * Whether a finding should be suppressed by an allowlist: the email domain
     * allowlist (email findings only), an exact-value allowlist, or a regex
     * pattern allowlist (both of the latter two apply to any rule).
     */
    private isAllowlisted;
    /**
     * Whether a finding is suppressed by the domain allowlist. Only applies to
     * email findings: an allowlisted domain matches the exact domain or any
     * subdomain of it (e.g. `example.com` allows `a@example.com` and
     * `a@mail.example.com`).
     */
    private isAllowlistedDomain;
    /**
     * Scan text for sensitive data
     */
    scan(text: string): ScanResult;
    /**
     * Detect matches for a single rule
     */
    private detectWithRule;
    /**
     * Resolve overlapping findings so a single span is never redacted or counted
     * more than once (e.g. a Bearer token that wraps an inner JWT). Findings are
     * assumed sorted by startIndex. When two overlap, keep the wider span; on an
     * equal span keep the higher severity; drop the other.
     */
    private mergeOverlappingFindings;
    /**
     * Generate redacted text
     */
    private redactText;
    /**
     * Generate redacted placeholder
     */
    private generateRedaction;
    /**
     * Calculate summary by category
     */
    private calculateSummary;
    /**
     * Calculate overall risk score (0-100)
     */
    private calculateRiskScore;
}
