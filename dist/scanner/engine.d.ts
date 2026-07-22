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
    private maxScanLength;
    constructor(rules?: DetectionRule[], options?: ScannerOptions);
    /**
     * Whether a finding should be suppressed by the domain allowlist. Only
     * applies to email findings: an allowlisted domain matches the exact domain
     * or any subdomain of it (e.g. `example.com` allows `a@example.com` and
     * `a@mail.example.com`).
     */
    private isAllowlisted;
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
