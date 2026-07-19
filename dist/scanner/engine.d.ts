/**
 * Core scanning engine
 */
import { DetectionRule, ScanResult } from '../types/findings.js';
export declare class PrivacyScanner {
    private rules;
    private counterMap;
    constructor(rules?: DetectionRule[]);
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
