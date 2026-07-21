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
