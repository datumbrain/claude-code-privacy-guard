/**
 * Core type definitions for privacy findings and rules
 */
export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type Category = 'pii' | 'secret' | 'credential' | 'internal-data' | 'financial' | 'auth-token';
export type RedactionStrategy = 'full-mask' | 'partial-mask' | 'token-replace' | 'semantic';
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
    context?: string;
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
export interface PrivacyGuardConfig {
    enabled: boolean;
    strictMode: boolean;
    allowedDomains: string[];
    disabledRules: string[];
    redactionStyle: 'placeholder' | 'mask' | 'remove';
    autoMaskOnHighRisk: boolean;
    externalRulesJsonPath?: string;
    externalRulesMode?: 'coding-only' | 'all';
}
