/**
 * Core scanning engine
 */
import { BUILTIN_RULES } from './detectors.js';
export class PrivacyScanner {
    rules;
    counterMap = new Map();
    constructor(rules = BUILTIN_RULES) {
        this.rules = rules.filter(r => r.enabled);
    }
    /**
     * Scan text for sensitive data
     */
    scan(text) {
        this.counterMap.clear();
        const findings = [];
        // Run all enabled rules
        for (const rule of this.rules) {
            const ruleFindings = this.detectWithRule(text, rule);
            findings.push(...ruleFindings);
        }
        // Sort findings by position
        findings.sort((a, b) => a.startIndex - b.startIndex);
        // Generate redacted text
        const redactedText = this.redactText(text, findings);
        // Calculate risk metrics
        const summary = this.calculateSummary(findings);
        const riskScore = this.calculateRiskScore(findings);
        const hasCriticalRisk = findings.some(f => f.severity === 'critical');
        const hasHighRisk = findings.some(f => f.severity === 'high' || f.severity === 'critical');
        return {
            findings,
            originalText: text,
            redactedText,
            riskScore,
            hasHighRisk,
            hasCriticalRisk,
            summary,
        };
    }
    /**
     * Detect matches for a single rule
     */
    detectWithRule(text, rule) {
        const findings = [];
        const pattern = typeof rule.pattern === 'string'
            ? new RegExp(rule.pattern, 'gm')
            : new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g');
        let match;
        while ((match = pattern.exec(text)) !== null) {
            const matchText = match[0];
            const redactedValue = this.generateRedaction(rule, matchText);
            findings.push({
                ruleId: rule.id,
                title: rule.title,
                severity: rule.severity,
                category: rule.category,
                match: matchText,
                startIndex: match.index,
                endIndex: match.index + matchText.length,
                redactedValue,
            });
        }
        return findings;
    }
    /**
     * Generate redacted text
     */
    redactText(text, findings) {
        if (findings.length === 0)
            return text;
        let result = '';
        let lastIndex = 0;
        for (const finding of findings) {
            result += text.slice(lastIndex, finding.startIndex);
            result += finding.redactedValue;
            lastIndex = finding.endIndex;
        }
        result += text.slice(lastIndex);
        return result;
    }
    /**
     * Generate redacted placeholder
     */
    generateRedaction(rule, match) {
        const category = rule.category.toUpperCase().replace('-', '_');
        switch (rule.redactionStrategy) {
            case 'semantic': {
                // Use counters for semantic placeholders like <EMAIL_1>
                const count = (this.counterMap.get(rule.id) || 0) + 1;
                this.counterMap.set(rule.id, count);
                return `<${category}_${count}>`;
            }
            case 'token-replace':
                return `<${category}>`;
            case 'partial-mask':
                if (match.length <= 8)
                    return '***';
                return match.slice(0, 3) + '***' + match.slice(-3);
            case 'full-mask':
            default:
                return '***';
        }
    }
    /**
     * Calculate summary by category
     */
    calculateSummary(findings) {
        const summary = {};
        for (const finding of findings) {
            summary[finding.category] = (summary[finding.category] || 0) + 1;
        }
        return summary;
    }
    /**
     * Calculate overall risk score (0-100)
     */
    calculateRiskScore(findings) {
        if (findings.length === 0)
            return 0;
        const severityWeights = {
            low: 10,
            medium: 25,
            high: 50,
            critical: 100,
        };
        const totalWeight = findings.reduce((sum, f) => sum + severityWeights[f.severity], 0);
        return Math.min(100, totalWeight);
    }
}
//# sourceMappingURL=engine.js.map