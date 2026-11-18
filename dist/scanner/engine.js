/**
 * Core scanning engine
 */
import { BUILTIN_RULES } from './detectors.js';
import safeRegex from 'safe-regex2';
import { shannonEntropy } from './entropy.js';
// Default cap on how much of the input text is run through the rule engine.
// Every enabled rule scans the full text, so cost scales with both text
// length and rule count; bounding the former keeps a single very large
// prompt from adding up to the hook's timeout even when every pattern is
// individually safe. The remainder is passed through unscanned rather than
// dropped, so an oversized prompt still reaches Claude instead of being
// silently truncated.
const DEFAULT_MAX_SCAN_LENGTH = 200_000;
/**
 * Compile a rule's pattern for scanning. String patterns get the rule's own
 * `flags` plus "g" and "m" (the historical default); RegExp patterns keep
 * their flags plus "g".
 */
export function compileRulePattern(rule) {
    if (typeof rule.pattern === 'string') {
        const flags = new Set(['g', 'm', ...(rule.flags ?? '').split('')]);
        flags.delete('y');
        if (rule.secretOnly)
            flags.add('d');
        return new RegExp(rule.pattern, [...flags].join(''));
    }
    const flags = rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g';
    return new RegExp(rule.pattern.source, flags);
}
function passesEntropy(rule, match) {
    let secret;
    if (rule.secretGroup !== undefined) {
        secret = match[rule.secretGroup];
    }
    else {
        secret = match.slice(1).find((g) => g !== undefined && g.length > 0);
    }
    return shannonEntropy(secret ?? match[0]) >= (rule.minEntropy ?? 0);
}
/** Index of the capture group holding the secret, or 0 for the whole match. */
function secretGroupIndex(rule, match) {
    if (rule.secretGroup !== undefined && match[rule.secretGroup] !== undefined)
        return rule.secretGroup;
    for (let i = 1; i < match.length; i++) {
        if (match[i] !== undefined && match[i].length > 0)
            return i;
    }
    return 0;
}
export class PrivacyScanner {
    rules;
    counterMap = new Map();
    allowedDomains;
    allowedValues;
    allowedPatterns;
    maxScanLength;
    constructor(rules = BUILTIN_RULES, options = {}) {
        this.rules = rules.filter(r => r.enabled);
        this.allowedDomains = (options.allowedDomains ?? []).map(d => d.trim().toLowerCase()).filter(Boolean);
        this.allowedValues = new Set((options.allowedValues ?? []).filter(Boolean));
        this.allowedPatterns = this.compileAllowedPatterns(options.allowedPatterns ?? []);
        this.maxScanLength = options.maxScanLength ?? DEFAULT_MAX_SCAN_LENGTH;
    }
    /**
     * Compile allowedPatterns entries, skipping (with a console warning) any
     * that fail to parse as a regex or look prone to catastrophic backtracking -
     * these come from user config, but they still run against every scanned
     * prompt, so an unsafe one deserves the same treatment as an external rule.
     */
    compileAllowedPatterns(patterns) {
        const compiled = [];
        for (const raw of patterns) {
            if (!raw)
                continue;
            let re;
            try {
                re = new RegExp(raw);
            }
            catch {
                console.warn(`Privacy Guard: skipping allowedPatterns entry - invalid regex: ${raw}`);
                continue;
            }
            if (!safeRegex(raw)) {
                console.warn(`Privacy Guard: skipping allowedPatterns entry - regex looks unsafe (possible catastrophic backtracking): ${raw}`);
                continue;
            }
            compiled.push(re);
        }
        return compiled;
    }
    /**
     * Whether a finding should be suppressed by an allowlist: the email domain
     * allowlist (email findings only), an exact-value allowlist, or a regex
     * pattern allowlist (both of the latter two apply to any rule).
     */
    isAllowlisted(finding) {
        if (this.isAllowlistedDomain(finding))
            return true;
        if (this.allowedValues.has(finding.match))
            return true;
        if (this.allowedPatterns.some(re => re.test(finding.match)))
            return true;
        return false;
    }
    /**
     * Whether a finding is suppressed by the domain allowlist. Only applies to
     * email findings: an allowlisted domain matches the exact domain or any
     * subdomain of it (e.g. `example.com` allows `a@example.com` and
     * `a@mail.example.com`).
     */
    isAllowlistedDomain(finding) {
        if (this.allowedDomains.length === 0 || finding.ruleId !== 'email-address') {
            return false;
        }
        const domain = finding.match.split('@')[1]?.toLowerCase();
        if (!domain)
            return false;
        return this.allowedDomains.some(d => domain === d || domain.endsWith('.' + d));
    }
    /**
     * Scan text for sensitive data
     */
    scan(text) {
        this.counterMap.clear();
        const findings = [];
        // Only the first maxScanLength characters are run through the rule
        // engine; anything beyond that is reattached untouched below.
        const scannedText = text.length > this.maxScanLength ? text.slice(0, this.maxScanLength) : text;
        const unscannedTail = text.slice(scannedText.length);
        // Run all enabled rules. Keyword-prefiltered rules are skipped unless one
        // of their keywords appears in the text.
        const lowered = scannedText.toLowerCase();
        for (const rule of this.rules) {
            if (rule.keywords && rule.keywords.length > 0 && !rule.keywords.some((k) => lowered.includes(k))) {
                continue;
            }
            const ruleFindings = this.detectWithRule(scannedText, rule);
            findings.push(...ruleFindings);
        }
        // Drop findings suppressed by the domain allowlist before any scoring so
        // risk score, summary, and redacted text all stay consistent with what
        // the guard actually acts on.
        const kept = findings.filter(f => !this.isAllowlisted(f));
        // Sort findings by position
        kept.sort((a, b) => a.startIndex - b.startIndex);
        // Resolve overlaps so the same span is not redacted or counted twice
        const mergedFindings = this.mergeOverlappingFindings(kept);
        // Generate redacted text
        const redactedText = this.redactText(scannedText, mergedFindings) + unscannedTail;
        // Calculate risk metrics
        const summary = this.calculateSummary(mergedFindings);
        const riskScore = this.calculateRiskScore(mergedFindings);
        const hasCriticalRisk = mergedFindings.some(f => f.severity === 'critical');
        const hasHighRisk = mergedFindings.some(f => f.severity === 'high' || f.severity === 'critical');
        return {
            findings: mergedFindings,
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
        const pattern = compileRulePattern(rule);
        let match;
        while ((match = pattern.exec(text)) !== null) {
            const matchText = match[0];
            // A rule whose pattern can match the empty string would otherwise spin
            // here forever: exec returns a zero-length match without advancing
            // lastIndex. Nudge past it and skip the empty finding.
            if (matchText.length === 0) {
                pattern.lastIndex += 1;
                continue;
            }
            // Data-driven entropy gate (gitleaks-style rules from JSON).
            if (rule.minEntropy !== undefined && !passesEntropy(rule, match))
                continue;
            // Rules with a validator (Luhn, entropy, ...) only keep candidates it
            // accepts. A throwing validator must never break the scan, so it counts
            // as "reject".
            if (rule.validate) {
                let accepted = false;
                try {
                    accepted = rule.validate(matchText, match);
                }
                catch {
                    accepted = false;
                }
                if (!accepted)
                    continue;
            }
            // Narrow the span to the secret itself when the rule asks for it.
            let spanText = matchText;
            let spanStart = match.index;
            if (rule.secretOnly) {
                const g = secretGroupIndex(rule, match);
                const indices = match.indices;
                const range = g > 0 ? indices?.[g] : undefined;
                if (range) {
                    spanStart = range[0];
                    spanText = text.slice(range[0], range[1]);
                }
            }
            const redactedValue = this.generateRedaction(rule, spanText);
            findings.push({
                ruleId: rule.id,
                title: rule.title,
                severity: rule.severity,
                category: rule.category,
                match: spanText,
                startIndex: spanStart,
                endIndex: spanStart + spanText.length,
                redactedValue,
            });
        }
        return findings;
    }
    /**
     * Resolve overlapping findings so a single span is never redacted or counted
     * more than once (e.g. a Bearer token that wraps an inner JWT). Findings are
     * assumed sorted by startIndex. When two overlap, keep the wider span; on an
     * equal span keep the higher severity; drop the other.
     */
    mergeOverlappingFindings(findings) {
        if (findings.length <= 1)
            return findings;
        const severityRank = {
            low: 0,
            medium: 1,
            high: 2,
            critical: 3,
        };
        const kept = [];
        for (const finding of findings) {
            const prev = kept[kept.length - 1];
            if (prev && finding.startIndex < prev.endIndex) {
                const prevSpan = prev.endIndex - prev.startIndex;
                const curSpan = finding.endIndex - finding.startIndex;
                const preferCurrent = curSpan > prevSpan ||
                    (curSpan === prevSpan &&
                        severityRank[finding.severity] > severityRank[prev.severity]);
                if (preferCurrent) {
                    kept[kept.length - 1] = finding;
                }
                continue;
            }
            kept.push(finding);
        }
        return kept;
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
