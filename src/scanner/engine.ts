/**
 * Core scanning engine
 */

import { DetectionRule, Finding, ScanResult, Severity } from '../types/findings.js';
import { BUILTIN_RULES } from './detectors.js';

export class PrivacyScanner {
  private rules: DetectionRule[];
  private counterMap: Map<string, number> = new Map();

  constructor(rules: DetectionRule[] = BUILTIN_RULES) {
    this.rules = rules.filter(r => r.enabled);
  }

  /**
   * Scan text for sensitive data
   */
  scan(text: string): ScanResult {
    this.counterMap.clear();
    const findings: Finding[] = [];

    // Run all enabled rules
    for (const rule of this.rules) {
      const ruleFindings = this.detectWithRule(text, rule);
      findings.push(...ruleFindings);
    }

    // Sort findings by position
    findings.sort((a, b) => a.startIndex - b.startIndex);

    // Resolve overlaps so the same span is not redacted or counted twice
    const mergedFindings = this.mergeOverlappingFindings(findings);

    // Generate redacted text
    const redactedText = this.redactText(text, mergedFindings);

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
  private detectWithRule(text: string, rule: DetectionRule): Finding[] {
    const findings: Finding[] = [];
    const pattern = typeof rule.pattern === 'string'
      ? new RegExp(rule.pattern, 'gm')
      : new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g');

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
   * Resolve overlapping findings so a single span is never redacted or counted
   * more than once (e.g. a Bearer token that wraps an inner JWT). Findings are
   * assumed sorted by startIndex. When two overlap, keep the wider span; on an
   * equal span keep the higher severity; drop the other.
   */
  private mergeOverlappingFindings(findings: Finding[]): Finding[] {
    if (findings.length <= 1) return findings;

    const severityRank: Record<Severity, number> = {
      low: 0,
      medium: 1,
      high: 2,
      critical: 3,
    };

    const kept: Finding[] = [];
    for (const finding of findings) {
      const prev = kept[kept.length - 1];
      if (prev && finding.startIndex < prev.endIndex) {
        const prevSpan = prev.endIndex - prev.startIndex;
        const curSpan = finding.endIndex - finding.startIndex;
        const preferCurrent =
          curSpan > prevSpan ||
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
  private redactText(text: string, findings: Finding[]): string {
    if (findings.length === 0) return text;

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
  private generateRedaction(rule: DetectionRule, match: string): string {
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
        if (match.length <= 8) return '***';
        return match.slice(0, 3) + '***' + match.slice(-3);

      case 'full-mask':
      default:
        return '***';
    }
  }

  /**
   * Calculate summary by category
   */
  private calculateSummary(findings: Finding[]): ScanResult['summary'] {
    const summary: ScanResult['summary'] = {};

    for (const finding of findings) {
      summary[finding.category] = (summary[finding.category] || 0) + 1;
    }

    return summary;
  }

  /**
   * Calculate overall risk score (0-100)
   */
  private calculateRiskScore(findings: Finding[]): number {
    if (findings.length === 0) return 0;

    const severityWeights: Record<Severity, number> = {
      low: 10,
      medium: 25,
      high: 50,
      critical: 100,
    };

    const totalWeight = findings.reduce((sum, f) => sum + severityWeights[f.severity], 0);
    return Math.min(100, totalWeight);
  }
}
