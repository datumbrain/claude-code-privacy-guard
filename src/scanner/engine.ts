/**
 * Core scanning engine
 */

import { DetectionRule, Finding, ScanResult, Severity } from '../types/findings.js';
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

/**
 * Compile a rule's pattern for scanning. String patterns get the rule's own
 * `flags` plus "g" and "m" (the historical default); RegExp patterns keep
 * their flags plus "g".
 */
export function compileRulePattern(rule: DetectionRule): RegExp {
  if (typeof rule.pattern === 'string') {
    const flags = new Set(['g', 'm', ...(rule.flags ?? '').split('')]);
    flags.delete('y');
    if (rule.secretOnly) flags.add('d');
    return new RegExp(rule.pattern, [...flags].join(''));
  }
  const flags = rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g';
  return new RegExp(rule.pattern.source, flags);
}

function passesEntropy(rule: DetectionRule, match: RegExpExecArray): boolean {
  let secret: string | undefined;
  if (rule.secretGroup !== undefined) {
    secret = match[rule.secretGroup];
  } else {
    secret = match.slice(1).find((g) => g !== undefined && g.length > 0);
  }
  return shannonEntropy(secret ?? match[0]) >= (rule.minEntropy ?? 0);
}

/** Index of the capture group holding the secret, or 0 for the whole match. */
function secretGroupIndex(rule: DetectionRule, match: RegExpExecArray): number {
  if (rule.secretGroup !== undefined && match[rule.secretGroup] !== undefined) return rule.secretGroup;
  for (let i = 1; i < match.length; i++) {
    if (match[i] !== undefined && match[i].length > 0) return i;
  }
  return 0;
}

export class PrivacyScanner {
  private rules: DetectionRule[];
  private counterMap: Map<string, number> = new Map();
  private allowedDomains: string[];
  private allowedValues: Set<string>;
  private allowedPatterns: RegExp[];
  private maxScanLength: number;

  constructor(rules: DetectionRule[] = BUILTIN_RULES, options: ScannerOptions = {}) {
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
  private compileAllowedPatterns(patterns: string[]): RegExp[] {
    const compiled: RegExp[] = [];
    for (const raw of patterns) {
      if (!raw) continue;

      let re: RegExp;
      try {
        re = new RegExp(raw);
      } catch {
        console.warn(`Privacy Guard: skipping allowedPatterns entry - invalid regex: ${raw}`);
        continue;
      }

      if (!safeRegex(raw)) {
        console.warn(
          `Privacy Guard: skipping allowedPatterns entry - regex looks unsafe (possible catastrophic backtracking): ${raw}`
        );
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
  private isAllowlisted(finding: Finding): boolean {
    if (this.isAllowlistedDomain(finding)) return true;
    if (this.allowedValues.has(finding.match)) return true;
    if (this.allowedPatterns.some(re => re.test(finding.match))) return true;
    return false;
  }

  /**
   * Whether a finding is suppressed by the domain allowlist. Only applies to
   * email findings: an allowlisted domain matches the exact domain or any
   * subdomain of it (e.g. `example.com` allows `a@example.com` and
   * `a@mail.example.com`).
   */
  private isAllowlistedDomain(finding: Finding): boolean {
    if (this.allowedDomains.length === 0 || finding.ruleId !== 'email-address') {
      return false;
    }
    const domain = finding.match.split('@')[1]?.toLowerCase();
    if (!domain) return false;
    return this.allowedDomains.some(d => domain === d || domain.endsWith('.' + d));
  }

  /**
   * Scan text for sensitive data
   */
  scan(text: string): ScanResult {
    this.counterMap.clear();
    const findings: Finding[] = [];

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
  private detectWithRule(text: string, rule: DetectionRule): Finding[] {
    const findings: Finding[] = [];
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
      if (rule.minEntropy !== undefined && !passesEntropy(rule, match)) continue;

      // Rules with a validator (Luhn, entropy, ...) only keep candidates it
      // accepts. A throwing validator must never break the scan, so it counts
      // as "reject".
      if (rule.validate) {
        let accepted = false;
        try {
          accepted = rule.validate(matchText, match);
        } catch {
          accepted = false;
        }
        if (!accepted) continue;
      }

      // Narrow the span to the secret itself when the rule asks for it.
      let spanText = matchText;
      let spanStart = match.index;
      if (rule.secretOnly) {
        const g = secretGroupIndex(rule, match);
        const indices = (match as RegExpExecArray & { indices?: Array<[number, number] | undefined> }).indices;
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
