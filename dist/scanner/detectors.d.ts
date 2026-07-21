/**
 * Pattern detectors for sensitive data
 */
import { DetectionRule } from '../types/findings.js';
interface ExternalRuleOptions {
    codingOnly?: boolean;
}
/**
 * Built-in detection rules
 * Start with high-value patterns that catch the most dangerous leaks
 */
export declare const BUILTIN_RULES: DetectionRule[];
/**
 * Load rules from external JSON converted from CSV regex lists.
 */
export declare function loadExternalRulesFromJson(jsonPath: string, options?: ExternalRuleOptions): DetectionRule[];
export {};
