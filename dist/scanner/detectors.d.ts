/**
 * Pattern detectors for sensitive data
 */
import { DetectionRule } from '../types/findings.js';
export interface ExternalRuleOptions {
    codingOnly?: boolean;
}
/**
 * Built-in detection rules
 * Start with high-value patterns that catch the most dangerous leaks
 */
export declare const BUILTIN_RULES: DetectionRule[];
/**
 * Addresses the email rule matches that are not a person's mailbox: the SSH
 * user in git remotes (git@github.com:org/repo.git) and image density
 * suffixes in asset names (logo@2x.png, icon@1.5x.webp).
 */
export declare function isNonPersonalAddress(match: string): boolean;
/**
 * Load rules from external JSON converted from CSV regex lists.
 */
export declare function loadExternalRulesFromJson(jsonPath: string, options?: ExternalRuleOptions): DetectionRule[];
