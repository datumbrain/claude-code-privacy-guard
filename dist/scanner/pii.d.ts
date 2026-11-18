/**
 * Opt-in PII detectors: credit card numbers, US SSNs, and phone numbers.
 *
 * These are deliberately NOT part of BUILTIN_RULES. They are enabled one by
 * one through the `piiProfile` config section and are off by default so the
 * tool stays coding-focused. Each rule pairs a loose candidate regex with a
 * strict validator (Luhn + issuer prefix, SSN range rules, NANP rules) so
 * order IDs, timestamps and version strings don't flood users with false
 * positives.
 */
import { DetectionRule, PiiProfile } from '../types/findings.js';
/** Luhn checksum over a digit string. */
export declare function passesLuhn(digits: string): boolean;
export declare function isValidCardNumber(raw: string): boolean;
export declare function isValidSsn(raw: string): boolean;
export declare function isValidPhone(raw: string): boolean;
export declare const PII_RULES: Record<keyof PiiProfile, DetectionRule>;
/** Rules enabled by a config's `piiProfile`; empty when nothing is opted in. */
export declare function getPiiRules(profile: PiiProfile | undefined): DetectionRule[];
