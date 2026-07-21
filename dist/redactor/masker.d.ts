/**
 * Redaction and masking utilities
 */
import { Finding, ScanResult } from '../types/findings.js';
export declare class Redactor {
    /**
     * Apply redaction to text based on findings
     */
    static redact(scanResult: ScanResult): string;
    /**
     * Generate a human-readable summary of findings
     */
    static summarize(scanResult: ScanResult): string;
    /**
     * Format findings for detailed display
     */
    static formatFindings(findings: Finding[]): string;
    private static truncate;
}
