/**
 * Redaction and masking utilities
 */
export class Redactor {
    /**
     * Apply redaction to text based on findings
     */
    static redact(scanResult) {
        return scanResult.redactedText;
    }
    /**
     * Generate a human-readable summary of findings
     */
    static summarize(scanResult) {
        if (scanResult.findings.length === 0) {
            return 'No sensitive data detected.';
        }
        const lines = ['Sensitive data detected:'];
        // Group by category
        for (const [category, count] of Object.entries(scanResult.summary)) {
            lines.push(`  - ${count} ${category.replace('-', ' ')} finding(s)`);
        }
        lines.push('');
        lines.push(`Risk Score: ${scanResult.riskScore}/100`);
        return lines.join('\n');
    }
    /**
     * Format findings for detailed display
     */
    static formatFindings(findings) {
        if (findings.length === 0)
            return 'No findings.';
        const lines = [];
        for (let i = 0; i < findings.length; i++) {
            const f = findings[i];
            lines.push(`${i + 1}. [${f.severity.toUpperCase()}] ${f.title}`);
            lines.push(`   Category: ${f.category}`);
            lines.push(`   Found: ${this.truncate(f.match, 50)}`);
            lines.push(`   Redacted: ${f.redactedValue}`);
            lines.push('');
        }
        return lines.join('\n');
    }
    static truncate(text, maxLength) {
        if (text.length <= maxLength)
            return text;
        return text.slice(0, maxLength) + '...';
    }
}
