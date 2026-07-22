/**
 * Builds the UserPromptSubmit hook JSON payload for a scan result, branching
 * on `mode`. The hook protocol has no field that rewrites/replaces the
 * submitted prompt (see README "Block, Redact, or Warn?") - so `redact` mode
 * still blocks, but hands back a copy-pasteable cleaned prompt instead of
 * making the user manually retype it.
 */
/**
 * Mask a matched secret/PII value down to a short, non-recoverable hint,
 * e.g. "sk-proj-abc123xyz1234567890" -> "sk-p…7890"
 */
function maskMatch(value) {
    if (value.length <= 8)
        return '*'.repeat(value.length);
    return `${value.slice(0, 4)}…${value.slice(-4)}`;
}
function formatFindingsList(result) {
    return result.findings
        .map((f) => `  - ${f.title} (${f.ruleId}): ${maskMatch(f.match)}`)
        .join('\n');
}
function formatSummary(result) {
    return (`Risk Score: ${result.riskScore}/100\n` +
        `Secrets: ${result.summary.secret || 0} | PII: ${result.summary.pii || 0}`);
}
/**
 * Returns the JSON payload to print for a scan with findings, or null when
 * there is nothing to report (caller should allow the prompt silently).
 */
export function buildHookResponse(result, mode) {
    if (result.findings.length === 0)
        return null;
    const findingsList = formatFindingsList(result);
    const summary = formatSummary(result);
    if (mode === 'warn') {
        return {
            systemMessage: `🛡️ Privacy Guard: sensitive data detected (warn mode - prompt allowed through)\n\n` +
                `Found ${result.findings.length} sensitive item(s):\n${findingsList}\n\n${summary}`,
        };
    }
    if (mode === 'redact') {
        return {
            decision: 'block',
            reason: `🛡️ Privacy Guard blocked this prompt\n\n` +
                `Found ${result.findings.length} sensitive item(s):\n${findingsList}\n\n${summary}\n\n` +
                `Claude Code's hook API can't resubmit a modified prompt automatically, so here's a cleaned copy you can paste instead:\n\n` +
                `---\n${result.redactedText}\n---\n\n` +
                `To disable a rule, add its ID to "disabledRules" in .privacy-guard.json.\n` +
                `To always allow this exact value, add it to "allowedValues" (or a matching regex to "allowedPatterns") in .privacy-guard.json.`,
        };
    }
    return {
        decision: 'block',
        reason: `🛡️ Privacy Guard blocked this prompt\n\n` +
            `Found ${result.findings.length} sensitive item(s):\n${findingsList}\n\n${summary}\n\n` +
            `Please remove or anonymize sensitive data before proceeding.\n` +
            `To disable a rule, add its ID to "disabledRules" in .privacy-guard.json.\n` +
            `To always allow this exact value, add it to "allowedValues" (or a matching regex to "allowedPatterns") in .privacy-guard.json.`,
    };
}
