#!/usr/bin/env node

/**
 * Privacy Guard Hook for UserPromptSubmit
 *
 * This hook intercepts user prompts before they're sent to Claude,
 * scans for sensitive data, and blocks prompts containing sensitive information.
 */

import { PrivacyScanner } from '../dist/scanner/engine.js';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { BUILTIN_RULES, loadExternalRulesFromJson } from '../dist/scanner/detectors.js';
import { ConfigLoader } from '../dist/config/loader.js';
import * as path from 'path';

// Read the user's prompt from stdin
let promptText = '';
try {
  // The prompt is passed via stdin by Claude Code
  promptText = readFileSync(0, 'utf-8');
} catch (error) {
  console.error('Error reading prompt:', error.message);
  process.exit(1);
}

// Load user configuration (.privacy-guard.json, searched upward from cwd)
const configPath = ConfigLoader.findConfig();
const config = new ConfigLoader(configPath ?? undefined).getConfig();

if (config.enabled === false) {
  process.exit(0);
}

// Initialize scanner with built-in + external JSON regex rules
let externalRulesPath = fileURLToPath(new URL('../data/regex_list_1.json', import.meta.url));
if (config.externalRulesJsonPath) {
  const baseDir = configPath ? path.dirname(configPath) : process.cwd();
  externalRulesPath = path.resolve(baseDir, config.externalRulesJsonPath);
}
const codingOnly = (config.externalRulesMode ?? 'coding-only') === 'coding-only';
const externalRules = loadExternalRulesFromJson(externalRulesPath, { codingOnly });

// Honor disabledRules from config for both built-in and external rules
const disabledRules = new Set(config.disabledRules);
const scanner = new PrivacyScanner(
  [...BUILTIN_RULES, ...externalRules].filter((rule) => !disabledRules.has(rule.id))
);

// Scan the prompt
const result = scanner.scan(promptText);

// Mask a matched secret/PII value down to a short, non-recoverable hint,
// e.g. "sk-proj-abc123xyz1234567890" -> "sk-p…7890"
function maskMatch(value) {
  if (value.length <= 8) return '*'.repeat(value.length);
  return `${value.slice(0, 4)}…${value.slice(-4)}`;
}

// If sensitive data found, block the prompt
if (result.findings.length > 0) {
  // Build detailed findings list
  const findingsList = result.findings.map(f =>
    `  - ${f.title} (${f.ruleId}): ${maskMatch(f.match)}`
  ).join('\n');

  // Return blocking decision as JSON
  const response = {
    decision: "block",
    reason: `🛡️ Privacy Guard blocked this prompt\n\n` +
            `Found ${result.findings.length} sensitive item(s):\n${findingsList}\n\n` +
            `Risk Score: ${result.riskScore}/100\n` +
            `Secrets: ${result.summary.secret || 0} | PII: ${result.summary.pii || 0}\n\n` +
            `Please remove or anonymize sensitive data before proceeding.\n` +
            `To disable a rule, add its ID to "disabledRules" in .privacy-guard.json.`
  };

  console.log(JSON.stringify(response, null, 2));

  // Per the UserPromptSubmit hook protocol, a JSON "decision": "block" is
  // only honored on exit 0. A non-zero exit here would be treated as a
  // non-blocking error and the prompt would go through anyway.
  process.exit(0);
}

// No sensitive data, allow the prompt
process.exit(0);
