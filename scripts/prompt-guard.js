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

// If sensitive data found, block the prompt
if (result.findings.length > 0) {
  // Build detailed findings list
  const findingsList = result.findings.map(f =>
    `  - ${f.title}: ${f.match.substring(0, 20)}...`
  ).join('\n');

  // Return blocking decision as JSON
  const response = {
    decision: "block",
    reason: `🛡️ Privacy Guard blocked this prompt\n\n` +
            `Found ${result.findings.length} sensitive item(s):\n${findingsList}\n\n` +
            `Risk Score: ${result.riskScore}/100\n` +
            `Secrets: ${result.summary.secret || 0} | PII: ${result.summary.pii || 0}\n\n` +
            `Please remove or anonymize sensitive data before proceeding.`
  };

  console.log(JSON.stringify(response, null, 2));

  // Also log to stderr for user visibility
  console.error('\n⚠️  Privacy Guard: Prompt blocked due to sensitive data');
  console.error(`   Found: ${result.findings.length} issue(s)`);
  console.error(`   Risk Score: ${result.riskScore}/100`);
  if ((result.summary.secret || 0) > 0) {
    console.error(`   - ${result.summary.secret} secret(s)`);
  }
  if (result.summary.pii > 0) {
    console.error(`   - ${result.summary.pii} PII item(s)`);
  }
  console.error('');

  process.exit(1); // Exit with non-zero to block the prompt
}

// No sensitive data, allow the prompt
process.exit(0);
