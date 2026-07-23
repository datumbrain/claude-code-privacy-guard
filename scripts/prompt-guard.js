#!/usr/bin/env node

/**
 * Privacy Guard Hook for UserPromptSubmit
 *
 * This hook intercepts user prompts before they're sent to Claude,
 * scans for sensitive data, and blocks prompts containing sensitive information.
 *
 * It is invoked directly by Claude Code as `node prompt-guard.js` (no shell
 * wrapper), so it must run unchanged on Windows, macOS, and Linux. All
 * platform-specific behavior (debug log location, path handling) lives here.
 */

import { PrivacyScanner } from '../dist/scanner/engine.js';
import { readFileSync, mkdirSync, appendFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { BUILTIN_RULES, loadExternalRulesFromJson } from '../dist/scanner/detectors.js';
import { ConfigLoader } from '../dist/config/loader.js';
import { buildHookResponse } from '../dist/hook/response.js';
import * as path from 'path';
import * as os from 'os';

// Debug logging is opt-in: set PRIVACY_GUARD_DEBUG=1 to enable. The log only
// ever holds execution metadata - never matched secret or PII values.
const DEBUG = process.env.PRIVACY_GUARD_DEBUG === '1';

// Resolve the per-user cache directory in a cross-platform way. On Windows we
// use %LOCALAPPDATA%; on POSIX we honor XDG_CACHE_HOME, falling back to
// ~/.cache (matching the path documented in the README).
function getCacheDir() {
  if (os.platform() === 'win32') {
    const base = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
    return path.join(base, 'claude-code-privacy-guard');
  }
  const base = process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache');
  return path.join(base, 'claude-code-privacy-guard');
}

// Append metadata lines to the debug log. Best-effort: debug logging must never
// affect the prompt flow, so any failure here is swallowed.
function debugLog(lines) {
  if (!DEBUG) return;
  try {
    const dir = getCacheDir();
    mkdirSync(dir, { recursive: true });
    appendFileSync(path.join(dir, 'debug.log'), lines.join('\n') + '\n');
  } catch {
    // Intentionally ignored - never let logging break prompting.
  }
}

// Record the exit path in the debug log, then exit. Centralizes the "exit path"
// metadata that the old shell wrapper used to log after running the script.
function finish(exitPath, code) {
  debugLog([`Exit path: ${exitPath}`, `Exit code: ${code}`, '']);
  process.exit(code);
}

// Pull the user's prompt out of the UserPromptSubmit stdin payload. Falls back
// to the raw text when stdin isn't the expected JSON envelope (e.g. the script
// invoked manually with a piped prompt, or a future protocol change) so the
// guard still scans something rather than silently allowing everything.
function extractPrompt(raw) {
  const trimmed = raw.trim();
  if (!trimmed.startsWith('{')) return raw;
  try {
    const payload = JSON.parse(trimmed);
    if (payload && typeof payload.prompt === 'string') return payload.prompt;
  } catch {
    // Not JSON after all - fall through and scan the raw text.
  }
  return raw;
}

// Pull session_id out of the same envelope, used only to dedupe the
// "disabled by config" notice below (one notice per session, not per prompt).
function extractSessionId(raw) {
  const trimmed = raw.trim();
  if (!trimmed.startsWith('{')) return undefined;
  try {
    const payload = JSON.parse(trimmed);
    if (payload && typeof payload.session_id === 'string') return payload.session_id;
  } catch {
    // Not JSON - no session id available.
  }
  return undefined;
}

// A config typo or a stale "enabled": false left over from debugging means
// every prompt goes through unscanned with no signal to the user. Emit a
// systemMessage the first time we see a given session_id, then stay quiet for
// the rest of that session so we're not repeating ourselves on every prompt.
function noticeIfDisabled(sessionId) {
  const noticePath = path.join(getCacheDir(), 'disabled-notice.json');

  if (sessionId) {
    try {
      const stored = JSON.parse(readFileSync(noticePath, 'utf-8'));
      if (stored && stored.lastSessionId === sessionId) return;
    } catch {
      // No prior notice file (or unreadable) - treat as not yet notified.
    }
  }

  console.log(
    JSON.stringify({
      systemMessage:
        '🛡️ Privacy Guard is disabled ("enabled": false in .privacy-guard.json) - prompts are not being scanned.',
    })
  );

  if (sessionId) {
    try {
      mkdirSync(path.dirname(noticePath), { recursive: true });
      writeFileSync(noticePath, JSON.stringify({ lastSessionId: sessionId }));
    } catch {
      // Best-effort only; failing to persist just means we notice again next time.
    }
  }
}

debugLog([
  `=== Hook Execution ${new Date().toISOString()} ===`,
  `CLAUDE_PLUGIN_ROOT: ${process.env.CLAUDE_PLUGIN_ROOT ?? ''}`,
  `CWD: ${process.cwd()}`,
  `Node version: ${process.version}`,
]);

try {
  // Read the hook payload from stdin (passed by Claude Code). Claude Code sends
  // a JSON envelope - {"session_id":...,"prompt":"..."} - not the bare prompt,
  // so only the "prompt" field may be scanned or echoed back. Scanning the raw
  // envelope would both produce false positives on paths/ids and leak the JSON
  // into redact mode's copy-pasteable output.
  let promptText = '';
  let rawStdin = '';
  try {
    rawStdin = readFileSync(0, 'utf-8');
    promptText = extractPrompt(rawStdin);
  } catch (error) {
    // The shell wrapper discarded stderr when debug was off; keep stderr quiet
    // and route the error to the debug log instead. Exit non-zero as before -
    // per the hook protocol this is a non-blocking error, matching prior
    // behavior (the prompt is not silently altered by this failure).
    debugLog([`ERROR reading prompt: ${error.message}`]);
    finish('stdin-read-error', 1);
  }

  // Load user configuration (.privacy-guard.json, searched upward from cwd)
  const configPath = ConfigLoader.findConfig();
  const config = new ConfigLoader(configPath ?? undefined).getConfig();

  if (config.enabled === false) {
    noticeIfDisabled(extractSessionId(rawStdin));
    finish('disabled', 0);
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
    [...BUILTIN_RULES, ...externalRules].filter((rule) => !disabledRules.has(rule.id)),
    {
      allowedDomains: config.allowedDomains,
      allowedValues: config.allowedValues,
      allowedPatterns: config.allowedPatterns,
    }
  );

  // Scan the prompt
  const result = scanner.scan(promptText);

  // React to findings per the configured mode: "block" (default) rejects the
  // prompt outright, "redact" also blocks (the hook API can't rewrite the
  // prompt) but hands back a copy-pasteable cleaned version, and "warn"
  // allows the prompt through with a visible systemMessage.
  const mode = config.mode ?? 'block';
  const response = buildHookResponse(result, mode);

  if (response) {
    console.log(JSON.stringify(response, null, 2));

    // Per the UserPromptSubmit hook protocol, a JSON "decision": "block" (or
    // a "warn" mode's systemMessage-only payload) is only honored on exit 0.
    // A non-zero exit here would be treated as a non-blocking error and the
    // prompt would go through unannotated.
    finish(response.decision === 'block' ? `${mode}-block` : 'warn', 0);
  }

  // No sensitive data, allow the prompt
  finish('allow', 0);
} catch (error) {
  // Any unexpected internal error: keep stderr quiet (the wrapper used to
  // discard it) and log to the debug file when enabled. Exit non-zero, which
  // the hook protocol treats as a non-blocking error - matching the wrapper's
  // pass-through of a failing exit code.
  debugLog([`ERROR: ${error && error.stack ? error.stack : String(error)}`]);
  finish('internal-error', 1);
}
