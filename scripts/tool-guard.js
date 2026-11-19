#!/usr/bin/env node

/**
 * Privacy Guard hook for PreToolUse and PostToolUse.
 *
 * PreToolUse (Read, Grep, Bash): asks (or denies, per config) before a tool
 * call that would put secrets into the conversation - reading a credentials
 * file, dumping the environment, or reading a file whose contents contain
 * secrets.
 *
 * PostToolUse: scans tool output. The output is already in context by then,
 * so this only warns the user (so they can rotate) and tells Claude not to
 * repeat the values.
 *
 * Fail-open by design: any internal error exits 0 with no output, so a broken
 * guard never blocks the user's tools. Decision logic lives in
 * src/hook/tool-guard.ts.
 */

import { readFileSync, openSync, readSync, closeSync, fstatSync, statSync, mkdirSync, appendFileSync } from 'fs';
import { fileURLToPath } from 'url';
import * as path from 'path';
import { ConfigLoader } from '../dist/config/loader.js';
import { buildScanner, getCacheDir, readPluginVersion } from '../dist/hook/setup.js';
import { checkPostToolUse, checkPreToolUse, resolveToolGuardConfig } from '../dist/hook/tool-guard.js';

const DEBUG = process.env.PRIVACY_GUARD_DEBUG === '1';

// Metadata only - never matched values.
function debugLog(line) {
  if (!DEBUG) return;
  try {
    const dir = getCacheDir();
    mkdirSync(dir, { recursive: true });
    appendFileSync(path.join(dir, 'debug.log'), `[tool-guard ${new Date().toISOString()}] ${line}\n`);
  } catch {
    // Never let logging affect the tool flow.
  }
}

// Read at most maxBytes of a regular file; null for anything unreadable,
// missing, a directory, or binary-looking (NUL byte in the sample).
function readFilePrefix(filePath, maxBytes) {
  let fd;
  try {
    // Check before opening: opening a FIFO blocks until a writer appears,
    // which would hang the hook until its timeout.
    if (!statSync(filePath).isFile()) return null;
    fd = openSync(filePath, 'r');
    if (!fstatSync(fd).isFile()) return null;
    const buf = Buffer.alloc(maxBytes);
    const n = readSync(fd, buf, 0, maxBytes, 0);
    const slice = buf.subarray(0, n);
    if (slice.includes(0)) return null;
    return slice.toString('utf-8');
  } catch {
    return null;
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* ignore */ }
    }
  }
}

try {
  const input = JSON.parse(readFileSync(0, 'utf-8'));
  const event = input.hook_event_name;

  // Config is searched upward from the session's cwd when Claude Code gives it.
  const configPath = ConfigLoader.findConfig(typeof input.cwd === 'string' ? input.cwd : process.cwd());
  const config = new ConfigLoader(configPath ?? undefined).getConfig();
  const guard = resolveToolGuardConfig(config.toolGuard);

  if (config.enabled === false || !guard.enabled) {
    debugLog(`${event} ${input.tool_name}: disabled`);
    process.exit(0);
  }
  if (event === 'PreToolUse' && guard.preToolUse === 'off') process.exit(0);
  if (event === 'PostToolUse' && guard.postToolUse === 'off') process.exit(0);

  const scanner = buildScanner({
    config,
    configPath: configPath ?? null,
    defaultRulesPath: fileURLToPath(new URL('../data/gitleaks-rules.json', import.meta.url)),
    version: readPluginVersion(fileURLToPath(new URL('../package.json', import.meta.url))),
    maxScanLength: guard.maxScanBytes,
  });

  let output = null;
  if (event === 'PreToolUse') output = checkPreToolUse(input, guard, scanner, readFilePrefix);
  else if (event === 'PostToolUse') output = checkPostToolUse(input, guard, scanner);

  debugLog(`${event} ${input.tool_name}: ${output ? output.hookSpecificOutput.permissionDecision ?? 'warn' : 'allow'}`);
  if (output) console.log(JSON.stringify(output));
  process.exit(0);
} catch (error) {
  debugLog(`ERROR: ${error && error.stack ? error.stack : String(error)}`);
  process.exit(0);
}
