/**
 * Tests for the PreToolUse / PostToolUse guard (issue #11): the pure decision
 * logic in src/hook/tool-guard.ts, and the scripts/tool-guard.js hook end to
 * end (spawned like Claude Code does, with a JSON envelope on stdin).
 */

import { describe, expect, test } from '@jest/globals';
import { execFileSync } from 'child_process';
import { mkdtempSync, writeFileSync } from 'fs';
import * as os from 'os';
import * as path from 'path';
import { PrivacyScanner } from '../src/scanner/engine';
import { BUILTIN_RULES } from '../src/scanner/detectors';
import { ConfigLoader } from '../src/config/loader';
import {
  bashExposureReason,
  checkPostToolUse,
  checkPreToolUse,
  collectText,
  FileReader,
  isSensitivePath,
  resolveToolGuardConfig,
} from '../src/hook/tool-guard';

const guard = resolveToolGuardConfig(undefined);
const scanner = new PrivacyScanner(BUILTIN_RULES);
const noFiles: FileReader = () => null;

describe('isSensitivePath', () => {
  test.each([
    '.env',
    '/repo/.env',
    '/repo/.env.local',
    '/repo/.env.production',
    'C:\\repo\\.env',
    '/home/me/.aws/credentials',
    '~/.ssh/id_rsa',
    '/home/me/.ssh/id_ed25519',
    'certs/server.pem',
    'tls/private.key',
    '/home/me/.netrc',
    '/home/me/.git-credentials',
    '/home/me/.docker/config.json',
    '/home/me/.kube/config',
    'gcp/service-account-prod.json',
    '/proc/self/environ',
  ])('flags %s', (p: string) => {
    expect(isSensitivePath(p, guard)).toBe(true);
  });

  test.each([
    '.env.example',
    '/repo/.env.sample',
    '/repo/.env.template',
    '/home/me/.ssh/id_rsa.pub',
    '/home/me/.ssh/config',
    '/home/me/.aws/config',
    'src/env.ts',
    'src/keyboard.ts',
    'docs/environment.md',
    'README.md',
  ])('does not flag %s', (p: string) => {
    expect(isSensitivePath(p, guard)).toBe(false);
  });

  test('extra sensitivePaths and allowedPaths from config', () => {
    const custom = resolveToolGuardConfig({ sensitivePaths: ['secrets/**', '*.secret'], allowedPaths: ['.env.test'] });
    expect(isSensitivePath('repo/secrets/db/prod.yaml', custom)).toBe(true);
    expect(isSensitivePath('a/b/token.secret', custom)).toBe(true);
    expect(isSensitivePath('.env.test', custom)).toBe(false);
    expect(isSensitivePath('.env.local', custom)).toBe(true);
  });
});

describe('bashExposureReason', () => {
  test.each([
    'cat .env',
    'cat ~/.aws/credentials',
    'head -n 5 config/.env.production',
    'grep API_KEY .env',
    'less ~/.ssh/id_rsa',
    'base64 -i server.pem',
    'cat < .env',
    'env',
    'env | sort',
    'printenv',
    'printenv | grep KEY',
    'echo start; env',
    'export -p',
  ])('flags %s', (cmd: string) => {
    expect(bashExposureReason(cmd, guard)).not.toBeNull();
  });

  test.each([
    'npm test',
    'source .env && npm run dev',
    'ls -la .env',
    'cp .env.example .env',
    'docker run --env-file .env app',
    'env NODE_ENV=test npm test',
    'printenv HOME',
    'set -euo pipefail; make build',
    'cat .env.example',
    'git status',
    'cat README.md',
    "grep -r 'process.env' src",
  ])('does not flag %s', (cmd: string) => {
    expect(bashExposureReason(cmd, guard)).toBeNull();
  });
});

describe('checkPreToolUse', () => {
  const pre = (tool_name: string, tool_input: Record<string, unknown>, g = guard, read: FileReader = noFiles) =>
    checkPreToolUse({ hook_event_name: 'PreToolUse', tool_name, tool_input, cwd: '/repo' }, g, scanner, read);

  test('asks before reading a credentials file', () => {
    const out = pre('Read', { file_path: '/repo/.env' });
    expect(out?.hookSpecificOutput.permissionDecision).toBe('ask');
    expect(out?.hookSpecificOutput.permissionDecisionReason).toMatch(/\.env/);
  });

  test('denies instead when preToolUse is "deny"', () => {
    const out = pre('Read', { file_path: '/repo/.env' }, resolveToolGuardConfig({ preToolUse: 'deny' }));
    expect(out?.hookSpecificOutput.permissionDecision).toBe('deny');
  });

  test('does nothing when preToolUse is "off" or the guard is disabled', () => {
    expect(pre('Read', { file_path: '/repo/.env' }, resolveToolGuardConfig({ preToolUse: 'off' }))).toBeNull();
    expect(pre('Read', { file_path: '/repo/.env' }, resolveToolGuardConfig({ enabled: false }))).toBeNull();
  });

  test('scans the contents of an ordinary file and asks when it holds a secret', () => {
    const reader = (p: string) => (p === path.resolve('/repo', 'src/config.js') ? 'const k = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";' : null);
    const out = pre('Read', { file_path: 'src/config.js' }, guard, reader);
    expect(out?.hookSpecificOutput.permissionDecision).toBe('ask');
    expect(out?.hookSpecificOutput.permissionDecisionReason).toMatch(/GitHub Token/);
    // The reason never contains the full secret.
    expect(out?.hookSpecificOutput.permissionDecisionReason).not.toMatch(/ghp_abcdefghijklmnopqrstuvwxyz1234567890/);
  });

  test('allows an ordinary file without secrets', () => {
    expect(pre('Read', { file_path: 'src/app.js' }, guard, () => 'export const x = 1;')).toBeNull();
  });

  test('allowedPaths skips both the path check and the content scan', () => {
    const g = resolveToolGuardConfig({ allowedPaths: ['.env'] });
    expect(pre('Read', { file_path: '/repo/.env' }, g, () => 'API_KEY=hunter2hunter2hunter2live')).toBeNull();
  });

  test('guards Grep on a sensitive path and Bash env dumps', () => {
    expect(pre('Grep', { pattern: 'KEY', path: '/repo/.env' })?.hookSpecificOutput.permissionDecision).toBe('ask');
    expect(pre('Grep', { pattern: 'KEY', path: '/repo/src' })).toBeNull();
    expect(pre('Bash', { command: 'printenv' })?.hookSpecificOutput.permissionDecision).toBe('ask');
    expect(pre('Bash', { command: 'npm test' })).toBeNull();
  });

  test('ignores other tools', () => {
    expect(pre('Write', { file_path: '/repo/.env', content: 'x' })).toBeNull();
  });
});

describe('checkPostToolUse', () => {
  const post = (tool_response: unknown, g = guard) =>
    checkPostToolUse({ hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_response }, g, scanner);

  test('warns the user and tells Claude not to repeat secrets found in output', () => {
    const out = post({ stdout: 'AWS key AKIAIOSFODNN7EXAMPLE found', stderr: '' });
    expect(out?.systemMessage).toMatch(/AWS/);
    expect(out?.systemMessage).toMatch(/rotat/i);
    expect(out?.hookSpecificOutput.additionalContext).toMatch(/Do not repeat/);
    expect(out?.systemMessage).not.toMatch(/AKIAIOSFODNN7EXAMPLE/);
  });

  test('stays quiet for clean output and when off', () => {
    expect(post({ stdout: 'all tests passed' })).toBeNull();
    expect(post({ stdout: 'AKIAIOSFODNN7EXAMPLE' }, resolveToolGuardConfig({ postToolUse: 'off' }))).toBeNull();
  });

  test('collectText walks nested responses and respects the size cap', () => {
    expect(collectText({ file: { content: 'abc', lines: ['d', 'e'] }, n: 3 }, 1000)).toBe('abc\nd\ne');
    expect(collectText({ a: 'x'.repeat(500), b: 'y'.repeat(500) }, 100).length).toBeLessThanOrEqual(100);
  });
});

describe('toolGuard config loading', () => {
  function load(content: unknown) {
    const file = path.join(mkdtempSync(path.join(os.tmpdir(), 'pg-tg-')), '.privacy-guard.json');
    writeFileSync(file, JSON.stringify(content));
    return new ConfigLoader(file).getConfig();
  }

  test('keeps valid fields and drops malformed ones', () => {
    const config = load({
      toolGuard: { preToolUse: 'deny', postToolUse: 'nope', allowedPaths: ['.env', 3], maxScanBytes: -1 },
    });
    expect(config.toolGuard).toEqual({ preToolUse: 'deny', allowedPaths: ['.env'] });
    expect(resolveToolGuardConfig(config.toolGuard).postToolUse).toBe('warn');
  });
});

describe('scripts/tool-guard.js end to end', () => {
  const HOOK = path.resolve(__dirname, '../scripts/tool-guard.js');

  function run(envelope: Record<string, unknown> | string, config?: Record<string, unknown>, files: Record<string, string> = {}) {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'pg-tool-hook-'));
    if (config) writeFileSync(path.join(dir, '.privacy-guard.json'), JSON.stringify(config));
    for (const [name, content] of Object.entries(files)) writeFileSync(path.join(dir, name), content);
    const input = typeof envelope === 'string' ? envelope : JSON.stringify({ cwd: dir, ...envelope });
    const stdout = execFileSync('node', [HOOK], {
      input,
      cwd: dir,
      encoding: 'utf-8',
      env: { ...process.env, XDG_CACHE_HOME: path.join(dir, 'cache') },
      stdio: ['pipe', 'pipe', 'ignore'],
    });
    return stdout.trim() ? JSON.parse(stdout) : null;
  }

  test('asks before Read of .env', () => {
    const out = run({ hook_event_name: 'PreToolUse', tool_name: 'Read', tool_input: { file_path: '.env' } }, undefined, {
      '.env': 'API_KEY=hunter2hunter2hunter2live\n',
    });
    expect(out.hookSpecificOutput.permissionDecision).toBe('ask');
  });

  test('asks before Read of a file containing a gitleaks-detected secret', () => {
    const out = run({ hook_event_name: 'PreToolUse', tool_name: 'Read', tool_input: { file_path: 'pay.js' } }, undefined, {
      // Fake token assembled at runtime so push protection doesn't flag the fixture.
      'pay.js': `const stripe = "${['sk', 'live', '4eC39HqLyjWDarjtT1zdp7dc'].join('_')}";\n`,
    });
    expect(out.hookSpecificOutput.permissionDecision).toBe('ask');
    expect(out.hookSpecificOutput.permissionDecisionReason).toMatch(/stripe/i);
  });

  test('allows a clean Read with no output', () => {
    expect(
      run({ hook_event_name: 'PreToolUse', tool_name: 'Read', tool_input: { file_path: 'a.js' } }, undefined, { 'a.js': 'x = 1\n' })
    ).toBeNull();
  });

  test('warns on secrets in PostToolUse output', () => {
    const out = run({
      hook_event_name: 'PostToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'cat x' },
      tool_response: { stdout: 'ghp_abcdefghijklmnopqrstuvwxyz1234567890', stderr: '' },
    });
    expect(out.hookSpecificOutput.hookEventName).toBe('PostToolUse');
    expect(out.systemMessage).toMatch(/GitHub Token/);
  });

  test('respects enabled: false and toolGuard.enabled: false', () => {
    const env = { hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'env' } };
    expect(run(env, { enabled: false })).toBeNull();
    expect(run(env, { toolGuard: { enabled: false } })).toBeNull();
  });

  test('fails open on garbage input', () => {
    expect(run('not json at all')).toBeNull();
  });
});
