/**
 * When "enabled": false is set, the hook passes every prompt through
 * unscanned. Without a visible signal, a stale or forgotten config line can
 * silently disable protection with no way to notice. The hook emits one
 * systemMessage per session_id (not per prompt) so it isn't repeated on
 * every submission within the same session.
 */

import { describe, expect, test } from '@jest/globals';
import { execFileSync } from 'child_process';
import { mkdtempSync, writeFileSync } from 'fs';
import * as os from 'os';
import * as path from 'path';

const HOOK = path.resolve(__dirname, '../scripts/prompt-guard.js');

function runHook(sessionId: string, cacheDir: string, cwd: string): { systemMessage?: string } | null {
  const stdout = execFileSync('node', [HOOK], {
    input: JSON.stringify({ session_id: sessionId, prompt: 'refactor the parser' }),
    cwd,
    env: { ...process.env, XDG_CACHE_HOME: cacheDir },
    encoding: 'utf-8',
    stdio: ['pipe', 'pipe', 'ignore'],
  });
  return stdout.trim() ? JSON.parse(stdout) : null;
}

describe('disabled-by-config notice', () => {
  test('emits a systemMessage the first time a session sees enabled: false, then stays quiet', () => {
    const cwd = mkdtempSync(path.join(os.tmpdir(), 'privacy-guard-disabled-'));
    const cacheDir = mkdtempSync(path.join(os.tmpdir(), 'privacy-guard-cache-'));
    writeFileSync(path.join(cwd, '.privacy-guard.json'), JSON.stringify({ enabled: false }));

    const first = runHook('session-a', cacheDir, cwd);
    expect(first?.systemMessage).toContain('Privacy Guard is disabled');

    const second = runHook('session-a', cacheDir, cwd);
    expect(second).toBeNull();
  });

  test('notices again for a new session_id', () => {
    const cwd = mkdtempSync(path.join(os.tmpdir(), 'privacy-guard-disabled-'));
    const cacheDir = mkdtempSync(path.join(os.tmpdir(), 'privacy-guard-cache-'));
    writeFileSync(path.join(cwd, '.privacy-guard.json'), JSON.stringify({ enabled: false }));

    runHook('session-b', cacheDir, cwd);
    const differentSession = runHook('session-c', cacheDir, cwd);
    expect(differentSession?.systemMessage).toContain('Privacy Guard is disabled');
  });

  test('prompt still passes through unscanned while disabled', () => {
    const cwd = mkdtempSync(path.join(os.tmpdir(), 'privacy-guard-disabled-'));
    const cacheDir = mkdtempSync(path.join(os.tmpdir(), 'privacy-guard-cache-'));
    writeFileSync(path.join(cwd, '.privacy-guard.json'), JSON.stringify({ enabled: false }));

    const stdout = execFileSync('node', [HOOK], {
      input: JSON.stringify({ session_id: 'session-d', prompt: 'my email is john.doe@example.com' }),
      cwd,
      env: { ...process.env, XDG_CACHE_HOME: cacheDir },
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'ignore'],
    });
    const response = stdout.trim() ? JSON.parse(stdout) : null;
    expect(response?.decision).toBeUndefined();
  });
});
