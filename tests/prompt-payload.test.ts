/**
 * End-to-end tests for the UserPromptSubmit hook script's stdin handling.
 *
 * Claude Code pipes a JSON envelope (session_id, transcript_path, cwd, prompt,
 * ...) into the hook - not the bare prompt. The hook must scan and echo back
 * only the "prompt" field; scanning the envelope produced false positives on
 * paths/ids and leaked the whole JSON into redact mode's cleaned copy.
 */

import { describe, expect, test } from '@jest/globals';
import { execFileSync } from 'child_process';
import { mkdtempSync, writeFileSync } from 'fs';
import * as os from 'os';
import * as path from 'path';

const HOOK = path.resolve(__dirname, '../scripts/prompt-guard.js');

function runHook(stdin: string, config: Record<string, unknown>): { decision?: string; reason?: string; systemMessage?: string } | null {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'privacy-guard-hook-'));
  writeFileSync(path.join(dir, '.privacy-guard.json'), JSON.stringify(config));
  const stdout = execFileSync('node', [HOOK], {
    input: stdin,
    cwd: dir,
    encoding: 'utf-8',
    stdio: ['pipe', 'pipe', 'ignore'],
  });
  return stdout.trim() ? JSON.parse(stdout) : null;
}

const ENVELOPE = {
  session_id: 'a24ce33f-3780-491d-8d22-aa4d88f34bd1',
  transcript_path: '/Users/someone/.claude/projects/-Users-someone-proj/a24ce33f.jsonl',
  cwd: '/Users/someone/Projects/proj',
  prompt_id: 'c8320832-4a29-41d5-aa58-359903658ce6',
  permission_mode: 'default',
  hook_event_name: 'UserPromptSubmit',
  prompt: 'my email is john.doe@example.com',
};

describe('hook stdin payload handling', () => {
  test('redact mode returns the cleaned prompt, not the JSON envelope', () => {
    const response = runHook(JSON.stringify(ENVELOPE), { mode: 'redact' });

    expect(response?.decision).toBe('block');
    expect(response?.reason).toContain('---\nmy email is <PII_1>\n---');
    expect(response?.reason).not.toContain('session_id');
    expect(response?.reason).not.toContain('hook_event_name');
  });

  test('scans only the prompt field, not envelope metadata', () => {
    const clean = { ...ENVELOPE, prompt: 'refactor the parser' };
    expect(runHook(JSON.stringify(clean), { mode: 'block' })).toBeNull();
  });

  test('still blocks on sensitive data inside the prompt field', () => {
    const response = runHook(JSON.stringify(ENVELOPE), { mode: 'block' });

    expect(response?.decision).toBe('block');
    expect(response?.reason).toContain('Email Address');
  });

  test('falls back to scanning raw stdin when it is not a JSON envelope', () => {
    const response = runHook('my email is john.doe@example.com', { mode: 'block' });

    expect(response?.decision).toBe('block');
    expect(response?.reason).toContain('Email Address');
  });
});
