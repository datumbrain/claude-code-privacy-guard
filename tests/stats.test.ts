/**
 * The prompt hook keeps counts of detections per session and globally in
 * stats.json. Only counts keyed by category and rule id are stored, never
 * matched values.
 */

import { describe, expect, test } from '@jest/globals';
import { execFileSync } from 'child_process';
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from 'fs';
import * as os from 'os';
import * as path from 'path';
import { recordPrompt, SESSION_RETENTION_DAYS } from '../src/hook/stats';
import { ScanResult } from '../src/types/findings';

const HOOK = path.resolve(__dirname, '../scripts/prompt-guard.js');

function result(findings: Array<{ ruleId: string; category: string }>): ScanResult {
  return { findings, originalText: '', redactedText: '', riskScore: 0, hasHighRisk: false, hasCriticalRisk: false, summary: {} } as unknown as ScanResult;
}

const tmp = (prefix: string) => mkdtempSync(path.join(os.tmpdir(), prefix));

describe('recordPrompt', () => {
  test('counts prompts and findings globally and per session', () => {
    const dir = tmp('pg-stats-');
    recordPrompt(dir, 's1', result([{ ruleId: 'email', category: 'pii' }, { ruleId: 'aws-key', category: 'secret' }]));
    const stats = recordPrompt(dir, 's1', result([{ ruleId: 'email', category: 'pii' }]))!;

    expect(stats.global).toEqual({ totalPrompts: 2, totalFindings: 3, byCategory: { pii: 2, secret: 1 }, byRule: { email: 2, 'aws-key': 1 } });
    expect(stats.sessions.s1.totalPrompts).toBe(2);
    expect(stats.sessions.s1.byRule.email).toBe(2);
  });

  test('clean prompts still count as prompts', () => {
    const stats = recordPrompt(tmp('pg-stats-'), 's1', result([]))!;
    expect(stats.global.totalPrompts).toBe(1);
    expect(stats.global.totalFindings).toBe(0);
  });

  test('without a session id only the global totals change', () => {
    const stats = recordPrompt(tmp('pg-stats-'), undefined, result([{ ruleId: 'email', category: 'pii' }]))!;
    expect(stats.global.totalFindings).toBe(1);
    expect(stats.sessions).toEqual({});
  });

  test('prunes sessions idle longer than the retention window', () => {
    const dir = tmp('pg-stats-');
    const old = new Date(Date.now() - (SESSION_RETENTION_DAYS + 1) * 24 * 60 * 60 * 1000);
    recordPrompt(dir, 'old', result([]), old);
    const stats = recordPrompt(dir, 'new', result([]))!;
    expect(Object.keys(stats.sessions)).toEqual(['new']);
    expect(stats.global.totalPrompts).toBe(2);
  });

  test('recovers from a corrupt stats file', () => {
    const dir = tmp('pg-stats-');
    writeFileSync(path.join(dir, 'stats.json'), '{not json');
    const stats = recordPrompt(dir, 's1', result([]))!;
    expect(stats.global.totalPrompts).toBe(1);
  });
});

describe('prompt hook integration', () => {
  function run(cacheDir: string, cwd: string, prompt: string) {
    try {
      execFileSync('node', [HOOK], {
        input: JSON.stringify({ session_id: 'sess-1', prompt }),
        cwd,
        env: { ...process.env, XDG_CACHE_HOME: cacheDir },
        stdio: ['pipe', 'pipe', 'ignore'],
      });
    } catch {
      // A non-zero exit is irrelevant here; only the stats file matters.
    }
  }

  test('writes stats without storing the matched value', () => {
    const cwd = tmp('pg-stats-cwd-');
    const cache = tmp('pg-stats-cache-');
    run(cache, cwd, 'my key is AKIAIOSFODNN7EXAMPLX and refactor the parser');
    run(cache, cwd, 'refactor the parser');

    const file = path.join(cache, 'claude-code-privacy-guard', 'stats.json');
    expect(existsSync(file)).toBe(true);
    const raw = readFileSync(file, 'utf-8');
    const stats = JSON.parse(raw);
    expect(stats.global.totalPrompts).toBe(2);
    expect(stats.sessions['sess-1'].totalPrompts).toBe(2);
    expect(raw).not.toContain('AKIAIOSFODNN7EXAMPLX');
  });
});
