/**
 * The vetted external rule set is cached on disk between hook invocations
 * (issue #57). These tests pin that the cache is invisible except for speed:
 * a hit returns exactly what an uncached load would, and anything that could
 * change the result (data file, filter, plugin version, a damaged cache file)
 * misses or heals instead of serving stale or broken rules.
 */

import { beforeEach, describe, expect, test } from '@jest/globals';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { loadExternalRulesFromJson } from '../src/scanner/detectors';
import { loadExternalRulesCached } from '../src/scanner/rule-cache';

const DATA = path.resolve(process.cwd(), 'data/regex_list_1.json');
const HOOK = path.resolve(__dirname, '../scripts/prompt-guard.js');

let dir: string;
let cacheDir: string;
const opts = () => ({ dir: cacheDir, version: '1.0.0' });
const cacheFile = () => path.join(cacheDir, 'rules-cache.json');

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'privacy-guard-rulecache-'));
  cacheDir = path.join(dir, 'cache');
});

function writeData(entries: object[]): string {
  const file = path.join(dir, 'rules.json');
  fs.writeFileSync(file, JSON.stringify(entries));
  return file;
}

const entry = (name: string, regex: string) => ({
  name,
  description: `${name} api key`,
  regex,
  risk: 8,
  category: 'Secret',
});

describe('loadExternalRulesCached', () => {
  test('first call misses and writes the cache, second call hits', () => {
    const first = loadExternalRulesCached(DATA, { codingOnly: true }, opts());
    expect(first.cacheHit).toBe(false);
    expect(fs.existsSync(cacheFile())).toBe(true);

    const second = loadExternalRulesCached(DATA, { codingOnly: true }, opts());
    expect(second.cacheHit).toBe(true);
  });

  test('a hit returns exactly what the uncached loader returns', () => {
    for (const codingOnly of [true, false]) {
      const uncached = loadExternalRulesFromJson(DATA, { codingOnly });
      loadExternalRulesCached(DATA, { codingOnly }, opts());
      const hit = loadExternalRulesCached(DATA, { codingOnly }, opts());
      expect(hit.cacheHit).toBe(true);
      expect(hit.rules).toEqual(uncached);
      expect(hit.rules.length).toBeGreaterThan(0);
    }
  });

  test('changing the data file invalidates the cache', () => {
    const file = writeData([entry('Acme Key', 'acme_[a-z0-9]{16}')]);
    loadExternalRulesCached(file, { codingOnly: true }, opts());
    expect(loadExternalRulesCached(file, { codingOnly: true }, opts()).cacheHit).toBe(true);

    fs.writeFileSync(file, JSON.stringify([entry('Acme Key', 'acme_[a-z0-9]{16}'), entry('Zed Token', 'zed_[a-z0-9]{16}')]));
    const after = loadExternalRulesCached(file, { codingOnly: true }, opts());
    expect(after.cacheHit).toBe(false);
    expect(after.rules.map((r) => r.title)).toEqual(['Acme Key', 'Zed Token']);
  });

  test('an edit that keeps the file size and mtime is still detected (content-hashed)', () => {
    const file = writeData([entry('Acme Key', 'acme_[a-z0-9]{16}')]);
    const before = fs.statSync(file);
    loadExternalRulesCached(file, { codingOnly: true }, opts());

    fs.writeFileSync(file, JSON.stringify([entry('Acme Key', 'acmf_[a-z0-9]{16}')]));
    fs.utimesSync(file, before.atime, before.mtime);
    expect(fs.statSync(file).size).toBe(before.size);

    const after = loadExternalRulesCached(file, { codingOnly: true }, opts());
    expect(after.cacheHit).toBe(false);
    expect(after.rules[0].pattern).toBe('acmf_[a-z0-9]{16}');
  });

  test('a different codingOnly filter does not reuse the other filter\'s cache', () => {
    const a = loadExternalRulesCached(DATA, { codingOnly: true }, opts());
    const b = loadExternalRulesCached(DATA, { codingOnly: false }, opts());
    expect(b.cacheHit).toBe(false);
    expect(b.rules.length).toBeGreaterThan(a.rules.length);
  });

  test('a different plugin version does not reuse the cache', () => {
    loadExternalRulesCached(DATA, { codingOnly: true }, { dir: cacheDir, version: '1.0.0' });
    const upgraded = loadExternalRulesCached(DATA, { codingOnly: true }, { dir: cacheDir, version: '1.0.1' });
    expect(upgraded.cacheHit).toBe(false);
  });

  test.each([
    ['not JSON', 'this is not json'],
    ['empty file', ''],
    ['truncated JSON', '{"key":"abc","rules":['],
    ['wrong key', JSON.stringify({ key: 'stale', rules: [] })],
    ['rules is not an array', JSON.stringify({ key: 'x', rules: 'nope' })],
  ])('a damaged cache file (%s) is ignored and healed', (_label, contents) => {
    fs.mkdirSync(cacheDir, { recursive: true });
    fs.writeFileSync(cacheFile(), contents);

    const result = loadExternalRulesCached(DATA, { codingOnly: true }, opts());
    expect(result.cacheHit).toBe(false);
    expect(result.rules).toEqual(loadExternalRulesFromJson(DATA, { codingOnly: true }));
    expect(loadExternalRulesCached(DATA, { codingOnly: true }, opts()).cacheHit).toBe(true);
  });

  test('a cache whose rules have the wrong shape is rejected even with a matching key', () => {
    loadExternalRulesCached(DATA, { codingOnly: true }, opts());
    const stored = JSON.parse(fs.readFileSync(cacheFile(), 'utf-8'));

    for (const tamper of [
      (r: any) => { r.pattern = 123; },
      (r: any) => { delete r.id; },
      (r: any) => { r.enabled = false; },
    ]) {
      const copy = JSON.parse(JSON.stringify(stored));
      tamper(copy.rules[0]);
      fs.writeFileSync(cacheFile(), JSON.stringify(copy));
      const result = loadExternalRulesCached(DATA, { codingOnly: true }, opts());
      expect(result.cacheHit).toBe(false);
      expect(result.rules).toEqual(loadExternalRulesFromJson(DATA, { codingOnly: true }));
    }
  });

  test('an unwritable cache directory still returns the rules', () => {
    // A regular file where the cache directory should be makes mkdir fail.
    const blocker = path.join(dir, 'blocker');
    fs.writeFileSync(blocker, 'x');
    const result = loadExternalRulesCached(DATA, { codingOnly: true }, { dir: path.join(blocker, 'sub'), version: '1.0.0' });
    expect(result.cacheHit).toBe(false);
    expect(result.rules).toEqual(loadExternalRulesFromJson(DATA, { codingOnly: true }));
  });

  test('a missing data file behaves like the uncached loader (no rules, no cache written)', () => {
    const result = loadExternalRulesCached(path.join(dir, 'nope.json'), { codingOnly: true }, opts());
    expect(result).toEqual({ rules: [], cacheHit: false });
    expect(fs.existsSync(cacheFile())).toBe(false);
  });

  test('unsafe and invalid entries are vetted out before caching, so a hit never resurrects them', () => {
    const file = writeData([
      entry('Good Token', 'good_[a-z0-9]{16}'),
      entry('Evil Token', '(a+)+$'),
      entry('Empty Token', 'x*'),
      entry('Broken Token', '([unclosed'),
    ]);
    const miss = loadExternalRulesCached(file, { codingOnly: true }, opts());
    const hit = loadExternalRulesCached(file, { codingOnly: true }, opts());
    expect(hit.cacheHit).toBe(true);
    expect(miss.rules.map((r) => r.title)).toEqual(['Good Token']);
    expect(hit.rules).toEqual(miss.rules);
  });

  test('leaves no temp files behind', () => {
    loadExternalRulesCached(DATA, { codingOnly: true }, opts());
    expect(fs.readdirSync(cacheDir)).toEqual(['rules-cache.json']);
  });
});

describe('hook integration', () => {
  function runHook(prompt: string, cwd: string, xdg: string, extraEnv: Record<string, string> = {}) {
    const stdout = execFileSync('node', [HOOK], {
      input: JSON.stringify({ session_id: 's', prompt }),
      cwd,
      env: { ...process.env, XDG_CACHE_HOME: xdg, ...extraEnv },
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'ignore'],
    });
    return stdout.trim() ? JSON.parse(stdout) : null;
  }

  const hookCache = () => path.join(dir, 'xdg', 'claude-code-privacy-guard', 'rules-cache.json');
  // 'AKIA...' is a built-in rule; the external set matters for the second prompt.
  const SECRET_PROMPT = 'my key is sk-proj-1234567890abcdefghij';

  test('first run writes the cache; the second (cache hit) gives the identical verdict', () => {
    const cwd = fs.mkdtempSync(path.join(dir, 'cwd-'));
    const xdg = path.join(dir, 'xdg');

    const cold = runHook(SECRET_PROMPT, cwd, xdg);
    expect(fs.existsSync(hookCache())).toBe(true);
    const warm = runHook(SECRET_PROMPT, cwd, xdg);

    expect(cold.decision).toBe('block');
    expect(warm).toEqual(cold);
  });

  test('a clean prompt passes on both the cold and the cached run', () => {
    const cwd = fs.mkdtempSync(path.join(dir, 'cwd-'));
    const xdg = path.join(dir, 'xdg');
    expect(runHook('refactor the parser', cwd, xdg)).toBeNull();
    expect(runHook('refactor the parser', cwd, xdg)).toBeNull();
  });

  test('changing disabledRules between cached runs takes effect immediately', () => {
    const cwd = fs.mkdtempSync(path.join(dir, 'cwd-'));
    const xdg = path.join(dir, 'xdg');
    const config = path.join(cwd, '.privacy-guard.json');

    expect(runHook(SECRET_PROMPT, cwd, xdg).decision).toBe('block');
    expect(runHook(SECRET_PROMPT, cwd, xdg).decision).toBe('block'); // warm

    fs.writeFileSync(config, JSON.stringify({ disabledRules: ['openai-api-key'] }));
    expect(runHook(SECRET_PROMPT, cwd, xdg)).toBeNull();

    fs.writeFileSync(config, JSON.stringify({ disabledRules: [] }));
    expect(runHook(SECRET_PROMPT, cwd, xdg).decision).toBe('block');
  });

  test('allowlist changes take effect on a warm cache', () => {
    const cwd = fs.mkdtempSync(path.join(dir, 'cwd-'));
    const xdg = path.join(dir, 'xdg');
    runHook(SECRET_PROMPT, cwd, xdg);
    fs.writeFileSync(
      path.join(cwd, '.privacy-guard.json'),
      JSON.stringify({ allowedValues: ['sk-proj-1234567890abcdefghij'] })
    );
    expect(runHook(SECRET_PROMPT, cwd, xdg)).toBeNull();
  });

  test('a corrupted cache file never breaks the hook and is repaired', () => {
    const cwd = fs.mkdtempSync(path.join(dir, 'cwd-'));
    const xdg = path.join(dir, 'xdg');
    runHook(SECRET_PROMPT, cwd, xdg);
    fs.writeFileSync(hookCache(), '{"key": corrupted');

    expect(runHook(SECRET_PROMPT, cwd, xdg).decision).toBe('block');
    expect(JSON.parse(fs.readFileSync(hookCache(), 'utf-8')).rules.length).toBeGreaterThan(0);
  });

  test('PRIVACY_GUARD_NO_CACHE=1 bypasses the cache entirely', () => {
    const cwd = fs.mkdtempSync(path.join(dir, 'cwd-'));
    const xdg = path.join(dir, 'xdg');
    expect(runHook(SECRET_PROMPT, cwd, xdg, { PRIVACY_GUARD_NO_CACHE: '1' }).decision).toBe('block');
    expect(fs.existsSync(hookCache())).toBe(false);
  });

  test('a custom externalRulesJsonPath is cached by content, not path', () => {
    const cwd = fs.mkdtempSync(path.join(dir, 'cwd-'));
    const xdg = path.join(dir, 'xdg');
    const rulesFile = path.join(cwd, 'custom.json');
    fs.writeFileSync(rulesFile, JSON.stringify([entry('Acme Token', 'acme_[a-z0-9]{16}')]));
    fs.writeFileSync(path.join(cwd, '.privacy-guard.json'), JSON.stringify({ externalRulesJsonPath: './custom.json' }));

    const prompt = 'use acme_abcdef0123456789 here';
    expect(runHook(prompt, cwd, xdg).decision).toBe('block');
    expect(runHook(prompt, cwd, xdg).decision).toBe('block'); // warm

    // Editing the custom file must not be served from the old cache.
    fs.writeFileSync(rulesFile, JSON.stringify([entry('Zed Token', 'zed_[a-z0-9]{16}')]));
    expect(runHook(prompt, cwd, xdg)).toBeNull();
  });
});
