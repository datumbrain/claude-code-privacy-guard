import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { afterEach, beforeEach, describe, expect, jest, test } from '@jest/globals';
import { loadExternalRulesFromJson } from '../src/scanner/detectors';
import { loadExternalRulesCached } from '../src/scanner/rule-cache';

const entry = (name: string, regex: string) => ({
  name,
  description: `${name} api key`,
  regex,
  risk: 7,
  category: 'Credentials',
});

let dir: string;
let rulesFile: string;
let cacheDir: string;

function writeRules(entries: unknown[]) {
  fs.writeFileSync(rulesFile, JSON.stringify(entries));
}

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pg-cache-'));
  rulesFile = path.join(dir, 'rules.json');
  cacheDir = path.join(dir, 'cache');
  writeRules([entry('Acme token', 'acme_[a-z0-9]{20}')]);
});

afterEach(() => {
  jest.restoreAllMocks();
  fs.rmSync(dir, { recursive: true, force: true });
});

const opts = { codingOnly: true };
const cache = (version = '1.0.0') => ({ cacheDir, version });

describe('loadExternalRulesCached', () => {
  test('returns the same rules as an uncached load', () => {
    const cached = loadExternalRulesCached(rulesFile, opts, cache());
    const direct = loadExternalRulesFromJson(rulesFile, opts);
    expect(cached).toEqual(direct);
  });

  test('works on the real bundled ruleset', () => {
    const real = path.resolve(process.cwd(), 'data/regex_list_1.json');
    const first = loadExternalRulesCached(real, opts, cache());
    const second = loadExternalRulesCached(real, opts, cache());
    expect(second).toEqual(first);
    expect(second).toEqual(loadExternalRulesFromJson(real, opts));
  });

  test('writes a cache file on first load', () => {
    loadExternalRulesCached(rulesFile, opts, cache());
    expect(fs.existsSync(path.join(cacheDir, 'external-rules-cache.json'))).toBe(true);
  });

  test('serves from the cache file, not the source, when the key matches', () => {
    loadExternalRulesCached(rulesFile, opts, cache());
    const cacheFile = path.join(cacheDir, 'external-rules-cache.json');
    const stored = JSON.parse(fs.readFileSync(cacheFile, 'utf-8'));
    const key = Object.keys(stored.entries)[0];
    stored.entries[key][0].title = 'FROM-CACHE';
    fs.writeFileSync(cacheFile, JSON.stringify(stored));
    expect(loadExternalRulesCached(rulesFile, opts, cache())[0].title).toBe('FROM-CACHE');
  });

  test('invalidates when the rules file content changes', () => {
    expect(loadExternalRulesCached(rulesFile, opts, cache()).map((r) => r.title)).toEqual(['Acme token']);
    writeRules([entry('Globex token', 'globex_[a-z0-9]{20}')]);
    expect(loadExternalRulesCached(rulesFile, opts, cache()).map((r) => r.title)).toEqual(['Globex token']);
  });

  test('invalidates when codingOnly changes', () => {
    writeRules([entry('Acme token', 'acme_[a-z0-9]{20}'), { name: 'Cisco router', description: 'router', regex: 'rtr-[0-9]{6}', risk: 3, category: 'Confidential' }]);
    const codingOnly = loadExternalRulesCached(rulesFile, { codingOnly: true }, cache());
    const all = loadExternalRulesCached(rulesFile, { codingOnly: false }, cache());
    expect(codingOnly).toHaveLength(1);
    expect(all).toHaveLength(2);
  });

  test('invalidates across plugin version upgrades', () => {
    loadExternalRulesCached(rulesFile, opts, cache('1.0.0'));
    const cacheFile = path.join(cacheDir, 'external-rules-cache.json');
    const stored = JSON.parse(fs.readFileSync(cacheFile, 'utf-8'));
    const key = Object.keys(stored.entries)[0];
    stored.entries[key][0].title = 'STALE';
    fs.writeFileSync(cacheFile, JSON.stringify(stored));

    expect(loadExternalRulesCached(rulesFile, opts, cache('1.0.0'))[0].title).toBe('STALE');
    expect(loadExternalRulesCached(rulesFile, opts, cache('1.1.0'))[0].title).toBe('Acme token');
  });

  test('a corrupt cache file falls back to a normal load', () => {
    fs.mkdirSync(cacheDir, { recursive: true });
    fs.writeFileSync(path.join(cacheDir, 'external-rules-cache.json'), '{not json');
    expect(loadExternalRulesCached(rulesFile, opts, cache()).map((r) => r.title)).toEqual(['Acme token']);
  });

  test('an unwritable cache dir falls back to a normal load', () => {
    const blocker = path.join(dir, 'blocker');
    fs.writeFileSync(blocker, 'a file, not a directory');
    const rules = loadExternalRulesCached(rulesFile, opts, { cacheDir: path.join(blocker, 'cache'), version: '1' });
    expect(rules.map((r) => r.title)).toEqual(['Acme token']);
  });

  test('a missing rules file yields no rules', () => {
    expect(loadExternalRulesCached(path.join(dir, 'nope.json'), opts, cache())).toEqual([]);
  });

  test('keeps entries for several rule files without unbounded growth', () => {
    for (let i = 0; i < 12; i++) {
      writeRules([entry(`Rule ${i}`, `r${i}_[a-z0-9]{20}`)]);
      loadExternalRulesCached(rulesFile, opts, cache());
    }
    const stored = JSON.parse(fs.readFileSync(path.join(cacheDir, 'external-rules-cache.json'), 'utf-8'));
    expect(Object.keys(stored.entries).length).toBeLessThanOrEqual(8);
  });
});
