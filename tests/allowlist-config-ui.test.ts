import { describe, expect, test } from '@jest/globals';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { parseAllowlists, validateAllowedPattern } from '../src/cli/validate';
import { writeAllowlists, writeDisabledRules } from '../src/cli/config-writer';
import { PrivacyScanner } from '../src/scanner/engine';
import { BUILTIN_RULES } from '../src/scanner/detectors';

function tempConfigPath(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'privacy-guard-test-'));
  return path.join(dir, '.privacy-guard.json');
}

describe('validateAllowedPattern', () => {
  test('accepts a well-formed regex', () => {
    expect(validateAllowedPattern('^test-[a-z0-9]+$')).toBeNull();
  });

  test('rejects an empty pattern', () => {
    expect(validateAllowedPattern('')).toMatch(/empty/i);
  });

  test('rejects an unparseable regex', () => {
    expect(validateAllowedPattern('([a-z')).toMatch(/invalid regex/i);
  });

  test('rejects a regex prone to catastrophic backtracking', () => {
    expect(validateAllowedPattern('(a+)+$')).toMatch(/unsafe/i);
  });

  test('accepts exactly what the scanner would compile', () => {
    // A pattern the UI accepts must actually take effect in the scanner,
    // which applies the same validity + safety checks at load time.
    const pattern = '^AKIA[A-Z0-9]{16}$';
    expect(validateAllowedPattern(pattern)).toBeNull();

    const scanner = new PrivacyScanner(
      BUILTIN_RULES.filter((r) => r.id === 'aws-api-key'),
      { allowedPatterns: [pattern] }
    );
    expect(scanner.scan('key: AKIAIOSFODNN7EXAMPLE').findings).toHaveLength(0);
  });
});

describe('parseAllowlists', () => {
  test('normalizes domains to lowercase and trims whitespace', () => {
    const result = parseAllowlists({ allowedDomains: ['  Example.COM  ', 'mail.example.com'] });
    expect(result.allowedDomains).toEqual(['example.com', 'mail.example.com']);
  });

  test('drops empty entries and duplicates', () => {
    const result = parseAllowlists({
      allowedDomains: ['example.com', '', 'example.com'],
      allowedValues: ['a', 'a', ''],
      allowedPatterns: ['^a$', '^a$'],
    });
    expect(result.allowedDomains).toEqual(['example.com']);
    expect(result.allowedValues).toEqual(['a']);
    expect(result.allowedPatterns).toEqual(['^a$']);
  });

  test('defaults missing lists to empty arrays', () => {
    expect(parseAllowlists({})).toEqual({ allowedDomains: [], allowedValues: [], allowedPatterns: [] });
  });

  test('rejects non-string-array input', () => {
    expect(() => parseAllowlists({ allowedValues: 'nope' })).toThrow(/allowedValues must be a string array/);
    expect(() => parseAllowlists({ allowedDomains: [1] })).toThrow(/allowedDomains must be a string array/);
  });

  test('rejects the whole payload when any pattern is unusable', () => {
    expect(() => parseAllowlists({ allowedPatterns: ['^ok$', '(a+)+$'] })).toThrow(/unsafe/i);
  });

  test('does not lowercase allowed values (they are matched exactly)', () => {
    expect(parseAllowlists({ allowedValues: ['AKIAIOSFODNN7EXAMPLE'] }).allowedValues).toEqual([
      'AKIAIOSFODNN7EXAMPLE',
    ]);
  });
});

describe('writeAllowlists', () => {
  test('creates a config file with all three lists', () => {
    const configPath = tempConfigPath();
    writeAllowlists(configPath, {
      allowedDomains: ['example.com'],
      allowedValues: ['sample'],
      allowedPatterns: ['^test-'],
    });

    expect(JSON.parse(fs.readFileSync(configPath, 'utf-8'))).toEqual({
      allowedDomains: ['example.com'],
      allowedValues: ['sample'],
      allowedPatterns: ['^test-'],
    });
  });

  test('preserves unrelated keys and existing disabledRules', () => {
    const configPath = tempConfigPath();
    fs.writeFileSync(configPath, JSON.stringify({ mode: 'redact', disabledRules: ['email-address'] }));

    writeAllowlists(configPath, {
      allowedDomains: ['example.com'],
      allowedValues: [],
      allowedPatterns: [],
    });

    const written = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(written.mode).toBe('redact');
    expect(written.disabledRules).toEqual(['email-address']);
    expect(written.allowedDomains).toEqual(['example.com']);
  });

  test('saving rule toggles afterwards leaves allowlists intact', () => {
    const configPath = tempConfigPath();
    writeAllowlists(configPath, {
      allowedDomains: ['example.com'],
      allowedValues: ['sample'],
      allowedPatterns: ['^test-'],
    });
    writeDisabledRules(configPath, ['email-address']);

    const written = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(written.allowedDomains).toEqual(['example.com']);
    expect(written.allowedValues).toEqual(['sample']);
    expect(written.allowedPatterns).toEqual(['^test-']);
    expect(written.disabledRules).toEqual(['email-address']);
  });

  test('refuses to clobber a malformed config', () => {
    const configPath = tempConfigPath();
    fs.writeFileSync(configPath, '{ not json');

    expect(() =>
      writeAllowlists(configPath, { allowedDomains: [], allowedValues: [], allowedPatterns: [] })
    ).toThrow(/Could not parse existing config/);
    expect(fs.readFileSync(configPath, 'utf-8')).toBe('{ not json');
  });
});
