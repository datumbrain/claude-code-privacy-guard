import { describe, expect, jest, test } from '@jest/globals';
import { PrivacyScanner } from '../src/scanner/engine';
import { BUILTIN_RULES } from '../src/scanner/detectors';

const awsKeyRule = BUILTIN_RULES.filter((r) => r.id === 'aws-api-key');
const emailRule = BUILTIN_RULES.filter((r) => r.id === 'email-address');

describe('allowedValues', () => {
  test('suppresses a finding whose exact matched value is allowlisted', () => {
    const scanner = new PrivacyScanner(awsKeyRule, { allowedValues: ['AKIAIOSFODNN7EXAMPLE'] });
    const result = scanner.scan('key: AKIAIOSFODNN7EXAMPLE');
    expect(result.findings).toHaveLength(0);
  });

  test('still flags values not on the allowlist', () => {
    const scanner = new PrivacyScanner(awsKeyRule, { allowedValues: ['AKIAIOSFODNN7EXAMPLE'] });
    const result = scanner.scan('key: AKIAABCDEFGHIJKLMNOP');
    expect(result.findings).toHaveLength(1);
  });

  test('comparison is case-sensitive', () => {
    const scanner = new PrivacyScanner(awsKeyRule, { allowedValues: ['akiaiosfodnn7example'] });
    const result = scanner.scan('key: AKIAIOSFODNN7EXAMPLE');
    expect(result.findings).toHaveLength(1);
  });

  test('applies across any rule, not just email-address', () => {
    const scanner = new PrivacyScanner(BUILTIN_RULES, { allowedValues: ['AKIAIOSFODNN7EXAMPLE'] });
    const result = scanner.scan('key: AKIAIOSFODNN7EXAMPLE and email: user@company.co.uk');
    const ids = result.findings.map((f) => f.ruleId);
    expect(ids).not.toContain('aws-api-key');
    expect(ids).toContain('email-address');
  });

  test('empty allowlist leaves findings untouched', () => {
    const scanner = new PrivacyScanner(awsKeyRule, { allowedValues: [] });
    const result = scanner.scan('key: AKIAIOSFODNN7EXAMPLE');
    expect(result.findings).toHaveLength(1);
  });
});

describe('allowedPatterns', () => {
  test('suppresses findings matching an allowlisted regex', () => {
    const scanner = new PrivacyScanner(awsKeyRule, { allowedPatterns: ['^AKIAIOSFODNN7'] });
    const result = scanner.scan('key: AKIAIOSFODNN7EXAMPLE');
    expect(result.findings).toHaveLength(0);
  });

  test('still flags values not matching the pattern', () => {
    const scanner = new PrivacyScanner(awsKeyRule, { allowedPatterns: ['^AKIAIOSFODNN7'] });
    const result = scanner.scan('key: AKIAZZZZZZZZZZZZZZZZ');
    expect(result.findings).toHaveLength(1);
  });

  test('applies across any rule, not just email-address', () => {
    const scanner = new PrivacyScanner(emailRule, { allowedPatterns: ['@example\\.com$'] });
    const result = scanner.scan('user@example.com and user@company.co.uk');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].match).toBe('user@company.co.uk');
  });

  test('skips an invalid regex with a warning instead of throwing', () => {
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const scanner = new PrivacyScanner(awsKeyRule, { allowedPatterns: ['(unterminated'] });
      const result = scanner.scan('key: AKIAIOSFODNN7EXAMPLE');
      expect(result.findings).toHaveLength(1);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('invalid regex'));
    } finally {
      warnSpy.mockRestore();
    }
  });

  test('skips a catastrophic-backtracking pattern with a warning instead of using it', () => {
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const scanner = new PrivacyScanner(awsKeyRule, { allowedPatterns: ['(x+x+)+y'] });
      const result = scanner.scan('key: AKIAIOSFODNN7EXAMPLE');
      expect(result.findings).toHaveLength(1);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('unsafe'));
    } finally {
      warnSpy.mockRestore();
    }
  });

  test('empty allowlist leaves findings untouched', () => {
    const scanner = new PrivacyScanner(awsKeyRule, { allowedPatterns: [] });
    const result = scanner.scan('key: AKIAIOSFODNN7EXAMPLE');
    expect(result.findings).toHaveLength(1);
  });
});
