import { describe, expect, test } from '@jest/globals';
import { PrivacyScanner } from '../src/scanner/engine';
import { BUILTIN_RULES } from '../src/scanner/detectors';

const emailRule = BUILTIN_RULES.filter((r) => r.id === 'email-address');

describe('allowedDomains', () => {
  test('suppresses email findings whose domain is allowlisted', () => {
    const scanner = new PrivacyScanner(emailRule, { allowedDomains: ['example.com'] });
    const result = scanner.scan('reach me at user@example.com please');
    expect(result.findings).toHaveLength(0);
  });

  test('still flags emails on non-allowlisted domains', () => {
    const scanner = new PrivacyScanner(emailRule, { allowedDomains: ['example.com'] });
    const result = scanner.scan('reach me at user@company.co.uk please');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].ruleId).toBe('email-address');
  });

  test('matches subdomains of an allowlisted domain', () => {
    const scanner = new PrivacyScanner(emailRule, { allowedDomains: ['example.com'] });
    const result = scanner.scan('user@mail.example.com');
    expect(result.findings).toHaveLength(0);
  });

  test('does not treat a suffix collision as a subdomain match', () => {
    const scanner = new PrivacyScanner(emailRule, { allowedDomains: ['example.com'] });
    // notexample.com must NOT be allowed just because it ends with example.com
    const result = scanner.scan('user@notexample.com');
    expect(result.findings).toHaveLength(1);
  });

  test('matching is case-insensitive', () => {
    const scanner = new PrivacyScanner(emailRule, { allowedDomains: ['Example.COM'] });
    const result = scanner.scan('User@EXAMPLE.com');
    expect(result.findings).toHaveLength(0);
  });

  test('empty allowlist leaves email findings untouched', () => {
    const scanner = new PrivacyScanner(emailRule, { allowedDomains: [] });
    const result = scanner.scan('user@example.com');
    expect(result.findings).toHaveLength(1);
  });

  test('only applies to email findings, not other rules', () => {
    // An allowlisted domain must not suppress a same-looking match from a
    // different rule; use the full rule set and a non-email secret.
    const scanner = new PrivacyScanner(BUILTIN_RULES, { allowedDomains: ['example.com'] });
    const result = scanner.scan('user@example.com and token ghp_1234567890abcdefghijklmnopqrstuvwxyz');
    const ids = result.findings.map((f) => f.ruleId);
    expect(ids).not.toContain('email-address');
    expect(result.findings.length).toBeGreaterThan(0);
  });
});
