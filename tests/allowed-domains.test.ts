import { describe, expect, test } from '@jest/globals';
import { PrivacyScanner } from '../src/scanner/engine';
import { BUILTIN_RULES } from '../src/scanner/detectors';

const emailRule = BUILTIN_RULES.filter((r) => r.id === 'email-address');

describe('allowedDomains', () => {
  test('suppresses email findings whose domain is allowlisted', () => {
    const scanner = new PrivacyScanner(emailRule, { allowedDomains: ['acme-corp.io'] });
    const result = scanner.scan('reach me at user@acme-corp.io please');
    expect(result.findings).toHaveLength(0);
  });

  test('still flags emails on non-allowlisted domains', () => {
    const scanner = new PrivacyScanner(emailRule, { allowedDomains: ['acme-corp.io'] });
    const result = scanner.scan('reach me at user@company.co.uk please');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].ruleId).toBe('email-address');
  });

  test('matches subdomains of an allowlisted domain', () => {
    const scanner = new PrivacyScanner(emailRule, { allowedDomains: ['acme-corp.io'] });
    const result = scanner.scan('user@mail.acme-corp.io');
    expect(result.findings).toHaveLength(0);
  });

  test('does not treat a suffix collision as a subdomain match', () => {
    const scanner = new PrivacyScanner(emailRule, { allowedDomains: ['acme-corp.io'] });
    // notacme-corp.io must NOT be allowed just because it ends with acme-corp.io
    const result = scanner.scan('user@notacme-corp.io');
    expect(result.findings).toHaveLength(1);
  });

  test('matching is case-insensitive', () => {
    const scanner = new PrivacyScanner(emailRule, { allowedDomains: ['Acme-Corp.IO'] });
    const result = scanner.scan('User@ACME-CORP.io');
    expect(result.findings).toHaveLength(0);
  });

  test('empty allowlist leaves email findings untouched', () => {
    const scanner = new PrivacyScanner(emailRule, { allowedDomains: [] });
    const result = scanner.scan('user@acme-corp.io');
    expect(result.findings).toHaveLength(1);
  });

  test('only applies to email findings, not other rules', () => {
    // An allowlisted domain must not suppress a same-looking match from a
    // different rule; use the full rule set and a non-email secret.
    const scanner = new PrivacyScanner(BUILTIN_RULES, { allowedDomains: ['acme-corp.io'] });
    const result = scanner.scan('user@acme-corp.io and token ghp_1234567890abcdefghijklmnopqrstuvwxyz');
    const ids = result.findings.map((f) => f.ruleId);
    expect(ids).not.toContain('email-address');
    expect(result.findings.length).toBeGreaterThan(0);
  });
});

describe('reserved documentation domains (RFC 2606 / RFC 6761)', () => {
  const scanner = new PrivacyScanner(emailRule);

  test.each([
    'john.doe@example.com',
    'a@mail.example.com',
    'ops@example.org',
    'team@example.net',
    'dev@app.test',
    'me@site.example',
    'x@nowhere.invalid',
    'root@box.localhost',
    'User@EXAMPLE.COM',
  ])('are always allowed, with no config: %s', (email: string) => {
    expect(scanner.scan(`contact ${email} for access`).findings).toHaveLength(0);
  });

  test.each([
    'user@examples.com',
    'user@example.co',
    'user@notexample.com',
    'user@example.com.evil.io',
    'user@testing.io',
    'user@contest.io',
  ])('look-alikes are still flagged: %s', (email: string) => {
    expect(scanner.scan(email).findings).toHaveLength(1);
  });
});
