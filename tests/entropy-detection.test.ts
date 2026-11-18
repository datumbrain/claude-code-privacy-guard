import { describe, expect, test } from '@jest/globals';
import { PrivacyScanner } from '../src/scanner/engine';
import { BUILTIN_RULES } from '../src/scanner/detectors';
import { ENTROPY_CONFIG, ENTROPY_RULE, looksLikeHighEntropySecret, shannonEntropy } from '../src/scanner/entropy';

const scanner = new PrivacyScanner([ENTROPY_RULE]);
const detects = (text: string) =>
  scanner.scan(text).findings.some((f) => f.ruleId === 'high-entropy-secret');

describe('shannonEntropy', () => {
  test('is 0 for empty and single-character strings', () => {
    expect(shannonEntropy('')).toBe(0);
    expect(shannonEntropy('aaaaaaaa')).toBe(0);
  });

  test('is 1 bit for two equally likely characters', () => {
    expect(shannonEntropy('abababab')).toBeCloseTo(1, 5);
  });
});

describe('high-entropy-secret rule', () => {
  test('is registered as a built-in rule', () => {
    expect(BUILTIN_RULES.some((r) => r.id === 'high-entropy-secret')).toBe(true);
  });

  test.each([
    'token: q8Zx3vL0pRt7NwB2kYh9Fd4JsMa6Ue1C',
    'api_key=Zk93LmQ7xT2vB8nR5wYc1HdE4sGf6JaP',
    'secret_key = "Hk3pQ9zX7vLm2WnR8tYb4DfG6sJc1AeU"',
    'my token is 7fA9bC2dE5gH8jK1mN4pQ6sT0vX3yZ',
    'const authToken = "Zk93LmQ7xT2vB8nR5wYc1HdE4sGf6JaP";',
    'password: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b',
    '{"client_secret": "Zk93LmQ7xT2vB8nR5wYc1HdE4sGf6JaP"}',
  ])('detects an unrecognized high-entropy token after a keyword: %s', (text: string) => {
    expect(detects(text)).toBe(true);
  });

  test.each([
    // No keyword context: entropy alone must never flag.
    'commit 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b',
    'sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'request 550e8400-e29b-41d4-a716-446655440000',
    'md5 5d41402abc4b2a76b9719d911017c592',
    // Keyword present, but the value is benign.
    'token: 550e8400-e29b-41d4-a716-446655440000',
    'auth: getAuthenticationTokenFromRequest',
    'password: aaaaaaaaaaaaaaaaaaaa1',
    'secret: YOUR_API_SECRET_VALUE_1',
    'token: /usr/local/lib/python3.9/site-packages',
    'token: abc123',
  ])('does not flag benign text: %s', (text: string) => {
    expect(detects(text)).toBe(false);
  });

  test('flags only the keyword-attached token in a mixed text', () => {
    const text = 'build 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b\napi_key=Zk93LmQ7xT2vB8nR5wYc1HdE4sGf6JaP';
    const findings = scanner.scan(text).findings;
    expect(findings).toHaveLength(1);
    expect(findings[0].match).toBe('api_key=Zk93LmQ7xT2vB8nR5wYc1HdE4sGf6JaP');
  });

  test('thresholds live in ENTROPY_CONFIG and are honored', () => {
    expect(ENTROPY_CONFIG.minLength).toBeGreaterThan(0);
    expect(looksLikeHighEntropySecret('q8Zx3vL0pRt7NwB2kYh9Fd4JsMa6Ue1C')).toBe(true);
    expect(looksLikeHighEntropySecret('q8Zx3vL0pRt7')).toBe(false); // below minLength
  });

  test('scans a maximum-size prompt quickly (performance guard)', () => {
    // 200k chars is the engine's scan cap. Mix keyword-heavy lines and long
    // token-shaped runs so the validator and regex both get exercised.
    const line = 'const apiKeyHandler = token + secret; // see docs for auth Zk93LmQ7xT2vB8nR5wYc1HdE4sGf6JaP\n';
    const text = line.repeat(Math.ceil(200_000 / line.length));
    const start = Date.now();
    scanner.scan(text);
    expect(Date.now() - start).toBeLessThan(2000);
  });
});
