import { describe, expect, test } from '@jest/globals';
import { buildHookResponse } from '../src/hook/response';
import { PrivacyScanner } from '../src/scanner/engine';
import { BUILTIN_RULES } from '../src/scanner/detectors';

const emailRule = BUILTIN_RULES.filter((r) => r.id === 'email-address');

function scanWithFinding() {
  const scanner = new PrivacyScanner(emailRule);
  return scanner.scan('reach me at john@example.com please');
}

function scanClean() {
  const scanner = new PrivacyScanner(emailRule);
  return scanner.scan('nothing sensitive here');
}

describe('buildHookResponse', () => {
  test('returns null when there are no findings, regardless of mode', () => {
    const clean = scanClean();
    expect(buildHookResponse(clean, 'block')).toBeNull();
    expect(buildHookResponse(clean, 'redact')).toBeNull();
    expect(buildHookResponse(clean, 'warn')).toBeNull();
  });

  test('block mode returns a block decision with a masked value and no full match leaked', () => {
    const result = scanWithFinding();
    const response = buildHookResponse(result, 'block');
    expect(response?.decision).toBe('block');
    expect(response?.reason).toContain('Privacy Guard blocked this prompt');
    expect(response?.reason).not.toContain('john@example.com');
    expect(response?.systemMessage).toBeUndefined();
  });

  test('redact mode still blocks (hook API cannot rewrite the prompt) but includes the cleaned text', () => {
    const result = scanWithFinding();
    const response = buildHookResponse(result, 'redact');
    expect(response?.decision).toBe('block');
    expect(response?.reason).toContain(result.redactedText);
    expect(response?.reason).not.toContain('john@example.com');
  });

  test('warn mode allows the prompt through (no decision) and surfaces a systemMessage', () => {
    const result = scanWithFinding();
    const response = buildHookResponse(result, 'warn');
    expect(response?.decision).toBeUndefined();
    expect(response?.systemMessage).toContain('warn mode - prompt allowed through');
    expect(response?.systemMessage).not.toContain('john@example.com');
  });
});
