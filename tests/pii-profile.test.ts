import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { describe, expect, test } from '@jest/globals';
import { PrivacyScanner } from '../src/scanner/engine';
import { BUILTIN_RULES } from '../src/scanner/detectors';
import { ConfigLoader } from '../src/config/loader';
import { PII_RULES, getPiiRules, isValidPhone, isValidSsn, passesLuhn } from '../src/scanner/pii';

const scan = (ruleKey: keyof typeof PII_RULES, text: string) =>
  new PrivacyScanner([PII_RULES[ruleKey]]).scan(text).findings;

describe('PII detectors are opt-in', () => {
  test('none are part of the built-in rule set', () => {
    for (const rule of Object.values(PII_RULES)) {
      expect(BUILTIN_RULES.some((r) => r.id === rule.id)).toBe(false);
    }
  });

  test('getPiiRules returns nothing for an empty or missing profile', () => {
    expect(getPiiRules(undefined)).toEqual([]);
    expect(getPiiRules({})).toEqual([]);
    expect(getPiiRules({ creditCard: false, ssn: false, phone: false })).toEqual([]);
  });

  test('getPiiRules returns only the enabled detectors', () => {
    expect(getPiiRules({ ssn: true }).map((r) => r.id)).toEqual(['pii-ssn']);
    expect(getPiiRules({ creditCard: true, phone: true }).map((r) => r.id)).toEqual([
      'pii-credit-card',
      'pii-phone',
    ]);
  });

  test('default scanner ignores card, SSN and phone numbers', () => {
    const scanner = new PrivacyScanner(BUILTIN_RULES);
    const result = scanner.scan('card 4111 1111 1111 1111 ssn 123-45-6789 call (415) 555-2671');
    expect(result.findings.filter((f) => f.ruleId.startsWith('pii-'))).toHaveLength(0);
  });
});

describe('piiProfile config', () => {
  function load(content: unknown) {
    const file = path.join(os.tmpdir(), `pg-pii-${Date.now()}-${Math.random()}.json`);
    fs.writeFileSync(file, JSON.stringify(content));
    try {
      return new ConfigLoader(file).getConfig();
    } finally {
      fs.rmSync(file, { force: true });
    }
  }

  test('defaults to everything off', () => {
    expect(new ConfigLoader().getConfig().piiProfile).toEqual({});
    expect(load({ enabled: true }).piiProfile).toEqual({});
  });

  test('honors explicit true flags', () => {
    expect(load({ piiProfile: { creditCard: true, phone: true } }).piiProfile).toEqual({
      creditCard: true,
      phone: true,
    });
  });

  test('treats malformed values as off', () => {
    expect(load({ piiProfile: 'yes' }).piiProfile).toEqual({});
    expect(load({ piiProfile: { ssn: 'true', phone: 1 } }).piiProfile).toEqual({});
  });
});

describe('credit card detection', () => {
  test('passesLuhn', () => {
    expect(passesLuhn('4111111111111111')).toBe(true);
    expect(passesLuhn('4111111111111112')).toBe(false);
  });

  test.each([
    '4111 1111 1111 1111', // Visa
    '4111-1111-1111-1111',
    '4111111111111111',
    '5555555555554444', // Mastercard
    '378282246310005', // Amex
    '3782 822463 10005',
    '6011111111111117', // Discover
  ])('detects a valid card: %s', (card: string) => {
    expect(scan('creditCard', `pay with ${card} please`)).toHaveLength(1);
  });

  test.each([
    '4111 1111 1111 1112', // fails Luhn
    '1234567890123456', // no issuer prefix
    '1700000000000000', // timestamp-shaped
    '4111 1111-1111 1111', // mixed separators
    '41111111111111111111', // 20 digits
    '4111 1111 1111', // too short
    'ORD-4111111111111111', // part of an identifier
  ])('does not flag near-miss: %s', (text: string) => {
    expect(scan('creditCard', text)).toHaveLength(0);
  });
});

describe('SSN detection', () => {
  test('detects a valid dashed SSN', () => {
    expect(scan('ssn', 'my ssn is 123-45-6789.')).toHaveLength(1);
  });

  test.each([
    ['000-12-3456', 'area 000'],
    ['666-12-3456', 'area 666'],
    ['900-12-3456', 'area 9xx'],
    ['999-12-3456', 'area 9xx'],
    ['123-00-6789', 'group 00'],
    ['123-45-0000', 'serial 0000'],
  ])('rejects invalid SSN %s (%s)', (ssn: string) => {
    expect(isValidSsn(ssn)).toBe(false);
    expect(scan('ssn', ssn)).toHaveLength(0);
  });

  test.each(['123456789', '123-456-7890', 'id 1123-45-6789', '123-45-67890'])(
    'does not flag non-SSN shape: %s',
    (text: string) => {
      expect(scan('ssn', text)).toHaveLength(0);
    }
  );
});

describe('phone detection', () => {
  test.each([
    '(415) 555-2671',
    '415-555-2671',
    '415.555.2671',
    '+1 415 555 2671',
    '1-415-555-2671',
    '+14155552671',
    '+44 20 7946 0958',
    '+49 30 901820',
  ])('detects a phone number: %s', (phone: string) => {
    expect(scan('phone', `call me on ${phone} tomorrow`)).toHaveLength(1);
  });

  test.each([
    '4155552671', // bare 10 digits (order id shape)
    'ORD-415-555-2671',
    '192.168.100.1234',
    '123-456-7890', // area code starts with 1
    '911-555-2671', // N11 area code
    '415-155-2671', // exchange starts with 1
    '(555) 555-0123', // fictional 555-01xx block
    '555-0150',
    'version 1.2.3.4567',
    '+1234',
    'id 20240101123456',
  ])('does not flag phone-shaped non-phone: %s', (text: string) => {
    expect(scan('phone', text)).toHaveLength(0);
  });

  test('isValidPhone applies NANP rules to +1 numbers', () => {
    expect(isValidPhone('+1 415 555 2671')).toBe(true);
    expect(isValidPhone('+1 055 555 2671')).toBe(false);
  });
});
