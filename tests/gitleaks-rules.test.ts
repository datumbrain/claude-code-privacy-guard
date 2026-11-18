import * as fs from 'fs';
import * as path from 'path';
import { describe, expect, jest, test } from '@jest/globals';
import { PrivacyScanner, compileRulePattern } from '../src/scanner/engine';
import { BUILTIN_RULES, loadExternalRulesFromJson } from '../src/scanner/detectors';
import { PII_RULES } from '../src/scanner/pii';
import { probeRegex } from '../src/scanner/regex-audit';
import { DetectionRule } from '../src/types/findings';

const dataPath = path.resolve(process.cwd(), 'data/gitleaks-rules.json');
const rawEntries = JSON.parse(fs.readFileSync(dataPath, 'utf-8')) as { name: string }[];
const gitleaksRules = loadExternalRulesFromJson(dataPath, { codingOnly: true });

describe('bundled gitleaks ruleset', () => {
  test('ships with attribution and license', () => {
    const license = fs.readFileSync(path.resolve(process.cwd(), 'data/gitleaks-LICENSE'), 'utf-8');
    expect(license).toMatch(/MIT License/);
  });

  test('every entry loads with zero rejections, in coding-only mode too', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    const all = loadExternalRulesFromJson(dataPath, { codingOnly: false });
    const coding = loadExternalRulesFromJson(dataPath, { codingOnly: true });
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
    expect(all).toHaveLength(rawEntries.length);
    expect(coding).toHaveLength(rawEntries.length);
    expect(rawEntries.length).toBeGreaterThan(150);
  });

  test('keeps the stable external-<slug> id scheme', () => {
    for (const rule of gitleaksRules) expect(rule.id).toMatch(/^external-[a-z0-9-]+$/);
    expect(gitleaksRules.some((r) => r.id === 'external-stripe-access-token')).toBe(true);
  });

  test('carries keywords, entropy and flags through the loader', () => {
    const sourcegraph = gitleaksRules.find((r) => r.id === 'external-sourcegraph-access-token') as DetectionRule;
    expect(sourcegraph.keywords).toEqual(expect.arrayContaining(['sgp_', 'sourcegraph']));
    expect(sourcegraph.minEntropy).toBe(3);
    expect(sourcegraph.flags).toBe('i');
  });

  const scanner = new PrivacyScanner(gitleaksRules);
  const ruleIds = (text: string) => scanner.scan(text).findings.map((f) => f.ruleId);

  // Fixtures are assembled at runtime so the literal token shapes never sit in
  // the source, where GitHub push protection rejects them. They are fake.
  const j = (...parts: string[]) => parts.join('');
  test.each([
    ['external-stripe-access-token', j('STRIPE=sk', '_live_', '4eC39HqLyjWDarjtT1zdp7dc ')],
    ['external-slack-bot-token', j('xox', 'b-1234567890123-1234567890123-', 'AbCdEfGhIjKlMnOpQrStUvWx')],
    ['external-shopify-access-token', j('shp', 'at_', 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6')],
    ['external-digitalocean-pat', j('dop', '_v1_', '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b9f86d081884c7d659a2feaa0 ')],
    ['external-linear-api-key', j('lin', '_api_', 'q8Zx3vL0pRt7NwB2kYh9Fd4JsMa6Ue1Cq8Zx3vL0')],
  ])('detects %s', (id: string, text: string) => {
    expect(ruleIds(text)).toContain(id);
  });

  test('keyword prefilter: a bare 40-hex SHA is not a Sourcegraph token', () => {
    expect(ruleIds('commit 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b')).not.toContain('external-sourcegraph-access-token');
  });

  test('keyword prefilter: the same value next to its keyword is flagged', () => {
    expect(ruleIds('sourcegraph token 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b')).toContain(
      'external-sourcegraph-access-token'
    );
  });

  test('entropy gate drops low-entropy placeholders', () => {
    expect(ruleIds(j('shp', 'at_', '0'.repeat(32)))).not.toContain('external-shopify-access-token');
  });
});

describe('catastrophic-backtracking audit of every shipped rule', () => {
  // Built-ins, the bundled gitleaks set and the opt-in PII rules. A linear
  // regex takes a few ms on 20k chars; a quadratic one takes hundreds.
  const shipped: DetectionRule[] = [...BUILTIN_RULES, ...gitleaksRules, ...Object.values(PII_RULES)];

  test.each(shipped.map((rule) => [rule.id, rule] as const))('%s stays linear', (_id, rule) => {
    const { worstMs, shape } = probeRegex(compileRulePattern(rule), 20_000);
    if (worstMs >= 100) throw new Error(`${rule.id} took ${worstMs.toFixed(0)} ms on ${JSON.stringify(shape)}`);
  });

  test('email-address no longer goes quadratic on long dash/dot runs', () => {
    const email = BUILTIN_RULES.find((r) => r.id === 'email-address') as DetectionRule;
    const s = new PrivacyScanner([email], { maxScanLength: 1_000_000 });
    for (const text of ['1-'.repeat(100_000), '123-45-'.repeat(30_000), 'a.'.repeat(100_000)]) {
      const start = Date.now();
      s.scan(text);
      expect(Date.now() - start).toBeLessThan(1000);
    }
    expect(s.scan('mail john.doe+tag@mail.example.co.uk now').findings[0].match).toBe('john.doe+tag@mail.example.co.uk');
  });
});
