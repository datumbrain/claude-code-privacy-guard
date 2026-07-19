import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { describe, expect, test } from '@jest/globals';
import { PrivacyScanner } from '../src/scanner/engine';
import { BUILTIN_RULES, loadExternalRulesFromJson } from '../src/scanner/detectors';
import { DetectionRule } from '../src/types/findings';

const externalRulesPath = path.resolve(process.cwd(), 'data/regex_list_1.json');
const externalRules = loadExternalRulesFromJson(externalRulesPath, { codingOnly: true });
const allRules: DetectionRule[] = [...BUILTIN_RULES, ...externalRules];

describe('rule coverage', () => {
  test('loads built-in and external coding rules', () => {
    expect(BUILTIN_RULES.length).toBeGreaterThan(0);
    expect(externalRules.length).toBeGreaterThan(0);
    expect(allRules.length).toBeGreaterThan(BUILTIN_RULES.length);
  });

  test.each(allRules)('rule metadata is valid: $id', (rule: DetectionRule) => {
    expect(rule.id).toBeTruthy();
    expect(rule.title).toBeTruthy();
    expect(rule.description).toBeTruthy();
    expect(rule.enabled).toBe(true);
    expect(rule.redactionStrategy).toBeTruthy();
  });

  test.each(allRules)('regex compiles: $id', (rule: DetectionRule) => {
    const compiled = typeof rule.pattern === 'string'
      ? new RegExp(rule.pattern, 'g')
      : new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : `${rule.pattern.flags}g`);

    expect(compiled).toBeInstanceOf(RegExp);
  });

  test.each(allRules)('scanner can execute rule safely: $id', (rule: DetectionRule) => {
    const scanner = new PrivacyScanner([rule]);
    const input = [
      'const apiKey = "test";',
      'Authorization: Bearer abc123',
      '-----BEGIN PRIVATE KEY-----',
      'MIIEvQIBADANBgkqhki...',
      '-----END PRIVATE KEY-----',
    ].join('\n');

    expect(() => scanner.scan(input)).not.toThrow();
  });

  const rulesWithActionableExamples = allRules.filter((rule) => {
    if (!rule.examples || rule.examples.length === 0) return false;
    const firstExample = rule.examples[0];
    if (!firstExample || firstExample.trim().length === 0) return false;
    // External CSV-imported rules currently use title placeholders as examples.
    return firstExample !== rule.title;
  });

  test.each(rulesWithActionableExamples)('example triggers detection: $id', (rule: DetectionRule) => {
    const scanner = new PrivacyScanner([rule]);
    const sample = rule.examples[0];
    const result = scanner.scan(sample);
    const found = result.findings.some((finding) => finding.ruleId === rule.id);
    expect(found).toBe(true);
  });
});

describe('openai-api-key rule', () => {
  const openaiRule = BUILTIN_RULES.find((rule) => rule.id === 'openai-api-key') as DetectionRule;
  const scanner = new PrivacyScanner([openaiRule]);

  test.each([
    'sk-proj-1234567890abcdefghij',
    'sk-1234567890abcdefghij',
    'sk-proj-Ab12_cd34-Ef56Gh78Ij90Kl12Mn34',
  ])('matches realistic key: %s', (key: string) => {
    const result = scanner.scan(`my key is ${key}`);
    expect(result.findings.some((finding) => finding.ruleId === 'openai-api-key')).toBe(true);
  });

  test('does not match ordinary hyphenated words', () => {
    const result = scanner.scan('the task-managers reviewed risk-assessment-review docs at desk-workstations');
    expect(result.findings).toHaveLength(0);
  });

  test('does not match keys owned by other detectors', () => {
    const result = scanner.scan(
      'sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890 sk-or-v1-abcdefghijklmnopqrstuvwxyz1234567890'
    );
    expect(result.findings).toHaveLength(0);
  });
});

describe('bearer-token rule', () => {
  const bearerRule = BUILTIN_RULES.find((rule) => rule.id === 'bearer-token') as DetectionRule;
  const scanner = new PrivacyScanner([bearerRule]);

  test('matches a realistic bearer token', () => {
    const result = scanner.scan('Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
    expect(result.findings.some((finding) => finding.ruleId === 'bearer-token')).toBe(true);
  });

  test('does not match prose asking about how Bearer tokens work', () => {
    const result = scanner.scan('how do Bearer tokens work?');
    expect(result.findings).toHaveLength(0);
  });

  test('does not match short placeholder values after Bearer', () => {
    const result = scanner.scan('Bearer abc123');
    expect(result.findings).toHaveLength(0);
  });
});

describe('overlapping findings (issue #4)', () => {
  const bearerRule = BUILTIN_RULES.find((rule) => rule.id === 'bearer-token') as DetectionRule;
  const jwtRule = BUILTIN_RULES.find((rule) => rule.id === 'jwt-token') as DetectionRule;
  const scanner = new PrivacyScanner([bearerRule, jwtRule]);

  // A real JWT sitting inside a Bearer header matches both rules; the Bearer
  // span wraps the JWT span, so overlap resolution must keep only the Bearer
  // finding and redact the region once.
  const jwt =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
  const input = `header: Bearer ${jwt} end`;

  test('counts one finding, not two', () => {
    const result = scanner.scan(input);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].ruleId).toBe('bearer-token');
  });

  test('redacts the overlapping span exactly once', () => {
    const result = scanner.scan(input);
    expect(result.redactedText).toBe('header: <AUTH_TOKEN> end');
  });
});

describe('empty-match guard (issue #31)', () => {
  const emptyMatchRule: DetectionRule = {
    id: 'empty-matchable',
    title: 'Empty Matchable',
    description: 'A pattern that can match the empty string',
    severity: 'low',
    category: 'pii',
    pattern: 'a*',
    examples: [],
    redactionStrategy: 'full-mask',
    enabled: true,
  };

  test('scan returns promptly with no findings for an empty-matchable rule', () => {
    const scanner = new PrivacyScanner([emptyMatchRule]);
    const start = Date.now();
    const result = scanner.scan('bbb');
    // Would hang without the zero-length guard; assert it finished quickly.
    expect(Date.now() - start).toBeLessThan(1000);
    expect(result.findings).toHaveLength(0);
  });

  test('external rule loading rejects empty-matchable regexes', () => {
    const tmpPath = path.join(os.tmpdir(), `ccpg-empty-match-${Date.now()}.json`);
    fs.writeFileSync(
      tmpPath,
      JSON.stringify([
        { name: 'token empty', description: 'bad', regex: 'a*', risk: 5, category: 'secret' },
        {
          name: 'token valid',
          description: 'good',
          regex: 'AKIA[0-9A-Z]{16}',
          risk: 8,
          category: 'secret',
        },
      ])
    );

    try {
      const rules = loadExternalRulesFromJson(tmpPath, { codingOnly: false });
      expect(rules.map((rule) => rule.pattern)).not.toContain('a*');
      expect(rules.map((rule) => rule.pattern)).toContain('AKIA[0-9A-Z]{16}');
    } finally {
      fs.unlinkSync(tmpPath);
    }
  });
});

describe('email-address rule TLD class (character-class typo fix)', () => {
  const emailRule = BUILTIN_RULES.find((rule) => rule.id === 'email-address') as DetectionRule;
  const scanner = new PrivacyScanner([emailRule]);

  test.each(['user@example.com', 'john.doe@company.co.uk'])(
    'still matches a valid email: %s',
    (email: string) => {
      const result = scanner.scan(`contact ${email} please`);
      expect(result.findings.some((finding) => finding.ruleId === 'email-address')).toBe(true);
    }
  );
});

