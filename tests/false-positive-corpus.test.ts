import * as path from 'path';
import { describe, expect, test } from '@jest/globals';
import { PrivacyScanner } from '../src/scanner/engine';
import { BUILTIN_RULES, loadExternalRulesFromJson } from '../src/scanner/detectors';
import { DetectionRule } from '../src/types/findings';
import {
  CANARIES,
  CORPUS,
  KNOWN_FALSE_POSITIVES,
} from './fixtures/false-positive-corpus';

// Load the full default rule set exactly as rules.test.ts does: built-in rules
// plus the external coding-only rules from data/regex_list_1.json.
const externalRulesPath = path.resolve(process.cwd(), 'data/regex_list_1.json');
const externalRules = loadExternalRulesFromJson(externalRulesPath, { codingOnly: true });
const allRules: DetectionRule[] = [...BUILTIN_RULES, ...externalRules];
const scanner = new PrivacyScanner(allRules);

const corpusCases = CORPUS.flatMap((group) =>
  group.snippets.map((snippet) => ({ category: group.category, snippet }))
);

describe('false-positive regression corpus', () => {
  test('the full default rule set is loaded', () => {
    // Guard against silently scanning with an empty/partial rule set, which would
    // make every zero-finding assertion below vacuously pass.
    expect(BUILTIN_RULES.length).toBeGreaterThan(0);
    expect(externalRules.length).toBeGreaterThan(0);
    expect(allRules.length).toBeGreaterThan(BUILTIN_RULES.length);
  });

  test('the corpus is non-trivial', () => {
    expect(corpusCases.length).toBeGreaterThanOrEqual(40);
  });

  test.each(corpusCases)(
    'produces zero findings [$category]: $snippet',
    ({ snippet }) => {
      const result = scanner.scan(snippet);
      // On failure, surface which rules fired so a regression is easy to diagnose.
      const fired = result.findings.map((f) => `${f.ruleId}:${JSON.stringify(f.match)}`);
      expect(fired).toEqual([]);
    }
  );
});

describe('true-positive canaries (scanner self-check)', () => {
  test.each(CANARIES)('fires $label', ({ snippet, expectRuleId }) => {
    const result = scanner.scan(snippet);
    const found = result.findings.some((finding) => finding.ruleId === expectRuleId);
    expect(found).toBe(true);
  });
});

describe('documented current-behavior false positives', () => {
  // These are NOT bugs this PR fixes; they pin present-day behaviour so that if a
  // rule is later refined, the change is intentional and visible in this test.
  test.each(KNOWN_FALSE_POSITIVES)(
    'still fires $firesRuleId: $snippet',
    ({ snippet, firesRuleId }) => {
      const result = scanner.scan(snippet);
      const found = result.findings.some((finding) => finding.ruleId === firesRuleId);
      expect(found).toBe(true);
    }
  );
});
