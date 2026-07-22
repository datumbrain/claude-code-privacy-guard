import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { describe, expect, jest, test } from '@jest/globals';
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

describe('github-token rule', () => {
  const githubRule = BUILTIN_RULES.find((rule) => rule.id === 'github-token') as DetectionRule;
  const scanner = new PrivacyScanner([githubRule]);

  test.each([
    'ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789',
    'github_pat_11ABCDEFG0abcdefghijklm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefghijklmnopqrstuvw',
  ])('matches realistic token: %s', (token: string) => {
    const result = scanner.scan(`my token is ${token}`);
    expect(result.findings.some((finding) => finding.ruleId === 'github-token')).toBe(true);
  });

  test('does not match prose mentioning github_pat or short placeholders', () => {
    const result = scanner.scan('set github_pat_here and ghp_abc123 in your env');
    expect(result.findings).toHaveLength(0);
  });
});

describe('gitlab-token rule', () => {
  const gitlabRule = BUILTIN_RULES.find((rule) => rule.id === 'gitlab-token') as DetectionRule;
  const scanner = new PrivacyScanner([gitlabRule]);

  test.each([
    'glpat-abcdefghij1234567890',
    'glpat-EXAMPLEabcd1234567890.01.0example12',
    'gldt-AbCdEfGhIjKlMnOpQrSt',
    'glrt-t1_AbCdEfGhIjKlMnOpQr',
  ])('matches realistic token: %s', (token: string) => {
    const result = scanner.scan(`CI_JOB_TOKEN=${token}`);
    expect(result.findings.some((finding) => finding.ruleId === 'gitlab-token')).toBe(true);
  });

  test('does not match prose or short placeholder values', () => {
    const result = scanner.scan('create a glpat-style token; glpat-abc123 is a placeholder');
    expect(result.findings).toHaveLength(0);
  });
});

describe('azure-client-secret rule', () => {
  const azureRule = BUILTIN_RULES.find((rule) => rule.id === 'azure-client-secret') as DetectionRule;
  const scanner = new PrivacyScanner([azureRule]);

  test.each([
    'q_x8Q~AbCdEfGhIjKlMnOpQrStUvWxYz.12345~a',
    'Iq18Q~yfZ2K7Vt.wNxE4pDb-Mh9cRj3sGl6uT',
  ])('matches realistic secret: %s', (secret: string) => {
    const result = scanner.scan(`AZURE_CLIENT_SECRET=${secret}`);
    expect(result.findings.some((finding) => finding.ruleId === 'azure-client-secret')).toBe(true);
  });

  test('does not match GUIDs or generic base64-like strings', () => {
    const result = scanner.scan(
      'client_id 4f9d2b1a-7c3e-4a5b-9d8f-1e2a3b4c5d6e value dGhpc2lzYWxvbmdiYXNlNjRzdHJpbmc0MGNoYXJz'
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

describe('ReDoS guard (issue #21)', () => {
  test('external rule loading rejects a catastrophic-backtracking regex', () => {
    const tmpPath = path.join(os.tmpdir(), `ccpg-redos-${Date.now()}.json`);
    fs.writeFileSync(
      tmpPath,
      JSON.stringify([
        {
          name: 'pathological token',
          description: 'nested quantifiers, classic catastrophic backtracking shape',
          regex: '(x+x+)+y',
          risk: 5,
          category: 'secret',
        },
        {
          name: 'token valid',
          description: 'good',
          regex: 'AKIA[0-9A-Z]{16}',
          risk: 8,
          category: 'secret',
        },
      ])
    );

    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const rules = loadExternalRulesFromJson(tmpPath, { codingOnly: false });
      expect(rules.map((rule) => rule.pattern)).not.toContain('(x+x+)+y');
      expect(rules.map((rule) => rule.pattern)).toContain('AKIA[0-9A-Z]{16}');
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('pathological token'));
    } finally {
      warnSpy.mockRestore();
      fs.unlinkSync(tmpPath);
    }
  });
});

describe('scanned input length cap (issue #21)', () => {
  test('scan caps the portion of text run through the rule engine', () => {
    const awsKeyRule = BUILTIN_RULES.find((rule) => rule.id === 'aws-api-key') as DetectionRule;
    const scanner = new PrivacyScanner([awsKeyRule], { maxScanLength: 20 });

    // The key sits well past the 20-char scan window, so it must pass through
    // untouched in the output rather than being detected or dropped.
    const padding = 'x'.repeat(30);
    const text = `${padding}AKIAIOSFODNN7EXAMPLE`;
    const result = scanner.scan(text);

    expect(result.findings).toHaveLength(0);
    expect(result.redactedText).toBe(text);
  });

  test('scan still detects matches within the maxScanLength window', () => {
    const awsKeyRule = BUILTIN_RULES.find((rule) => rule.id === 'aws-api-key') as DetectionRule;
    const scanner = new PrivacyScanner([awsKeyRule], { maxScanLength: 50 });

    const result = scanner.scan('key: AKIAIOSFODNN7EXAMPLE');

    expect(result.findings).toHaveLength(1);
    expect(result.redactedText).toBe('key: <SECRET>');
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


function ruleScanner(id: string): PrivacyScanner {
  const rule = BUILTIN_RULES.find((r) => r.id === id) as DetectionRule;
  expect(rule).toBeDefined();
  return new PrivacyScanner([rule]);
}

describe('slack-token rule', () => {
  const scanner = ruleScanner('slack-token');

  // Synthetic fixtures assembled at runtime (see detectors.ts note) so the full
  // token never appears as one literal in source.
  test.each([
    ['xoxb', '000000000000', '000000000000', 'EXAMPLExxxxEXAMPLExxxx'].join('-'),
    ['xoxp', '000000000000', '000000000000', '000000000000', 'EXAMPLExxxxEXAMPLExxxx'].join('-'),
    ['xapp', '1', 'EXAMPLE00000', '000000000000', 'EXAMPLExxxxEXAMPLExxxx'].join('-'),
  ])('matches a realistic Slack token: %s', (token: string) => {
    const result = scanner.scan(`token=${token}`);
    expect(result.findings.some((f) => f.ruleId === 'slack-token')).toBe(true);
  });

  test.each([
    'how do slack tokens work?',
    'reset your xoxb- token',
    'xoxb-xxxx',
    'xoxb-your-slack-token-here',
  ])('does not match placeholders or prose: %s', (text: string) => {
    const result = scanner.scan(text);
    expect(result.findings).toHaveLength(0);
  });
});

describe('gitlab-ci-job-token rule', () => {
  const scanner = ruleScanner('gitlab-ci-job-token');

  test('matches a realistic glcbt- token', () => {
    const result = scanner.scan('CI_JOB_TOKEN=glcbt-EXAMP_EXAMPLExxxxEXAMPLExx');
    expect(result.findings.some((f) => f.ruleId === 'gitlab-ci-job-token')).toBe(true);
  });

  test.each(['glcbt-xxxx', 'the CI_JOB_TOKEN variable name'])(
    'does not match placeholders or prose: %s',
    (text: string) => {
      const result = scanner.scan(text);
      expect(result.findings).toHaveLength(0);
    }
  );
});

describe('npm-access-token rule', () => {
  const scanner = ruleScanner('npm-access-token');

  test('matches a realistic npm_ token', () => {
    const result = scanner.scan('//registry.npmjs.org/:_authToken=npm_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEx');
    expect(result.findings.some((f) => f.ruleId === 'npm-access-token')).toBe(true);
  });

  test.each(['npm_token', 'NPM_TOKEN=changeme', 'run npm install'])(
    'does not match placeholders or prose: %s',
    (text: string) => {
      const result = scanner.scan(text);
      expect(result.findings).toHaveLength(0);
    }
  );
});

describe('twilio-api-key-sid rule', () => {
  const scanner = ruleScanner('twilio-api-key-sid');

  test('matches a realistic Twilio API Key SID', () => {
    const result = scanner.scan('TWILIO_API_KEY_SID=SK00000000000000000000000000000000');
    expect(result.findings.some((f) => f.ruleId === 'twilio-api-key-sid')).toBe(true);
  });

  test.each(['SKxxxx', 'your Twilio SK... API key'])(
    'does not match placeholders or prose: %s',
    (text: string) => {
      const result = scanner.scan(text);
      expect(result.findings).toHaveLength(0);
    }
  );
});

describe('twilio-account-sid rule', () => {
  const scanner = ruleScanner('twilio-account-sid');

  test('matches a realistic Twilio Account SID', () => {
    const result = scanner.scan('account_sid = AC00000000000000000000000000000000');
    expect(result.findings.some((f) => f.ruleId === 'twilio-account-sid')).toBe(true);
  });

  test('redacts as a low-severity identifier with partial-mask', () => {
    const result = scanner.scan('AC00000000000000000000000000000000');
    const finding = result.findings.find((f) => f.ruleId === 'twilio-account-sid') as NonNullable<
      ReturnType<typeof result.findings.find>
    >;
    expect(finding.severity).toBe('low');
    expect(finding.redactedValue).toContain('***');
  });

  test.each(['ACxxxx', 'the account SID starts with AC'])(
    'does not match placeholders or prose: %s',
    (text: string) => {
      const result = scanner.scan(text);
      expect(result.findings).toHaveLength(0);
    }
  );
});

describe('sendgrid-api-key rule', () => {
  const scanner = ruleScanner('sendgrid-api-key');

  test('matches a realistic SendGrid API key', () => {
    const key = ['SG', 'EXAMPLExxxxEXAMPLExxxx', 'EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEx'].join('.');
    const result = scanner.scan(`SENDGRID_API_KEY=${key}`);
    expect(result.findings.some((f) => f.ruleId === 'sendgrid-api-key')).toBe(true);
  });

  test.each(['SG.xxx.yyy', 'your SendGrid key looks like SG.<id>.<secret>'])(
    'does not match placeholders or prose: %s',
    (text: string) => {
      const result = scanner.scan(text);
      expect(result.findings).toHaveLength(0);
    }
  );
});

describe('gcp-service-account-key rule', () => {
  const scanner = ruleScanner('gcp-service-account-key');

  test('matches a service-account JSON envelope', () => {
    const json =
      '{"type": "service_account", "project_id": "demo", "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIB\\n-----END PRIVATE KEY-----\\n"}';
    const result = scanner.scan(json);
    expect(result.findings.some((f) => f.ruleId === 'gcp-service-account-key')).toBe(true);
  });

  test('matches even when the private key value is elided and fields are reordered', () => {
    const json = '{ "private_key": "REDACTED", "client_email": "x@y", "type":"service_account" }';
    const result = scanner.scan(json);
    expect(result.findings.some((f) => f.ruleId === 'gcp-service-account-key')).toBe(true);
  });

  test.each([
    'A service_account has a private_key field in its JSON.',
    'Set the type to service account and store the key securely.',
    '{"type": "user_account", "name": "demo"}',
  ])('does not match prose about service accounts: %s', (text: string) => {
    const result = scanner.scan(text);
    expect(result.findings).toHaveLength(0);
  });
});

describe('database-connection-string-credentials rule', () => {
  const scanner = ruleScanner('database-connection-string-credentials');

  test.each([
    'postgres://user:EXAMPLEpassword@db.example.com:5432/mydb',
    'postgresql://user:EXAMPLEpassword@db.example.com:5432/mydb',
    'mysql://user:EXAMPLEpassword@10.0.0.5:3306/appdb',
    'mongodb://user:EXAMPLEpassword@mongo1.example.com:27017/records',
    'mongodb+srv://user:EXAMPLEpassword@cluster0.abcd.mongodb.net/records',
    'redis://default:EXAMPLEpassword@redis.internal:6379/0',
    'rediss://default:EXAMPLEpassword@redis.internal:6380/0',
    'amqp://guest:EXAMPLEpassword@rabbit.example.com:5672/vhost',
    'amqps://guest:EXAMPLEpassword@rabbit.example.com:5671/vhost',
  ])('matches a URI with inline credentials: %s', (uri: string) => {
    const result = scanner.scan(`DATABASE_URL=${uri}`);
    expect(result.findings.some((f) => f.ruleId === 'database-connection-string-credentials')).toBe(true);
  });

  test('redacts with partial info preserved (partial-mask)', () => {
    const result = scanner.scan('postgres://user:EXAMPLEpassword@db.example.com:5432/mydb');
    const finding = result.findings.find(
      (f) => f.ruleId === 'database-connection-string-credentials'
    ) as NonNullable<ReturnType<typeof result.findings.find>>;
    expect(finding.redactedValue).toContain('***');
    expect(finding.redactedValue).not.toContain('EXAMPLEpassword');
  });

  test.each([
    'postgres://localhost:5432/mydb',
    'postgres://user@host',
    'redis://localhost:6379/0',
    'amqp://rabbit.example.com/vhost',
    'mongodb://mongo1:27017/db',
    'See https://www.postgresql.org/docs/current/libpq-connect.html',
  ])('does not match credential-less URIs or docs URLs: %s', (text: string) => {
    const result = scanner.scan(text);
    expect(result.findings).toHaveLength(0);
  });
});

