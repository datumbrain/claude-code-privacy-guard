/**
 * Pattern detectors for sensitive data
 */

import { DetectionRule } from '../types/findings.js';
import * as fs from 'fs';
import { createHash } from 'crypto';

interface ExternalRegexEntry {
  name: string;
  description: string;
  regex: string;
  risk: number;
  category: string;
}

interface ExternalRuleOptions {
  codingOnly?: boolean;
}

/**
 * Built-in detection rules
 * Start with high-value patterns that catch the most dangerous leaks
 */
export const BUILTIN_RULES: DetectionRule[] = [
  {
    id: 'email-address',
    title: 'Email Address',
    description: 'Detects email addresses that could be PII',
    severity: 'medium',
    category: 'pii',
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    examples: ['user@example.com', 'john.doe@company.co.uk'],
    redactionStrategy: 'semantic',
    enabled: true,
  },
  {
    id: 'jwt-token',
    title: 'JWT Token',
    description: 'Detects JSON Web Tokens that contain authentication data',
    severity: 'high',
    category: 'auth-token',
    pattern: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
    examples: ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
  {
    id: 'bearer-token',
    title: 'Bearer Token',
    description: 'Detects Bearer authentication tokens',
    severity: 'high',
    category: 'auth-token',
    pattern: /\bBearer\s+[A-Za-z0-9\-._~+/]{20,}=*/gi,
    examples: ['Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
  {
    id: 'aws-api-key',
    title: 'AWS API Key',
    description: 'Detects AWS access key IDs',
    severity: 'critical',
    category: 'secret',
    pattern: /\b(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g,
    examples: ['AKIAIOSFODNN7EXAMPLE'],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
  {
    id: 'openai-api-key',
    title: 'OpenAI API Key',
    description: 'Detects OpenAI API keys',
    severity: 'critical',
    category: 'secret',
    pattern: /\bsk-(?!ant-|or-v1-)(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
    examples: ['sk-proj-1234567890abcdefghij', 'sk-1234567890abcdefghij'],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
  {
    id: 'anthropic-api-key',
    title: 'Anthropic API Key',
    description: 'Detects Anthropic API keys',
    severity: 'critical',
    category: 'secret',
    pattern: /\bsk-ant-[A-Za-z0-9\-_]{20,}\b/g,
    examples: ['sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890'],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
  {
    id: 'openrouter-api-key',
    title: 'OpenRouter API Key',
    description: 'Detects OpenRouter API keys',
    severity: 'critical',
    category: 'secret',
    pattern: /\bsk-or-v1-[A-Za-z0-9]{20,}\b/g,
    examples: ['sk-or-v1-abcdefghijklmnopqrstuvwxyz1234567890'],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
  {
    id: 'google-ai-api-key',
    title: 'Google AI API Key',
    description: 'Detects Google/Gemini style API keys',
    severity: 'critical',
    category: 'secret',
    pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    examples: ['AIzaSyA-ExampleKeyString1234567890ABCDE'],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
  {
    id: 'groq-api-key',
    title: 'Groq API Key',
    description: 'Detects Groq API keys',
    severity: 'critical',
    category: 'secret',
    pattern: /\bgsk_[A-Za-z0-9]{20,}\b/g,
    examples: ['gsk_abcdefghijklmnopqrstuvwxyz1234567890'],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
  {
    id: 'perplexity-api-key',
    title: 'Perplexity API Key',
    description: 'Detects Perplexity API keys',
    severity: 'critical',
    category: 'secret',
    pattern: /\bpplx-[A-Za-z0-9]{20,}\b/g,
    examples: ['pplx-abcdefghijklmnopqrstuvwxyz123456'],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
  {
    id: 'huggingface-api-token',
    title: 'Hugging Face API Token',
    description: 'Detects Hugging Face user access tokens',
    severity: 'high',
    category: 'auth-token',
    pattern: /\bhf_[A-Za-z0-9]{30,}\b/g,
    examples: ['hf_abcdefghijklmnopqrstuvwxyz1234567890'],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
  {
    id: 'stripe-api-key',
    title: 'Stripe API Key',
    description: 'Detects Stripe secret keys',
    severity: 'critical',
    category: 'secret',
    pattern: /\bsk_(live|test)_[0-9a-zA-Z]{24,}\b/g,
    examples: ['sk_live_51AbCdEfGhIjKlMnOpQrStUv'],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
  {
    id: 'github-token',
    title: 'GitHub Token',
    description: 'Detects GitHub personal access and fine-grained tokens',
    severity: 'critical',
    category: 'secret',
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,255}\b|\bgithub_pat_[A-Za-z0-9_]{20,255}\b/g,
    examples: ['ghp_abcdefghijklmnopqrstuvwxyz1234567890'],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
  {
    id: 'slack-token',
    title: 'Slack Token',
    description: 'Detects Slack bot/user/legacy tokens (xoxb/xoxp/xoxa/xoxr) and app-level tokens (xapp)',
    severity: 'high',
    category: 'secret',
    // Bot/user tokens carry 2-3 numeric ID segments then the secret; legacy
    // xoxa/xoxr and app-level xapp use their own shapes. Requiring the ID
    // segments avoids matching placeholders like "xoxb-your-token".
    pattern: /\bxox[bp]-(?:[0-9]{8,}-){2,3}[A-Za-z0-9-]{16,}\b|\bxox[ar]-[0-9]-[0-9a-zA-Z]{18,}\b|\bxapp-[0-9]-[A-Za-z0-9]+-[0-9]+-[A-Za-z0-9]{16,}\b/g,
    // Synthetic (all-zero / EXAMPLE) fixtures assembled at runtime so the full
    // token never appears as one literal in source - keeps upstream secret
    // scanners from false-positiving on these examples.
    examples: [
      ['xoxb', '000000000000', '000000000000', 'EXAMPLExxxxEXAMPLExxxx'].join('-'),
      ['xapp', '1', 'EXAMPLE00000', '000000000000', 'EXAMPLExxxxEXAMPLExxxx'].join('-'),
    ],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
  {
    id: 'gitlab-token',
    title: 'GitLab Token',
    description: 'Detects GitLab personal access, deploy, runner, pipeline trigger, and service account tokens',
    severity: 'critical',
    category: 'secret',
    pattern: /\bgl(?:pat|ptt|dt|rt|soat|ft)-[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]{2,})*\b/g,
    examples: ['glpat-abcdefghij1234567890', 'glpat-EXAMPLEabcd1234567890.01.0example12'],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
  {
    id: 'gitlab-ci-job-token',
    title: 'GitLab CI Job Token',
    description: 'Detects GitLab CI/CD job tokens (glcbt- prefix, GA since GitLab 16.9)',
    severity: 'high',
    category: 'secret',
    pattern: /\bglcbt-[0-9A-Za-z]{1,5}_[A-Za-z0-9_-]{20}\b/g,
    examples: ['glcbt-EXAMP_EXAMPLExxxxEXAMPLExx'],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
  {
    id: 'npm-access-token',
    title: 'npm Access Token',
    description: 'Detects npm access tokens (npm_ prefix, 36-char base62 body)',
    severity: 'high',
    category: 'secret',
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/g,
    examples: ['npm_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEx'],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
  {
    id: 'twilio-api-key-sid',
    title: 'Twilio API Key SID',
    description: 'Detects Twilio API Key SIDs (SK + 32 hex), which pair with an API key secret',
    severity: 'high',
    category: 'secret',
    pattern: /\bSK[0-9a-fA-F]{32}\b/g,
    examples: ['SK00000000000000000000000000000000'],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
  {
    id: 'twilio-account-sid',
    title: 'Twilio Account SID',
    description: 'Detects Twilio Account SIDs (AC + 32 hex) - a public identifier, sensitive when paired with an auth token',
    severity: 'low',
    category: 'internal-data',
    pattern: /\bAC[0-9a-fA-F]{32}\b/g,
    examples: ['AC00000000000000000000000000000000'],
    redactionStrategy: 'partial-mask',
    enabled: true,
  },
  {
    id: 'sendgrid-api-key',
    title: 'SendGrid API Key',
    description: 'Detects SendGrid API keys (SG.<22>.<43> format)',
    severity: 'critical',
    category: 'secret',
    pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
    // Assembled at runtime (see slack-token note) to avoid secret-scanner
    // false positives on this synthetic fixture.
    examples: [['SG', 'EXAMPLExxxxEXAMPLExxxx', 'EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEx'].join('.')],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
  {
    id: 'gcp-service-account-key',
    title: 'GCP Service Account Key JSON',
    description: 'Detects a Google Cloud service-account key JSON envelope (type service_account co-occurring with a private_key field), even when the PEM is elided',
    severity: 'critical',
    category: 'secret',
    // Requires BOTH the exact "type": "service_account" and a "private_key"
    // field within a bounded window (either order) so prose describing service
    // accounts does not match. Bounded lazy span keeps it ReDoS-safe.
    pattern: /"type"\s*:\s*"service_account"[\s\S]{0,2000}?"private_key"\s*:\s*"|"private_key"\s*:\s*"[\s\S]{0,2000}?"type"\s*:\s*"service_account"/g,
    examples: ['{"type": "service_account", "project_id": "demo", "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIB\\n-----END PRIVATE KEY-----\\n", "client_email": "svc@demo.iam.gserviceaccount.com"}'],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
  {
    id: 'azure-client-secret',
    title: 'Azure Client Secret',
    description: 'Detects Microsoft Entra ID (Azure AD) application client secrets',
    severity: 'critical',
    category: 'secret',
    pattern: /(?<![A-Za-z0-9_~.-])[A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.-]{31,34}(?![A-Za-z0-9_~.-])/g,
    examples: ['q_x8Q~AbCdEfGhIjKlMnOpQrStUvWxYz.12345~a'],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
  {
    id: 'database-connection-string-credentials',
    title: 'Database Connection String with Credentials',
    description: 'Detects database URIs with an inline password (scheme://user:password@host) for postgres/mysql/mongodb/redis/amqp',
    severity: 'critical',
    category: 'secret',
    // Requires the ":password@" userinfo so credential-less URIs
    // (scheme://host, scheme://user@host) never match. @ and / are illegal
    // unencoded in RFC 3986 userinfo, so the class boundaries are reliable.
    pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?):\/\/[^\s:/@]+:[^\s/@]+@[^\s/@]+/g,
    examples: ['postgres://user:EXAMPLEpassword@db.example.com:5432/mydb'],
    redactionStrategy: 'partial-mask',
    enabled: true,
  },
  {
    id: 'generic-code-secret-assignment',
    title: 'Generic Code Secret Assignment',
    description: 'Detects likely hardcoded keys/tokens in code assignments',
    severity: 'high',
    category: 'secret',
    pattern: /\b(?:api[_-]?key|secret|token|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['"`][A-Za-z0-9_\-/+=]{16,}['"`]/gi,
    examples: ['api_key = "abc1234567890secretvalue"'],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
  {
    id: 'private-key',
    title: 'Private Key',
    description: 'Detects SSH and PEM private keys',
    severity: 'critical',
    category: 'secret',
    pattern: /-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----[\s\S]*?-----END (RSA |OPENSSH |EC )?PRIVATE KEY-----/g,
    examples: ['-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...\n-----END PRIVATE KEY-----'],
    redactionStrategy: 'token-replace',
    enabled: true,
  },
];

const CODING_SECRET_KEYWORDS = [
  'api key',
  'apikey',
  'access key',
  'token',
  'secret',
  'password',
  'passwd',
  'private key',
  'credential',
  'bearer',
  'jwt',
  'oauth',
  'auth',
  'ssh',
  'pgp',
];

function riskToSeverity(risk: number): DetectionRule['severity'] {
  if (risk >= 8) return 'critical';
  if (risk >= 6) return 'high';
  if (risk >= 3) return 'medium';
  return 'low';
}

function sourceCategoryToRuleCategory(sourceCategory: string): DetectionRule['category'] {
  if (sourceCategory.toLowerCase() === 'pii') {
    return 'pii';
  }

  return 'secret';
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);
}

function isCodingSecretPattern(entry: ExternalRegexEntry): boolean {
  const text = `${entry.name} ${entry.description} ${entry.regex}`.toLowerCase();
  return CODING_SECRET_KEYWORDS.some((keyword) => text.includes(keyword));
}

/**
 * Load rules from external JSON converted from CSV regex lists.
 */
export function loadExternalRulesFromJson(
  jsonPath: string,
  options: ExternalRuleOptions = {}
): DetectionRule[] {
  if (!fs.existsSync(jsonPath)) {
    return [];
  }

  try {
    const raw = fs.readFileSync(jsonPath, 'utf-8');
    const parsed = JSON.parse(raw) as ExternalRegexEntry[];
    const codingOnly = options.codingOnly ?? true;
    const rules: DetectionRule[] = [];
    const usedIds = new Set<string>();

    for (const entry of parsed) {
      if (!entry?.name || !entry?.regex) {
        continue;
      }

      if (codingOnly && !isCodingSecretPattern(entry)) {
        continue;
      }

      try {
        // Ensure regex is compilable before adding, and reject any pattern that
        // can match the empty string: it would spin the scanner's exec loop
        // forever and, via the hook timeout, silently disable the guard.
        if (new RegExp(entry.regex).test('')) {
          continue;
        }
      } catch {
        continue;
      }

      // Suffix with a short hash of the entry's own content (not its position)
      // so IDs stay stable across data-file reordering, even on name collisions.
      const baseId = `external-${slugify(entry.name)}`;
      let id = baseId;
      if (usedIds.has(id)) {
        const contentHash = createHash('sha1').update(`${entry.name}:${entry.regex}`).digest('hex').slice(0, 6);
        id = `${baseId}-${contentHash}`;
      }
      usedIds.add(id);

      rules.push({
        id,
        title: entry.name,
        description: entry.description || `External regex rule: ${entry.name}`,
        severity: riskToSeverity(Number(entry.risk) || 0),
        category: sourceCategoryToRuleCategory(entry.category || ''),
        pattern: entry.regex,
        examples: [entry.name],
        redactionStrategy: 'token-replace',
        enabled: true,
      });
    }

    return rules;
  } catch (error) {
    console.error('Failed to load external regex JSON rules:', error);
    return [];
  }
}
