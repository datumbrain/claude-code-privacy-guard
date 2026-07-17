/**
 * Pattern detectors for sensitive data
 */
import * as fs from 'fs';
/**
 * Built-in detection rules
 * Start with high-value patterns that catch the most dangerous leaks
 */
export const BUILTIN_RULES = [
    {
        id: 'email-address',
        title: 'Email Address',
        description: 'Detects email addresses that could be PII',
        severity: 'medium',
        category: 'pii',
        pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
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
        pattern: /\bBearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
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
        id: 'generic-code-secret-assignment',
        title: 'Generic Code Secret Assignment',
        description: 'Detects likely hardcoded keys/tokens in code assignments',
        severity: 'high',
        category: 'secret',
        pattern: /\b(?:api[_-]?key|secret|token|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['"`][A-Za-z0-9_\-\/+=]{16,}['"`]/gi,
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
function riskToSeverity(risk) {
    if (risk >= 8)
        return 'critical';
    if (risk >= 6)
        return 'high';
    if (risk >= 3)
        return 'medium';
    return 'low';
}
function sourceCategoryToRuleCategory(sourceCategory) {
    if (sourceCategory.toLowerCase() === 'pii') {
        return 'pii';
    }
    return 'secret';
}
function slugify(value) {
    return value
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 80);
}
function isCodingSecretPattern(entry) {
    const text = `${entry.name} ${entry.description} ${entry.regex}`.toLowerCase();
    return CODING_SECRET_KEYWORDS.some((keyword) => text.includes(keyword));
}
/**
 * Load rules from external JSON converted from CSV regex lists.
 */
export function loadExternalRulesFromJson(jsonPath, options = {}) {
    if (!fs.existsSync(jsonPath)) {
        return [];
    }
    try {
        const raw = fs.readFileSync(jsonPath, 'utf-8');
        const parsed = JSON.parse(raw);
        const codingOnly = options.codingOnly ?? true;
        const rules = [];
        const usedIds = new Set();
        for (const entry of parsed) {
            if (!entry?.name || !entry?.regex) {
                continue;
            }
            if (codingOnly && !isCodingSecretPattern(entry)) {
                continue;
            }
            try {
                // Ensure regex is compilable before adding.
                void new RegExp(entry.regex, 'g');
            }
            catch {
                continue;
            }
            let id = `external-${slugify(entry.name)}`;
            let suffix = 2;
            while (usedIds.has(id)) {
                id = `external-${slugify(entry.name)}-${suffix}`;
                suffix += 1;
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
    }
    catch (error) {
        console.error('Failed to load external regex JSON rules:', error);
        return [];
    }
}
//# sourceMappingURL=detectors.js.map