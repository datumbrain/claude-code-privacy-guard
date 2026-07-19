/**
 * False-positive regression corpus (see issue #20).
 *
 * Every string in CORPUS is a realistic, benign snippet that MUST produce zero
 * findings when scanned with the full default rule set (built-in rules plus the
 * external coding-only rules from data/regex_list_1.json). The corpus pins the
 * *current* good behaviour of the scanner: a rule change that starts flagging any
 * of these snippets is a regression and should fail CI.
 *
 * Every snippet here was verified empirically against the compiled scanner before
 * being added - only strings that genuinely score zero findings today are included.
 * Near-misses that DO fire under the current rules are documented in
 * KNOWN_FALSE_POSITIVES below and deliberately kept OUT of the corpus, rather than
 * changing any rule. This is a test-only pin, not a rule fix.
 */

export interface CorpusGroup {
  category: string;
  snippets: string[];
}

export const CORPUS: CorpusGroup[] = [
  {
    category: 'prose mentioning secret terms (CLI / docs)',
    snippets: [
      'To authenticate, pass your API key in the request header.',
      'Run the CLI and provide a token when prompted for access.',
      'docs: how to rotate an API key and revoke a token safely',
      'See the authentication docs for how Bearer tokens and JWTs work.',
      'Stripe keys start with sk_live_ or sk_test_ prefixes.',
      'the value looks like ghp_ but is just a prefix mention',
    ],
  },
  {
    category: 'environment-variable references (no literal secret)',
    snippets: [
      'api_key = os.environ["API_KEY"]',
      'const apiKey = process.env.API_KEY;',
      'apiKey: process.env.API_KEY',
      'password = getpass.getpass("Enter your password: ")',
      'the config uses ${API_KEY} interpolation at runtime',
      'env: GITHUB_TOKEN is read by the action',
      'steps: uses actions/checkout@v4 with token: ${{ secrets.GITHUB_TOKEN }}',
      'heroku_api_key should be set in the dashboard',
      'facebook_app_secret is configured per environment',
    ],
  },
  {
    category: 'placeholder / example values',
    snippets: [
      'api_key = "YOUR_KEY"',
      'api_key = "<your-api-key>"',
      'token: "changeme"',
      'secret: null',
      'Authorization: Bearer <token>',
      'Authorization: Bearer YOUR_TOKEN_HERE',
      'set the key to sk-xxx or sk-... in your config',
    ],
  },
  {
    category: 'JWT-lookalikes (not three dot-separated eyJ segments)',
    snippets: [
      'the JWT starts with eyJ but this string eyJhbGci is not a full token',
      'header.payload.signature is the JWT structure',
      'eyJhbGciOiJIUzI1NiJ9 is only the header segment, not a full JWT',
      'a.b.c is not a jwt; eyJ.eyJ needs a third segment',
    ],
  },
  {
    category: 'hashes, UUIDs, git SHAs, and lockfile blobs',
    snippets: [
      'The commit 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b was reverted.',
      'id: 550e8400-e29b-41d4-a716-446655440000',
      '"integrity": "sha512-abc123DEF456ghi789JKLmno0PQRstu+vwx/yz=="',
      'the docker image sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      'commit c8f1e18b78e34a1f9d0c2e5a6b7c8d9e0f1a2b3c',
      'trace_id=00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
      'resolved "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"',
      'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ is a base64 fragment in a code comment',
      'data = base64.b64decode("SGVsbG8gV29ybGQgdGhpcyBpcyBhIHRlc3Q=")',
      'const uuid = crypto.randomUUID();',
      // A bcrypt hash is not an API-key-shaped secret and is not matched today.
      "const hash = '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy';",
    ],
  },
  {
    category: 'CLI / infra commands and secret-manager references (no actual secret)',
    snippets: [
      'kubectl get pods -n production -o wide',
      'gcloud auth login --brief',
      'kubectl create secret generic db --from-literal=password=REDACTED --dry-run=client',
      'gcloud secrets versions access latest --secret=db-password',
      'reference the secret at projects/my-project/secrets/db-password/versions/latest',
      'resource "google_secret_manager_secret" "db" { secret_id = "db-password" }',
      '- old_secret = get("projects/p/secrets/s/versions/1")\n+ new_secret = get("projects/p/secrets/s/versions/2")',
      'cat /etc/passwd | grep root',
      'export AWS_PROFILE=default && aws s3 ls',
      'npm install left-pad@1.3.0 --save-exact',
      'git log --oneline -n 20 shows recent commits',
    ],
  },
  {
    category: 'markdown docs about authentication',
    snippets: [
      '# Authentication\n\nProvide an API key via the `Authorization` header as a Bearer token.',
    ],
  },
];

/**
 * KNOWN_FALSE_POSITIVES - realistic benign strings that the CURRENT rules DO flag.
 *
 * These are deliberately excluded from CORPUS so it stays green. They document
 * present-day behaviour discovered while building the corpus; each is a candidate
 * for a future rule refinement, but this PR only pins behaviour and does not touch
 * any rule. If a rule is later tightened, move the corresponding entry into CORPUS.
 */
export const KNOWN_FALSE_POSITIVES: { snippet: string; firesRuleId: string; note: string }[] = [
  {
    snippet: 'AKIAIOSFODNN7EXAMPLE',
    firesRuleId: 'aws-api-key',
    note: "Amazon's own documented example access key ID; the aws-api-key AKIA... shape matches it.",
  },
  {
    snippet: 'api_key = "YOUR_API_KEY_HERE"',
    firesRuleId: 'generic-code-secret-assignment',
    note: 'The 17-char placeholder is >=16 word chars in quotes after api_key=, so the generic assignment rule fires. "YOUR_KEY" (used in the corpus) is short enough to stay clean.',
  },
  {
    snippet: 'OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxx',
    firesRuleId: 'openai-api-key',
    note: 'sk- followed by 20+ chars matches even when the chars are placeholder x\'s. Shorter "sk-xxx" prose stays clean.',
  },
  {
    snippet: 'the field secret_access_key holds your AWS secret',
    firesRuleId: 'external-aws-credentials-context',
    note: 'external-aws-credentials-context is a bare keyword alternation (access_key_id|secret_access_key|...), so the term alone fires with no value present.',
  },
  {
    snippet: 'POST https://login.microsoftonline.com/common/oauth2/v2.0/token',
    firesRuleId: 'external-microsoft-office-365-oauth-context',
    note: 'The rule matches the public OAuth endpoint URL itself, which appears in ordinary documentation.',
  },
  {
    snippet: 'root:x:0:0:root:/root:/bin/bash',
    firesRuleId: 'external-password-etc-passwd',
    note: 'A standard /etc/passwd line (no password hash - the x is a shadow reference) is matched by the passwd-file rule.',
  },
  {
    snippet: 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDexample user@host',
    firesRuleId: 'external-ssh-rsa-public',
    note: 'A PUBLIC ssh-rsa key line is matched; public keys are not secret but the rule flags the format.',
  },
];

/**
 * True-positive canaries - one real-shaped secret per built-in category family.
 * These MUST fire, so the corpus test file can self-check that the full rule set
 * was actually loaded (a corpus of zero-finding strings would also pass against a
 * broken/empty scanner). Each entry names the built-in rule expected to match.
 */
export const CANARIES: { label: string; snippet: string; expectRuleId: string }[] = [
  {
    label: 'email address (pii)',
    snippet: 'contact user@example.com for access',
    expectRuleId: 'email-address',
  },
  {
    label: 'JWT (auth-token)',
    snippet:
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
    expectRuleId: 'jwt-token',
  },
  {
    label: 'Bearer token (auth-token)',
    snippet: 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdefghij',
    expectRuleId: 'bearer-token',
  },
  {
    label: 'AWS access key ID (secret)',
    snippet: 'AKIAIOSFODNN7EXAMPLE',
    expectRuleId: 'aws-api-key',
  },
  {
    label: 'OpenAI API key (secret)',
    snippet: 'sk-proj-1234567890abcdefghij',
    expectRuleId: 'openai-api-key',
  },
  {
    label: 'GitHub token (secret)',
    snippet: 'ghp_abcdefghijklmnopqrstuvwxyz1234567890',
    expectRuleId: 'github-token',
  },
  {
    label: 'hardcoded secret assignment (secret)',
    snippet: 'api_key = "abc1234567890secretvalue"',
    expectRuleId: 'generic-code-secret-assignment',
  },
  {
    label: 'PEM private key (secret)',
    snippet: '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...\n-----END PRIVATE KEY-----',
    expectRuleId: 'private-key',
  },
];
