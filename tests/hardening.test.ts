/**
 * Regression tests for bugs found in a hardening pass over the existing
 * behavior (no new features). Each block names the bug it pins down. Secrets
 * are assembled at runtime so no full fake credential sits in the source.
 */

import { afterEach, beforeEach, describe, expect, test } from '@jest/globals';
import { execFileSync } from 'child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'fs';
import * as os from 'os';
import * as path from 'path';
import { PrivacyScanner } from '../src/scanner/engine';
import { BUILTIN_RULES, isNonPersonalAddress, loadExternalRulesFromJson } from '../src/scanner/detectors';
import { ConfigLoader } from '../src/config/loader';
import { buildScanner } from '../src/hook/setup';
import { isLoopbackHost } from '../src/cli/validate';
import {
  bashExposureReason,
  checkPreToolUse,
  globCouldMatchSensitive,
  isSensitivePath,
  parseShellSegments,
  resolveToolGuardConfig,
} from '../src/hook/tool-guard';

const j = (...parts: string[]) => parts.join('');
const RND = 'q8Zx3vL0pRt7NwB2kYh9Fd4JsMa6Ue1C';
const B64 = 'MIIEowIBAAKCAQEA7bq3xK9mPz2LwQvYt8NcR4jH6sUe1DfGa0ZoW5iTnXyVb';

const builtin = new PrivacyScanner(BUILTIN_RULES);
const full = new PrivacyScanner([
  ...BUILTIN_RULES,
  ...loadExternalRulesFromJson(path.resolve(__dirname, '../data/gitleaks-rules.json'), { codingOnly: true }),
]);
const ruleIds = (s: string, scanner = builtin) => scanner.scan(s).findings.map((f) => f.ruleId);
const guard = resolveToolGuardConfig(undefined);

// --- scanner: secrets that used to slip through ------------------------------

describe('database connection strings', () => {
  test.each([
    ['redis with an empty user', j('redis://:', RND, '@cache.internal:6379/0')],
    ['SQLAlchemy postgresql+psycopg2', j('postgresql+psycopg2://app:', RND, '@db.internal/app')],
    ['SQLAlchemy postgresql+asyncpg', j('postgresql+asyncpg://app:', RND, '@db.internal/app')],
    ['SQLAlchemy mysql+pymysql', j('mysql+pymysql://app:', RND, '@db.internal/app')],
    ['mongodb+srv still works', j('mongodb+srv://app:', RND, '@cluster0.mongodb.net/db')],
  ])('%s is a connection string, not just an email', (_label, uri) => {
    expect(ruleIds(uri)).toEqual(['database-connection-string-credentials']);
  });

  test('a credential-less URI still does not match', () => {
    expect(ruleIds('postgresql+psycopg2://db.internal/app')).toEqual([]);
    expect(ruleIds('redis://cache.internal:6379/0')).toEqual([]);
  });
});

describe('assignment operators beyond : and =', () => {
  test.each([
    ['Go :=', j('token := "', RND, '"')],
    ['Go := camelCase', j('apiKey := "', RND, '"')],
    ['Ruby hash =>', j("'secret' => '", RND, "'")],
    ['PHP array =>', j("'api_key' => '", RND, "'")],
    ['Ruby symbol-less => low entropy', j('"auth_token" => "', 'abcd1234abcd1234abcd', '"')],
  ])('%s is flagged as a secret', (_label, code) => {
    const findings = builtin.scan(code).findings;
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.category === 'secret')).toBe(true);
  });

  test('a comparison is not an assignment', () => {
    expect(ruleIds('if token == "abcd1234abcd1234abcd" {')).toEqual([]);
  });
});

describe('private keys', () => {
  const block = (kind: string) => j(`-----BEGIN ${kind}-----\n`, B64, '\n', B64, `\n-----END ${kind}-----`);

  test.each(['DSA PRIVATE KEY', 'ENCRYPTED PRIVATE KEY', 'PGP PRIVATE KEY BLOCK', 'RSA PRIVATE KEY', 'PRIVATE KEY'])(
    'detects a complete %s',
    (kind) => {
      expect(ruleIds(block(kind))).toEqual(['private-key']);
    }
  );

  test('detects a key cut off before its END line', () => {
    expect(ruleIds(j('-----BEGIN RSA PRIVATE KEY-----\n', B64, '\n', B64.slice(0, 30)))).toEqual(['private-key']);
  });

  test('detects a cut-off key inside a JSON string (escaped newlines)', () => {
    expect(ruleIds(j('{"key": "-----BEGIN PRIVATE KEY-----\\n', B64, '\\n'))).toEqual(['private-key']);
  });

  test('detects a legacy encrypted key with Proc-Type headers', () => {
    const pem = j(
      '-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,3F17F5316E2BAC89\n\n',
      B64
    );
    expect(ruleIds(pem)).toEqual(['private-key']);
  });

  test('a bare BEGIN line in code is not a key', () => {
    expect(ruleIds('if (pem.startsWith("-----BEGIN RSA PRIVATE KEY-----")) return true;')).toEqual([]);
  });

  test('stays fast on many BEGIN lines without an END', () => {
    const start = Date.now();
    builtin.scan('-----BEGIN PRIVATE KEY-----\n'.repeat(7000));
    expect(Date.now() - start).toBeLessThan(2000);
  });
});

// --- scanner: false positives that used to block -----------------------------

describe('email addresses that are not a person', () => {
  test.each(['logo@2x.png', 'icon@3x.webp', 'hero@1.5x.jpg', 'git@github.com', 'GIT@gitlab.com'])('%s', (s) => {
    expect(isNonPersonalAddress(s)).toBe(true);
    expect(ruleIds(s)).toEqual([]);
  });

  test.each(['jane@acme-corp.io', 'git.user@acme-corp.io', 'gitbot@acme-corp.io', 'x2@acme-corp.io'])(
    '%s is still an email',
    (s) => {
      expect(isNonPersonalAddress(s)).toBe(false);
      expect(ruleIds(s)).toEqual(['email-address']);
    }
  );
});

describe('openai-api-key needs a digit', () => {
  test('placeholders and hyphenated names are not keys', () => {
    expect(ruleIds('OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxx')).toEqual([]);
    expect(ruleIds('class="sk-folding-cube-animation-wrapper"')).toEqual([]);
  });

  test('real-shaped keys still are', () => {
    expect(ruleIds(j('sk-', 'proj-', RND))).toEqual(['openai-api-key']);
    expect(ruleIds(j('sk-', RND))).toEqual(['openai-api-key']);
  });
});

// --- config ------------------------------------------------------------------

describe('config value types', () => {
  function load(content: unknown) {
    const file = path.join(mkdtempSync(path.join(os.tmpdir(), 'pg-hard-')), '.privacy-guard.json');
    writeFileSync(file, JSON.stringify(content));
    return new ConfigLoader(file).getConfig();
  }
  const awsKey = j('AKIA', 'Z7QWERTYUIOPASDF');

  let warn: typeof console.warn;
  let error: typeof console.error;
  beforeEach(() => {
    warn = console.warn;
    error = console.error;
    console.warn = () => undefined;
    console.error = () => undefined;
  });
  afterEach(() => {
    console.warn = warn;
    console.error = error;
  });

  test('a string allowedPatterns is one pattern, not one pattern per character', () => {
    const config = load({ allowedPatterns: '^sk-test-.*$' });
    expect(config.allowedPatterns).toEqual(['^sk-test-.*$']);
    // Before the fix "." became a pattern and allowed every finding.
    expect(new PrivacyScanner(BUILTIN_RULES, config).scan(awsKey).findings).toHaveLength(1);
  });

  test('wrongly typed lists never crash the scanner (which let prompts through)', () => {
    const config = load({ allowedValues: 'x', allowedDomains: 42, disabledRules: { a: 1 }, allowedPatterns: [1, 'ok'] });
    expect(config.allowedValues).toEqual(['x']);
    expect(config.allowedDomains).toEqual([]);
    expect(config.disabledRules).toEqual([]);
    expect(config.allowedPatterns).toEqual(['ok']);
    expect(() => new PrivacyScanner(BUILTIN_RULES, config).scan(awsKey)).not.toThrow();
  });

  test('a non-boolean "enabled" keeps the guard on', () => {
    expect(load({ enabled: 'false' }).enabled).toBe(true);
    expect(load({ enabled: false }).enabled).toBe(false);
  });

  test('an invalid externalRulesMode or externalRulesJsonPath falls back to the default', () => {
    const config = load({ externalRulesMode: 'coding_only', externalRulesJsonPath: 42 });
    expect(config.externalRulesMode).toBeUndefined();
    expect(config.externalRulesJsonPath).toBeUndefined();
  });

  test.each([[[]], [null], ['block']])('a non-object config (%p) gives the defaults', (content) => {
    const config = load(content);
    expect(config.enabled).toBe(true);
    expect(config.mode).toBe('block');
    expect(config.allowedPatterns).toEqual([]);
  });
});

describe('findConfig', () => {
  test('falls back to the home-directory config for a project outside $HOME', () => {
    const home = mkdtempSync(path.join(os.tmpdir(), 'pg-home-'));
    const project = mkdtempSync(path.join(os.tmpdir(), 'pg-proj-'));
    writeFileSync(path.join(home, '.privacy-guard.json'), '{}');
    expect(ConfigLoader.findConfig(project, home)).toBe(path.join(home, '.privacy-guard.json'));

    // A project config still wins.
    writeFileSync(path.join(project, '.privacy-guard.json'), '{}');
    expect(ConfigLoader.findConfig(project, home)).toBe(path.join(project, '.privacy-guard.json'));
  });

  test('returns null when there is neither', () => {
    const empty = mkdtempSync(path.join(os.tmpdir(), 'pg-empty-'));
    expect(ConfigLoader.findConfig(empty, empty)).toBeNull();
  });
});

// --- tool guard: Bash ----------------------------------------------------------

describe('parseShellSegments', () => {
  test('splits commands and separates redirections', () => {
    expect(parseShellSegments('cat a.txt 2>&1 > out.log && sort < in.txt | head -n 5')).toEqual([
      { words: ['cat', 'a.txt'], inputs: [] },
      { words: ['sort'], inputs: ['in.txt'] },
      { words: ['head', '-n', '5'], inputs: [] },
    ]);
  });

  test('joins quoted pieces and parses command substitutions in double quotes', () => {
    expect(parseShellSegments('cat .e""nv')).toEqual([{ words: ['cat', '.env'], inputs: [] }]);
    expect(parseShellSegments('echo "$(cat .env)"')).toContainEqual({ words: ['cat', '.env'], inputs: [] });
  });
});

describe('bashExposureReason (hardening)', () => {
  test.each([
    'cat .env*',
    'head -5 .env.*',
    'cat ~/.ssh/id_rsa_work',
    'cat ~/.ssh/id_ed25519_github',
    'export',
    'declare -p',
    'echo hi; export',
    'cat .e""nv',
    'echo "$(cat .env)"',
    'rg KEY -g .env',
    'grep -e KEY .env',
    'grep -rne KEY .env',
    'grep -- KEY .env',
    'git grep KEY -- .env',
    'sort < .env',
    'cat <.env',
    "awk '{print}' .env",
    'sed -n 1p .env',
    'jq . .env.json',
    'sudo cat /root/.aws/credentials',
    'find . -name .env -exec cat {} \\;',
    'cat *.pem',
    'cat certs/id_*',
  ])('flags %s', (cmd) => {
    expect(bashExposureReason(cmd, guard)).not.toBeNull();
  });

  test.each([
    // Writing a file is not reading it.
    'cat > .env <<EOF\nFOO=bar\nEOF',
    'cat .env.example > .env',
    'cat a.txt 2>&1 > .env',
    'cat a.txt &>> .env.local',
    'cat a.txt >| .env',
    // A search pattern or script is not a file.
    'grep -rn ".env" src',
    'rg "\\.env" -g "*.ts"',
    'git grep -n .env',
    "jq '.env' app.json",
    'grep -e .env -r src',
    "sed -i 's/.env/.env.local/' Makefile",
    "awk '/.env/' Makefile",
    // A reader elsewhere on the line does not make every word a file.
    'echo "add KEY to .env" && cat README.md',
    'git commit -m "ignore .env" && git log | head',
    'ls .env; cat README.md',
    // Broad globs and public keys.
    'cat *.ts',
    'cat config/*.json',
    'cat ~/.ssh/id_rsa_work.pub',
    'cat .env.local.example',
    // Still not dumps.
    'export FOO=bar',
    'declare -p FOO',
  ])('does not flag %s', (cmd) => {
    expect(bashExposureReason(cmd, guard)).toBeNull();
  });

  test('names the file in ~ form', () => {
    expect(bashExposureReason('cat ~/.aws/credentials', guard)).toBe('reads sensitive file ~/.aws/credentials');
  });
});

// --- tool guard: paths and globs -------------------------------------------

describe('path globs', () => {
  test('"**/" matches zero directories too', () => {
    const g = resolveToolGuardConfig({ sensitivePaths: ['**/secrets/*'] });
    expect(isSensitivePath('secrets/a.txt', g)).toBe(true);
    expect(isSensitivePath('/repo/secrets/a.txt', g)).toBe(true);
    expect(isSensitivePath('/repo/secrets/deep/a.txt', g)).toBe(false);
  });

  test('a leading "./" is relative to the project', () => {
    const g = resolveToolGuardConfig({ sensitivePaths: ['./config/prod.json'], allowedPaths: ['./.env.test'] });
    expect(isSensitivePath('/repo/config/prod.json', g)).toBe(true);
    expect(isSensitivePath('config/prod.json', g)).toBe(true);
    expect(isSensitivePath('/repo/.env.test', g)).toBe(false);
  });

  test('custom-named SSH keys are sensitive, their public halves are not', () => {
    expect(isSensitivePath('/home/me/.ssh/id_ed25519_github', guard)).toBe(true);
    expect(isSensitivePath('/home/me/.ssh/id_rsa-work', guard)).toBe(true);
    expect(isSensitivePath('/home/me/.ssh/id_ed25519_github.pub', guard)).toBe(false);
  });

  test('templates of environment-specific env files are allowed', () => {
    expect(isSensitivePath('.env.local.example', guard)).toBe(false);
    expect(isSensitivePath('.env.production.sample', guard)).toBe(false);
    expect(isSensitivePath('.env.production', guard)).toBe(true);
  });

  test.each([
    ['.env*', true],
    ['**/.env*', true],
    ['id_*', true],
    ['*.pem', true],
    ['*.key', true],
    ['*', false],
    ['*.*', false],
    ['*.json', false],
    ['*.{ts,tsx}', false],
    ['src/**/*.ts', false],
    ['.env.example', false],
  ])('globCouldMatchSensitive(%s) = %s', (glob, expected) => {
    expect(globCouldMatchSensitive(glob, guard)).toBe(expected);
  });
});

describe('Grep tool', () => {
  const pre = (tool_input: Record<string, unknown>) =>
    checkPreToolUse({ hook_event_name: 'PreToolUse', tool_name: 'Grep', tool_input, cwd: '/repo' }, guard, builtin, () => null)
      ?.hookSpecificOutput.permissionDecision ?? null;

  test('a glob that targets credentials files is guarded', () => {
    expect(pre({ pattern: 'KEY', glob: '.env*', output_mode: 'content' })).toBe('ask');
    expect(pre({ pattern: 'KEY', glob: '**/*.pem' })).toBe('ask');
    expect(pre({ pattern: 'KEY', glob: '*.ts', output_mode: 'content' })).toBeNull();
  });

  test('modes that print only file names or counts are not guarded', () => {
    expect(pre({ pattern: 'KEY', path: '/repo/.env', output_mode: 'files_with_matches' })).toBeNull();
    expect(pre({ pattern: 'KEY', path: '/repo/.env', output_mode: 'count' })).toBeNull();
    expect(pre({ pattern: 'KEY', path: '/repo/.env', output_mode: 'content' })).toBe('ask');
    // Unset mode is still checked, whatever Grep's default is.
    expect(pre({ pattern: 'KEY', path: '/repo/.env' })).toBe('ask');
  });
});

// --- scan size -----------------------------------------------------------------

describe('toolGuard.maxScanBytes above the scanner default', () => {
  const late = j(' '.repeat(250_000), 'const k = "', 'ghp_', RND, 'abcd', '";');

  test('buildScanner passes maxScanLength through', () => {
    const prev = process.env.XDG_CACHE_HOME;
    process.env.XDG_CACHE_HOME = mkdtempSync(path.join(os.tmpdir(), 'pg-cache-'));
    try {
      const setup = {
        config: new ConfigLoader().getConfig(),
        configPath: null,
        defaultRulesPath: path.resolve(__dirname, '../data/gitleaks-rules.json'),
        version: 'test',
      };
      expect(buildScanner(setup).scan(late).findings).toHaveLength(0);
      expect(buildScanner({ ...setup, maxScanLength: 400_000 }).scan(late).findings.length).toBeGreaterThan(0);
    } finally {
      process.env.XDG_CACHE_HOME = prev;
    }
  });
});

// --- hook scripts end to end -----------------------------------------------------

describe('scripts/tool-guard.js (hardening)', () => {
  const HOOK = path.resolve(__dirname, '../scripts/tool-guard.js');

  function run(envelope: Record<string, unknown>, opts: { config?: unknown; files?: Record<string, string>; home?: string } = {}) {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'pg-hard-hook-'));
    if (opts.config !== undefined) writeFileSync(path.join(dir, '.privacy-guard.json'), JSON.stringify(opts.config));
    for (const [name, content] of Object.entries(opts.files ?? {})) writeFileSync(path.join(dir, name), content);
    const home = opts.home ?? mkdtempSync(path.join(os.tmpdir(), 'pg-hard-home-'));
    const stdout = execFileSync('node', [HOOK], {
      input: JSON.stringify({ cwd: dir, ...envelope }),
      cwd: dir,
      encoding: 'utf-8',
      timeout: 8000,
      env: { ...process.env, HOME: home, USERPROFILE: home, XDG_CACHE_HOME: path.join(dir, 'cache') },
      stdio: ['pipe', 'pipe', 'ignore'],
    });
    return { dir, out: stdout.trim() ? JSON.parse(stdout) : null };
  }

  test('a raised maxScanBytes scans past 200k characters of a file', () => {
    const files = { 'big.js': j(' '.repeat(250_000), 'const k = "', 'ghp_', RND, 'abcd', '";\n') };
    const read = { hook_event_name: 'PreToolUse', tool_name: 'Read', tool_input: { file_path: 'big.js' } };
    expect(run(read, { files }).out).toBeNull();
    expect(run(read, { files, config: { toolGuard: { maxScanBytes: 400_000 } } }).out?.hookSpecificOutput.permissionDecision).toBe('ask');
  });

  test('a string allowedPatterns no longer disables detection', () => {
    const { out } = run(
      { hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_input: { command: 'x' }, tool_response: { stdout: j('ghp_', RND, 'abcd') } },
      { config: { allowedPatterns: '^sk-test-.*$' } }
    );
    expect(out?.systemMessage).toMatch(/GitHub Token/);
  });

  test('the home-directory config applies to a project outside $HOME', () => {
    const home = mkdtempSync(path.join(os.tmpdir(), 'pg-hard-home-'));
    writeFileSync(path.join(home, '.privacy-guard.json'), JSON.stringify({ toolGuard: { enabled: false } }));
    const env = { hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'env' } };
    expect(run(env, { home }).out).toBeNull();
    expect(run(env).out?.hookSpecificOutput.permissionDecision).toBe('ask');
  });

  (process.platform === 'win32' ? test.skip : test)('Read of a FIFO does not hang the hook', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'pg-fifo-'));
    mkdirSync(dir, { recursive: true });
    const fifo = path.join(dir, 'pipe');
    execFileSync('mkfifo', [fifo]);
    const start = Date.now();
    const { out } = run({ hook_event_name: 'PreToolUse', tool_name: 'Read', tool_input: { file_path: fifo } });
    expect(out).toBeNull();
    expect(Date.now() - start).toBeLessThan(5000);
  });
});

// --- rules UI server -------------------------------------------------------------

describe('rules UI Host check', () => {
  test('only loopback Host headers for the bound port are accepted', () => {
    expect(isLoopbackHost('127.0.0.1:4321', 4321)).toBe(true);
    expect(isLoopbackHost('localhost:4321', 4321)).toBe(true);
    expect(isLoopbackHost('evil.example:4321', 4321)).toBe(false);
    expect(isLoopbackHost('127.0.0.1:4322', 4321)).toBe(false);
    expect(isLoopbackHost(undefined, 4321)).toBe(false);
    expect(isLoopbackHost('127.0.0.1:0', 0)).toBe(false);
  });
});
