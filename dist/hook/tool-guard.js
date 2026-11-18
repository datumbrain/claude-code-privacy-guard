/**
 * Tool I/O guard: PreToolUse and PostToolUse decisions.
 *
 * The prompt hook only sees what the user types. In practice the bigger leak
 * path is tool traffic: `Read` on `.env`, `cat ~/.aws/credentials` through
 * Bash, grep output full of tokens. This module decides what to do about it.
 *
 * - PreToolUse (Read, Grep, Bash): the only point where a leak can still be
 *   prevented. A tool call that targets a known-sensitive path, dumps the
 *   environment, or (for Read) points at a file whose contents contain
 *   secrets gets an "ask" (default) or "deny" permission decision.
 * - PostToolUse: the output is already in Claude's context by the time this
 *   runs (Claude Code does not let a hook rewrite a built-in tool's output),
 *   so it can only warn: a systemMessage tells the user what leaked so they
 *   can rotate it, and additionalContext asks Claude not to repeat the values.
 *
 * Everything here is pure (file access goes through an injectable reader) so
 * it can be unit-tested without spawning the hook.
 */
import * as path from 'path';
import { maskMatch } from './response.js';
export const DEFAULT_TOOL_GUARD = {
    enabled: true,
    preToolUse: 'ask',
    postToolUse: 'warn',
    sensitivePaths: [],
    allowedPaths: [],
    maxScanBytes: 200_000,
};
/**
 * Paths that hold credentials by convention. A glob without "/" matches the
 * file's basename; one with "/" matches the end of the full path.
 */
export const DEFAULT_SENSITIVE_PATHS = [
    '.env',
    '.env.*',
    '*.pem',
    '*.key',
    '*.p12',
    '*.pfx',
    '*.jks',
    '*.keystore',
    'id_rsa',
    'id_dsa',
    'id_ecdsa',
    'id_ed25519',
    '.netrc',
    '_netrc',
    '.pgpass',
    '.git-credentials',
    '.npmrc',
    '.pypirc',
    '.htpasswd',
    '.vault-token',
    'credentials.json',
    'service-account*.json',
    '.aws/credentials',
    '.docker/config.json',
    '.kube/config',
    '.config/gcloud/application_default_credentials.json',
    '.config/gcloud/credentials.db',
    '/proc/*/environ',
];
/** Never treated as sensitive, even if a sensitive glob matches. */
export const DEFAULT_ALLOWED_PATHS = [
    '.env.example',
    '.env.sample',
    '.env.template',
    '.env.dist',
    '.env.defaults',
    '*.pub',
];
export function resolveToolGuardConfig(config) {
    return { ...DEFAULT_TOOL_GUARD, ...(config ?? {}) };
}
// --- path matching ---------------------------------------------------------
function globToRegExp(glob) {
    let re = '';
    for (let i = 0; i < glob.length; i++) {
        const ch = glob[i];
        if (ch === '*' && glob[i + 1] === '*') {
            re += '.*';
            i++;
        }
        else if (ch === '*') {
            re += '[^/]*';
        }
        else if (ch === '?') {
            re += '[^/]';
        }
        else {
            re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
        }
    }
    return glob.includes('/') ? new RegExp(`(?:^|/)${re.replace(/^\\?\//, '')}$`, 'i') : new RegExp(`^${re}$`, 'i');
}
function matchesAny(filePath, globs) {
    const normalized = filePath.replace(/\\/g, '/');
    const base = normalized.split('/').pop() ?? normalized;
    return globs.some((glob) => {
        const re = globToRegExp(glob);
        return glob.includes('/') ? re.test(normalized) : re.test(base);
    });
}
export function isSensitivePath(filePath, guard) {
    if (!filePath)
        return false;
    if (matchesAny(filePath, [...DEFAULT_ALLOWED_PATHS, ...guard.allowedPaths]))
        return false;
    return matchesAny(filePath, [...DEFAULT_SENSITIVE_PATHS, ...guard.sensitivePaths]);
}
// --- bash command analysis -------------------------------------------------
const ENV_DUMP = /(?:^|[;&|(]\s*|\$\(\s*|`\s*)(?:sudo\s+)?(?:printenv|env|export\s+-p|declare\s+-x|set)\s*(?:$|[;&|)`>])/m;
/** Split a shell command into word-ish tokens (quotes stripped). Not a full parser. */
function shellTokens(command) {
    const tokens = [];
    const re = /"([^"]*)"|'([^']*)'|([^\s;&|<>()`]+)/g;
    let m;
    while ((m = re.exec(command)) !== null)
        tokens.push(m[1] ?? m[2] ?? m[3]);
    return tokens;
}
// Commands that print (part of) a file's contents. A sensitive path only
// counts when one of these is in the command, so `source .env`, `ls .env`,
// `cp .env.example .env` or `docker run --env-file .env` don't trigger.
const READERS = new Set([
    'cat', 'tac', 'nl', 'less', 'more', 'head', 'tail', 'bat', 'batcat', 'view',
    'grep', 'egrep', 'fgrep', 'rg', 'ag', 'awk', 'gawk', 'sed', 'cut', 'sort', 'uniq',
    'xxd', 'hexdump', 'od', 'strings', 'base64', 'jq', 'yq', 'diff', 'type', 'get-content',
    'openssl', 'python', 'python3', 'node',
]);
/** Why a Bash command looks like it would expose secrets, or null. */
export function bashExposureReason(command, guard) {
    if (ENV_DUMP.test(command))
        return 'dumps environment variables';
    const tokens = shellTokens(command);
    const readsFiles = /<\s*[^<\s]/.test(command.replace(/<<-?\s*\S+/g, '')) ||
        tokens.some((t) => READERS.has((t.split('/').pop() ?? t).toLowerCase()));
    if (!readsFiles)
        return null;
    for (const token of tokens) {
        // Strip redirection/assignment prefixes like `<.env` or `--env-file=.env`.
        const candidate = token.includes('=') ? token.slice(token.lastIndexOf('=') + 1) : token;
        const expanded = candidate.replace(/^~(?=\/)/, '$HOME');
        if (isSensitivePath(expanded, guard))
            return `reads sensitive file ${candidate}`;
    }
    return null;
}
// --- formatting ------------------------------------------------------------
function findingsSummary(result, limit = 10) {
    const lines = result.findings
        .slice(0, limit)
        .map((f) => `  - ${f.title} (${f.ruleId}): ${maskMatch(f.match)}`);
    if (result.findings.length > limit)
        lines.push(`  - ...and ${result.findings.length - limit} more`);
    return lines.join('\n');
}
function preDecision(decision, reason) {
    return {
        hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            permissionDecision: decision,
            permissionDecisionReason: `Privacy Guard: ${reason}`,
        },
    };
}
// --- PreToolUse ------------------------------------------------------------
export function checkPreToolUse(input, guard, scanner, readFile) {
    if (!guard.enabled || guard.preToolUse === 'off')
        return null;
    const decision = guard.preToolUse;
    const toolInput = input.tool_input ?? {};
    const cwd = typeof input.cwd === 'string' ? input.cwd : process.cwd();
    if (input.tool_name === 'Bash' && typeof toolInput.command === 'string') {
        const why = bashExposureReason(toolInput.command, guard);
        return why ? preDecision(decision, `this command ${why}, which would put secrets into the conversation.`) : null;
    }
    if (input.tool_name === 'Grep' && typeof toolInput.path === 'string') {
        return isSensitivePath(toolInput.path, guard)
            ? preDecision(decision, `searching ${toolInput.path} would put secrets into the conversation.`)
            : null;
    }
    if (input.tool_name === 'Read' && typeof toolInput.file_path === 'string') {
        const filePath = toolInput.file_path;
        // An explicitly allowed path skips both the path check and the content scan.
        if (matchesAny(filePath, guard.allowedPaths))
            return null;
        if (isSensitivePath(filePath, guard)) {
            return preDecision(decision, `${filePath} usually holds credentials. Reading it would put them into the conversation.`);
        }
        const content = readFile(path.resolve(cwd, filePath), guard.maxScanBytes);
        if (content === null)
            return null;
        const result = scanner.scan(content);
        if (result.findings.length === 0)
            return null;
        return preDecision(decision, `${filePath} contains ${result.findings.length} sensitive item(s). Reading it would put them into the conversation:\n${findingsSummary(result)}\n` +
            'Add the path to "toolGuard.allowedPaths" in .privacy-guard.json to stop asking for it.');
    }
    return null;
}
// --- PostToolUse -----------------------------------------------------------
/** Concatenate every string inside a tool response, up to `maxBytes`. */
export function collectText(value, maxBytes) {
    const parts = [];
    let size = 0;
    const visit = (v, depth) => {
        if (size >= maxBytes || depth > 8 || v === null || v === undefined)
            return;
        if (typeof v === 'string') {
            const piece = v.slice(0, maxBytes - size);
            parts.push(piece);
            size += piece.length + 1;
        }
        else if (Array.isArray(v)) {
            for (const item of v)
                visit(item, depth + 1);
        }
        else if (typeof v === 'object') {
            for (const item of Object.values(v))
                visit(item, depth + 1);
        }
    };
    visit(value, 0);
    return parts.join('\n');
}
export function checkPostToolUse(input, guard, scanner) {
    if (!guard.enabled || guard.postToolUse === 'off')
        return null;
    const text = collectText(input.tool_response, guard.maxScanBytes);
    if (!text)
        return null;
    const result = scanner.scan(text);
    if (result.findings.length === 0)
        return null;
    const tool = input.tool_name ?? 'tool';
    return {
        systemMessage: `🛡️ Privacy Guard: ${tool} output contained ${result.findings.length} sensitive item(s), and it is now in the conversation:\n` +
            `${findingsSummary(result)}\nConsider rotating these credentials.`,
        hookSpecificOutput: {
            hookEventName: 'PostToolUse',
            additionalContext: `Privacy Guard detected ${result.findings.length} secret or PII value(s) in the ${tool} output ` +
                `(${[...new Set(result.findings.map((f) => f.title))].join(', ')}). ` +
                'Do not repeat, quote, log, or transmit these values. Refer to them only by name (for example "the API key in .env").',
        },
    };
}
