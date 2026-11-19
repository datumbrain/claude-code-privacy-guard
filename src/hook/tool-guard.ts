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
import { PrivacyScanner } from '../scanner/engine.js';
import { ScanResult, ToolGuardConfig } from '../types/findings.js';
import { maskMatch } from './response.js';

export const DEFAULT_TOOL_GUARD: Required<ToolGuardConfig> = {
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
  // Also custom-named keys (id_rsa_work, id_ed25519_github); the matching
  // public keys are let through by "*.pub" in DEFAULT_ALLOWED_PATHS.
  'id_rsa*',
  'id_dsa*',
  'id_ecdsa*',
  'id_ed25519*',
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
  '.env.*.example',
  '.env.*.sample',
  '.env.*.template',
  '*.pub',
];

export interface HookInput {
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  tool_response?: unknown;
  cwd?: string;
  /** Session permission mode, e.g. "default", "acceptEdits", "plan", "auto", "bypassPermissions". */
  permission_mode?: string;
}

/**
 * Permission modes in which Claude Code resolves an "ask" without showing the
 * user a prompt (auto mode's classifier decides it; bypass and dontAsk never
 * prompt). An "ask" there protects nothing, so it is escalated to "deny".
 */
export const NON_INTERACTIVE_PERMISSION_MODES = new Set(['auto', 'bypassPermissions', 'dontAsk']);

export interface ToolHookOutput {
  systemMessage?: string;
  hookSpecificOutput: {
    hookEventName: 'PreToolUse' | 'PostToolUse';
    permissionDecision?: 'ask' | 'deny';
    permissionDecisionReason?: string;
    additionalContext?: string;
  };
}

/** Reads up to `maxBytes` of a file, or returns null when it can't. */
export type FileReader = (filePath: string, maxBytes: number) => string | null;

export function resolveToolGuardConfig(config: ToolGuardConfig | undefined): Required<ToolGuardConfig> {
  return { ...DEFAULT_TOOL_GUARD, ...(config ?? {}) };
}

// --- path matching ---------------------------------------------------------

function globToRegExp(rawGlob: string): RegExp {
  // "./x" means x relative to the project, which is how every other relative
  // glob is already matched (against the end of the path).
  const glob = rawGlob.replace(/^(?:\.\/)+/, '');
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i];
    if (ch === '*' && glob[i + 1] === '*' && glob[i + 2] === '/') {
      // "**/" matches zero or more directories, so "**/secrets/*" also
      // matches a top-level "secrets/a".
      re += '(?:.*/)?';
      i += 2;
    } else if (ch === '*' && glob[i + 1] === '*') {
      re += '.*';
      i++;
    } else if (ch === '*') {
      re += '[^/]*';
    } else if (ch === '?') {
      re += '[^/]';
    } else {
      re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return glob.includes('/') ? new RegExp(`(?:^|/)${re.replace(/^\\?\//, '')}$`, 'i') : new RegExp(`^${re}$`, 'i');
}

function matchesAny(filePath: string, globs: string[]): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  const base = normalized.split('/').pop() ?? normalized;
  return globs.some((glob) => {
    const re = globToRegExp(glob);
    return glob.replace(/^(?:\.\/)+/, '').includes('/') ? re.test(normalized) : re.test(base);
  });
}

export function isSensitivePath(filePath: string, guard: Required<ToolGuardConfig>): boolean {
  if (!filePath) return false;
  if (matchesAny(filePath, [...DEFAULT_ALLOWED_PATHS, ...guard.allowedPaths])) return false;
  return matchesAny(filePath, [...DEFAULT_SENSITIVE_PATHS, ...guard.sensitivePaths]);
}

/**
 * Whether a shell or Grep glob such as ".env*", "id_*" or "*.pem" could
 * expand to a sensitive file name. The file name part of the glob is tested
 * against sample names built from the sensitive file-name globs. A glob that
 * starts with "*" is only tested against the extension-style samples
 * ("*.pem" -> "x.pem"), so broad globs like "*.json" or "*" are not flagged
 * just because "credentials.json" would match them.
 */
export function globCouldMatchSensitive(glob: string, guard: Required<ToolGuardConfig>): boolean {
  const base = glob.replace(/\\/g, '/').split('/').pop() ?? glob;
  if (!/[*?]/.test(base)) return false;
  // "*", "*.*", "??" - every file in a directory; too broad to call a read
  // of credentials (and shell "*" skips dotfiles such as .env anyway).
  if (/^[*?]+(?:\.[*?]+)?$/.test(base)) return false;
  const re = globToRegExp(base);
  const leadingWildcard = /^[*?]/.test(base);
  return [...DEFAULT_SENSITIVE_PATHS, ...guard.sensitivePaths]
    .filter((g) => !g.includes('/') && (!leadingWildcard || g.startsWith('*')))
    .map((g) => g.replace(/[*?]/g, 'x'))
    .some((sample) => re.test(sample) && isSensitivePath(sample, guard));
}

// --- bash command analysis -------------------------------------------------

const ENV_DUMP =
  /(?:^|[;&|(]\s*|\$\(\s*|`\s*)(?:sudo\s+)?(?:printenv|env|export|export\s+-p|declare\s+-[px]|typeset\s+-[px]|set)\s*(?:$|[;&|)`>])/m;

/**
 * One simple command of a shell line: its words (quotes removed, redirection
 * targets taken out) and the files it reads through `<`.
 */
export interface ShellSegment {
  words: string[];
  inputs: string[];
}

/**
 * Split a shell command into simple commands. Not a full parser, but it
 * honors quoting and escapes, splits on ; & | && || newlines, parentheses and
 * backticks, and tells input redirections (`< .env`) apart from output ones
 * (`> .env`, `2>&1`, `&>> log`), which write a file rather than print it.
 * Command substitutions inside double quotes ("$(cat .env)") are parsed as
 * commands of their own.
 */
export function parseShellSegments(command: string, depth = 0): ShellSegment[] {
  const segments: ShellSegment[] = [];
  const nested: string[] = [];
  let seg: ShellSegment = { words: [], inputs: [] };
  let word = '';
  let inWord = false;
  // What the next completed word is: an input file, an output file or
  // heredoc/herestring data to drop, or (null) an ordinary word.
  let pending: 'in' | 'drop' | null = null;

  const endWord = (): void => {
    if (inWord) {
      if (pending === 'in') seg.inputs.push(word);
      else if (pending === null) seg.words.push(word);
      pending = null;
    }
    word = '';
    inWord = false;
  };
  const endSegment = (): void => {
    endWord();
    pending = null;
    if (seg.words.length > 0 || seg.inputs.length > 0) segments.push(seg);
    seg = { words: [], inputs: [] };
  };
  const isFd = (): boolean => inWord && /^\d+$/.test(word);

  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    const next = command[i + 1];
    if (ch === "'") {
      const close = command.indexOf("'", i + 1);
      const stop = close === -1 ? command.length : close;
      word += command.slice(i + 1, stop);
      inWord = true;
      i = stop;
    } else if (ch === '"') {
      let j = i + 1;
      let quoted = '';
      while (j < command.length && command[j] !== '"') {
        if (command[j] === '\\' && j + 1 < command.length && '$`"\\\n'.includes(command[j + 1])) {
          quoted += command[j + 1];
          j += 2;
        } else {
          quoted += command[j++];
        }
      }
      if (/\$\(|`/.test(quoted)) nested.push(quoted.replace(/^[^$`]*/, ''));
      word += quoted;
      inWord = true;
      i = j;
    } else if (ch === '\\') {
      if (next === '\n') {
        i++;
      } else if (next !== undefined) {
        word += next;
        inWord = true;
        i++;
      }
    } else if (ch === ' ' || ch === '\t') {
      endWord();
    } else if (ch === '\n' || ch === ';' || ch === '(' || ch === ')' || ch === '`') {
      endSegment();
    } else if (ch === '|') {
      endSegment();
      if (next === '|' || next === '&') i++;
    } else if (ch === '&') {
      if (next === '>') {
        // &> file, &>> file
        endWord();
        i++;
        if (command[i + 1] === '>') i++;
        pending = 'drop';
      } else {
        endSegment();
        if (next === '&') i++;
      }
    } else if (ch === '>') {
      if (isFd()) {
        word = '';
        inWord = false;
      } else {
        endWord();
      }
      if (next === '>' || next === '|') i++;
      if (command[i + 1] === '&') {
        // >&2, 2>&1, >&- duplicate a descriptor; ">& file" writes a file.
        i++;
        const fd = /^\s*(?:\d+|-)/.exec(command.slice(i + 1));
        if (fd) i += fd[0].length;
        else pending = 'drop';
      } else {
        pending = 'drop';
      }
    } else if (ch === '<') {
      if (isFd()) {
        word = '';
        inWord = false;
      } else {
        endWord();
      }
      if (next === '<') {
        // <<EOF, <<-EOF (heredoc delimiter) and <<<"text" (herestring data).
        i++;
        if (command[i + 1] === '<' || command[i + 1] === '-') i++;
        pending = 'drop';
      } else if (next === '(') {
        // Process substitution: the "(" starts a nested command.
      } else {
        if (next === '>') i++;
        pending = 'in';
      }
    } else {
      word += ch;
      inWord = true;
    }
  }
  endSegment();

  if (depth < 3) for (const inner of nested) segments.push(...parseShellSegments(inner, depth + 1));
  return segments;
}

// Commands that print (part of) a file's contents. A sensitive path only
// counts in a command that runs one of these, so `source .env`, `ls .env`,
// `cp .env.example .env` or `docker run --env-file .env` don't trigger.
const READERS = new Set([
  'cat', 'tac', 'nl', 'less', 'more', 'head', 'tail', 'bat', 'batcat', 'view',
  'grep', 'egrep', 'fgrep', 'zgrep', 'rg', 'ag', 'ack', 'awk', 'gawk', 'sed', 'cut', 'sort', 'uniq',
  'xxd', 'hexdump', 'od', 'strings', 'base64', 'jq', 'yq', 'diff', 'type', 'get-content',
  'openssl',
]);

// Prefixes that run the next word as the command.
const COMMAND_WRAPPERS = new Set(['sudo', 'command', 'exec', 'nohup', 'time', 'nice', 'env', 'xargs']);

/**
 * Commands whose first operand is a pattern or script, not a file:
 * `grep ".env" src`, `sed -n 1p f`, `jq .env app.json`. `valueOptions` take the
 * next word as their value; `patternOptions` take the pattern itself (so no
 * operand is a pattern when one of them is used).
 */
interface PatternFirstCommand {
  valueOptions: Set<string>;
  patternOptions: Set<string>;
  /** Options that take two values (jq's --arg name value). */
  pairOptions?: Set<string>;
}

const GREP_SPEC: PatternFirstCommand = {
  valueOptions: new Set(['-A', '-B', '-C', '-m', '-d', '-D', '--max-count', '--context', '--after-context', '--before-context', '--include', '--exclude', '--exclude-dir', '-f', '--file']),
  patternOptions: new Set(['-e', '--regexp', '-f', '--file']),
};
const RG_SPEC: PatternFirstCommand = {
  valueOptions: new Set(['-A', '-B', '-C', '-m', '-g', '-t', '-T', '-M', '-j', '-f', '--glob', '--iglob', '--type', '--type-not', '--max-count', '--context', '--after-context', '--before-context', '--file']),
  patternOptions: new Set(['-e', '--regexp', '-f', '--file']),
};
const PATTERN_FIRST: Record<string, PatternFirstCommand> = {
  grep: GREP_SPEC,
  egrep: GREP_SPEC,
  fgrep: GREP_SPEC,
  zgrep: GREP_SPEC,
  ag: GREP_SPEC,
  ack: GREP_SPEC,
  rg: RG_SPEC,
  sed: { valueOptions: new Set(['-e', '-f', '-l', '--expression', '--file']), patternOptions: new Set(['-e', '-f', '--expression', '--file']) },
  awk: { valueOptions: new Set(['-F', '-v', '-f']), patternOptions: new Set(['-f']) },
  gawk: { valueOptions: new Set(['-F', '-v', '-f']), patternOptions: new Set(['-f']) },
  jq: {
    valueOptions: new Set(['-L', '--indent', '-f', '--from-file']),
    patternOptions: new Set(['-f', '--from-file']),
    pairOptions: new Set(['--arg', '--argjson', '--slurpfile', '--rawfile']),
  },
  yq: { valueOptions: new Set(['-I', '--indent', '-o', '--output-format', '-p', '--input-format']), patternOptions: new Set() },
};

const PATTERN_FILE_OPTIONS = new Set(['-f', '--file', '--from-file']);

const baseName = (word: string): string => (word.replace(/\\/g, '/').split('/').pop() ?? word).toLowerCase();

/**
 * Indexes of the words in a segment that are a search pattern or script
 * (and so are not files), e.g. ".env" in `grep -rn ".env" src`.
 */
function patternWordIndexes(words: string[]): Set<number> {
  const skip = new Set<number>();
  let k = 0;
  while (k < words.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(words[k]) || COMMAND_WRAPPERS.has(baseName(words[k])))) k++;
  let name = baseName(words[k] ?? '');
  let start = k + 1;
  if (name === 'git' && words[k + 1] === 'grep') {
    name = 'grep';
    start = k + 2;
  }
  const spec = PATTERN_FIRST[name];
  if (!spec) return skip;

  // An option that names the pattern (grep -e PAT) means no operand is one.
  const optionName = (w: string): string => (/^-[A-Za-z]+$/.test(w) ? `-${w.slice(-1)}` : w.split('=')[0]);
  const explicit = words.slice(start).some((w) => w.startsWith('-') && spec.patternOptions.has(optionName(w)));

  let operandsOnly = false;
  for (let i = start; i < words.length; i++) {
    const w = words[i];
    if (!operandsOnly && w === '--') {
      operandsOnly = true;
      continue;
    }
    if (!operandsOnly && w.startsWith('-') && w.length > 1) {
      const opt = optionName(w);
      const attached = w.includes('=') || /^-[A-Za-z]+\d/.test(w);
      if (attached) continue;
      if (spec.pairOptions?.has(opt)) {
        i += 2;
      } else if (spec.valueOptions.has(opt) || spec.patternOptions.has(opt)) {
        // A pattern given through -e/--regexp is not a file either; a pattern
        // *file* (-f) still is.
        if (spec.patternOptions.has(opt) && !PATTERN_FILE_OPTIONS.has(opt)) skip.add(i + 1);
        i += 1;
      }
      continue;
    }
    if (!explicit) skip.add(i);
    break;
  }
  return skip;
}

/** The file a word names, for the sensitive-path check (`--env-file=.env` -> `.env`). */
function wordAsPath(word: string): string {
  const candidate = word.includes('=') ? word.slice(word.lastIndexOf('=') + 1) : word;
  return candidate.replace(/^~(?=\/)/, '$HOME');
}

function isSensitiveWord(word: string, guard: Required<ToolGuardConfig>): boolean {
  const p = wordAsPath(word);
  return isSensitivePath(p, guard) || globCouldMatchSensitive(p, guard);
}

/**
 * Drop heredoc bodies (`<<EOF ... EOF`, `<<'EOF'`, `<<-EOF`), keeping the rest
 * of the opening line. A heredoc body is data fed to a program - often a
 * script or test text that merely mentions `.env` - not a file being read.
 */
export function stripHeredocs(command: string): string {
  return command.replace(
    /<<-?[ \t]*(['"]?)([A-Za-z_][\w-]*)\1([^\n]*)\n[\s\S]*?\n[ \t]*\2[ \t]*(?=\n|$)/g,
    ' $3'
  );
}

/** Why a Bash command looks like it would expose secrets, or null. */
export function bashExposureReason(rawCommand: string, guard: Required<ToolGuardConfig>): string | null {
  const command = stripHeredocs(rawCommand);
  if (ENV_DUMP.test(command)) return 'dumps environment variables';
  for (const seg of parseShellSegments(command)) {
    // `cmd < .env` feeds the file to the command, which may well print it.
    const input = seg.inputs.find((w) => isSensitiveWord(w, guard));
    if (input !== undefined) return `reads sensitive file ${input}`;
    if (!seg.words.some((w) => READERS.has(baseName(w)))) continue;
    const skip = patternWordIndexes(seg.words);
    const file = seg.words.find((w, i) => !skip.has(i) && isSensitiveWord(w, guard));
    if (file !== undefined) return `reads sensitive file ${wordAsPath(file).replace(/^\$HOME(?=\/)/, '~')}`;
  }
  return null;
}

// --- formatting ------------------------------------------------------------

function findingsSummary(result: ScanResult, limit = 10): string {
  const lines = result.findings
    .slice(0, limit)
    .map((f) => `  - ${f.title} (${f.ruleId}): ${maskMatch(f.match)}`);
  if (result.findings.length > limit) lines.push(`  - ...and ${result.findings.length - limit} more`);
  return lines.join('\n');
}

function preDecision(decision: 'ask' | 'deny', reason: string, escalatedFrom?: string): ToolHookOutput {
  if (escalatedFrom) {
    reason +=
      ` Blocked rather than asked because this session is in "${escalatedFrom}" permission mode, where a confirmation prompt would not reach you.` +
      (reason.includes('allowedPaths')
        ? ' Or switch to the default permission mode and retry.'
        : ' To allow it, add the path to "toolGuard.allowedPaths" in .privacy-guard.json, or switch to the default permission mode and retry.');
  }
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: decision,
      permissionDecisionReason: `Privacy Guard: ${reason}`,
    },
  };
}

// --- PreToolUse ------------------------------------------------------------

export function checkPreToolUse(
  input: HookInput,
  guard: Required<ToolGuardConfig>,
  scanner: PrivacyScanner,
  readFile: FileReader
): ToolHookOutput | null {
  if (!guard.enabled || guard.preToolUse === 'off') return null;
  // "ask" only works if the user will actually see the prompt.
  const escalatedFrom =
    guard.preToolUse === 'ask' && input.permission_mode && NON_INTERACTIVE_PERMISSION_MODES.has(input.permission_mode)
      ? input.permission_mode
      : undefined;
  const decision = escalatedFrom ? 'deny' : guard.preToolUse;
  const decide = (reason: string): ToolHookOutput => preDecision(decision, reason, escalatedFrom);
  const toolInput = input.tool_input ?? {};
  const cwd = typeof input.cwd === 'string' ? input.cwd : process.cwd();

  if (input.tool_name === 'Bash' && typeof toolInput.command === 'string') {
    const why = bashExposureReason(toolInput.command, guard);
    return why ? decide(`this command ${why}, which would put secrets into the conversation.`) : null;
  }

  if (input.tool_name === 'Grep') {
    // Only "content" mode prints matching lines; "files_with_matches" and
    // "count" print file names and numbers. An unset mode is checked too, so
    // a change in Grep's default can never switch the guard off.
    if (toolInput.output_mode === 'files_with_matches' || toolInput.output_mode === 'count') return null;
    if (typeof toolInput.path === 'string' && isSensitivePath(toolInput.path, guard)) {
      return decide(`searching ${toolInput.path} would put secrets into the conversation.`);
    }
    // glob: ".env*" or "**/*.pem" searches the credentials files themselves.
    if (
      typeof toolInput.glob === 'string' &&
      (isSensitivePath(toolInput.glob, guard) || globCouldMatchSensitive(toolInput.glob, guard))
    ) {
      return decide(`searching files matching ${toolInput.glob} would put secrets into the conversation.`);
    }
    return null;
  }

  if (input.tool_name === 'Read' && typeof toolInput.file_path === 'string') {
    const filePath = toolInput.file_path;
    // An explicitly allowed path skips both the path check and the content scan.
    if (matchesAny(filePath, guard.allowedPaths)) return null;
    if (isSensitivePath(filePath, guard)) {
      return decide(`${filePath} usually holds credentials. Reading it would put them into the conversation.`);
    }
    const content = readFile(path.resolve(cwd, filePath), guard.maxScanBytes);
    if (content === null) return null;
    const result = scanner.scan(content);
    if (result.findings.length === 0) return null;
    return decide(
      `${filePath} contains ${result.findings.length} sensitive item(s). Reading it would put them into the conversation:\n${findingsSummary(result)}\n` +
        'Add the path to "toolGuard.allowedPaths" in .privacy-guard.json to stop asking for it.'
    );
  }

  return null;
}

// --- PostToolUse -----------------------------------------------------------

/** Concatenate every string inside a tool response, up to `maxBytes`. */
export function collectText(value: unknown, maxBytes: number): string {
  const parts: string[] = [];
  let size = 0;
  const visit = (v: unknown, depth: number): void => {
    if (size >= maxBytes || depth > 8 || v === null || v === undefined) return;
    if (typeof v === 'string') {
      const piece = v.slice(0, maxBytes - size);
      parts.push(piece);
      size += piece.length + 1;
    } else if (Array.isArray(v)) {
      for (const item of v) visit(item, depth + 1);
    } else if (typeof v === 'object') {
      for (const item of Object.values(v as Record<string, unknown>)) visit(item, depth + 1);
    }
  };
  visit(value, 0);
  return parts.join('\n');
}

export function checkPostToolUse(
  input: HookInput,
  guard: Required<ToolGuardConfig>,
  scanner: PrivacyScanner
): ToolHookOutput | null {
  if (!guard.enabled || guard.postToolUse === 'off') return null;
  // A file the user explicitly allowed is not worth a warning after the fact.
  const filePath = input.tool_input?.file_path ?? input.tool_input?.path;
  if (typeof filePath === 'string' && matchesAny(filePath, guard.allowedPaths)) return null;
  const text = collectText(input.tool_response, guard.maxScanBytes);
  if (!text) return null;
  const result = scanner.scan(text);
  if (result.findings.length === 0) return null;

  const tool = input.tool_name ?? 'tool';
  return {
    systemMessage:
      `🛡️ Privacy Guard: ${tool} output contained ${result.findings.length} sensitive item(s), and it is now in the conversation:\n` +
      `${findingsSummary(result)}\nConsider rotating these credentials.`,
    hookSpecificOutput: {
      hookEventName: 'PostToolUse',
      additionalContext:
        `Privacy Guard detected ${result.findings.length} secret or PII value(s) in the ${tool} output ` +
        `(${[...new Set(result.findings.map((f) => f.title))].join(', ')}). ` +
        'Do not repeat, quote, log, or transmit these values. Refer to them only by name (for example "the API key in .env").',
    },
  };
}
