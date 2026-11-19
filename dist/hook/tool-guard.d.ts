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
import { PrivacyScanner } from '../scanner/engine.js';
import { ToolGuardConfig } from '../types/findings.js';
export declare const DEFAULT_TOOL_GUARD: Required<ToolGuardConfig>;
/**
 * Paths that hold credentials by convention. A glob without "/" matches the
 * file's basename; one with "/" matches the end of the full path.
 */
export declare const DEFAULT_SENSITIVE_PATHS: string[];
/** Never treated as sensitive, even if a sensitive glob matches. */
export declare const DEFAULT_ALLOWED_PATHS: string[];
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
export declare const NON_INTERACTIVE_PERMISSION_MODES: Set<string>;
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
export declare function resolveToolGuardConfig(config: ToolGuardConfig | undefined): Required<ToolGuardConfig>;
export declare function isSensitivePath(filePath: string, guard: Required<ToolGuardConfig>): boolean;
/**
 * Whether a shell or Grep glob such as ".env*", "id_*" or "*.pem" could
 * expand to a sensitive file name. The file name part of the glob is tested
 * against sample names built from the sensitive file-name globs. A glob that
 * starts with "*" is only tested against the extension-style samples
 * ("*.pem" -> "x.pem"), so broad globs like "*.json" or "*" are not flagged
 * just because "credentials.json" would match them.
 */
export declare function globCouldMatchSensitive(glob: string, guard: Required<ToolGuardConfig>): boolean;
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
export declare function parseShellSegments(command: string, depth?: number): ShellSegment[];
/**
 * Drop heredoc bodies (`<<EOF ... EOF`, `<<'EOF'`, `<<-EOF`), keeping the rest
 * of the opening line. A heredoc body is data fed to a program - often a
 * script or test text that merely mentions `.env` - not a file being read.
 */
export declare function stripHeredocs(command: string): string;
/** Why a Bash command looks like it would expose secrets, or null. */
export declare function bashExposureReason(rawCommand: string, guard: Required<ToolGuardConfig>): string | null;
export declare function checkPreToolUse(input: HookInput, guard: Required<ToolGuardConfig>, scanner: PrivacyScanner, readFile: FileReader): ToolHookOutput | null;
/** Concatenate every string inside a tool response, up to `maxBytes`. */
export declare function collectText(value: unknown, maxBytes: number): string;
export declare function checkPostToolUse(input: HookInput, guard: Required<ToolGuardConfig>, scanner: PrivacyScanner): ToolHookOutput | null;
