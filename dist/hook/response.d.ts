/**
 * Builds the UserPromptSubmit hook JSON payload for a scan result, branching
 * on `mode`. The hook protocol has no field that rewrites/replaces the
 * submitted prompt (see README "Block, Redact, or Warn?") - so `redact` mode
 * still blocks, but hands back a copy-pasteable cleaned prompt instead of
 * making the user manually retype it.
 */
import { PromptGuardMode, ScanResult } from '../types/findings.js';
export interface HookResponse {
    decision?: 'block';
    reason?: string;
    systemMessage?: string;
}
/**
 * Mask a matched secret/PII value down to a short, non-recoverable hint,
 * e.g. "sk-proj-abc123xyz1234567890" -> "sk-p…7890"
 */
export declare function maskMatch(value: string): string;
/**
 * Returns the JSON payload to print for a scan with findings, or null when
 * there is nothing to report (caller should allow the prompt silently).
 */
export declare function buildHookResponse(result: ScanResult, mode: PromptGuardMode): HookResponse | null;
