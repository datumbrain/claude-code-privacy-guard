/**
 * Local detection stats for the prompt hook.
 *
 * Keeps a small JSON file (stats.json in the cache dir) with counts of what the
 * guard has caught, per session and cumulatively. It stores only counts keyed by
 * category and rule id, never matched values, prompt text or paths.
 *
 * Everything here is best-effort: a stats failure must never affect prompting.
 */
import { ScanResult } from '../types/findings.js';
export interface StatsBucket {
    totalPrompts: number;
    totalFindings: number;
    byCategory: Record<string, number>;
    byRule: Record<string, number>;
}
export interface SessionStats extends StatsBucket {
    startedAt: string;
    lastUpdatedAt: string;
}
export interface StatsFile {
    global: StatsBucket;
    sessions: Record<string, SessionStats>;
}
/** Sessions untouched for this long are dropped so the file cannot grow forever. */
export declare const SESSION_RETENTION_DAYS = 30;
/**
 * Record one scanned prompt. Updates the global totals and, when a session id is
 * known, that session's entry. Returns the updated stats, or null if the file
 * could not be written.
 */
export declare function recordPrompt(cacheDir: string, sessionId: string | undefined, result: ScanResult, now?: Date): StatsFile | null;
