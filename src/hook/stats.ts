/**
 * Local detection stats for the prompt hook.
 *
 * Keeps a small JSON file (stats.json in the cache dir) with counts of what the
 * guard has caught, per session and cumulatively. It stores only counts keyed by
 * category and rule id, never matched values, prompt text or paths.
 *
 * Everything here is best-effort: a stats failure must never affect prompting.
 */

import * as fs from 'fs';
import * as path from 'path';
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
export const SESSION_RETENTION_DAYS = 30;

const STATS_FILE = 'stats.json';

function emptyBucket(): StatsBucket {
  return { totalPrompts: 0, totalFindings: 0, byCategory: {}, byRule: {} };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function readStats(filePath: string): StatsFile {
  try {
    const parsed: unknown = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    if (isRecord(parsed) && isRecord(parsed.global) && isRecord(parsed.sessions)) {
      return parsed as unknown as StatsFile;
    }
  } catch {
    // Missing or corrupt file: start over.
  }
  return { global: emptyBucket(), sessions: {} };
}

function bump(bucket: StatsBucket, result: ScanResult): void {
  bucket.totalPrompts += 1;
  bucket.totalFindings += result.findings.length;
  for (const finding of result.findings) {
    bucket.byCategory[finding.category] = (bucket.byCategory[finding.category] ?? 0) + 1;
    bucket.byRule[finding.ruleId] = (bucket.byRule[finding.ruleId] ?? 0) + 1;
  }
}

/**
 * Record one scanned prompt. Updates the global totals and, when a session id is
 * known, that session's entry. Returns the updated stats, or null if the file
 * could not be written.
 */
export function recordPrompt(
  cacheDir: string,
  sessionId: string | undefined,
  result: ScanResult,
  now: Date = new Date()
): StatsFile | null {
  try {
    const filePath = path.join(cacheDir, STATS_FILE);
    const stats = readStats(filePath);
    const stamp = now.toISOString();

    bump(stats.global, result);

    if (sessionId) {
      const session = stats.sessions[sessionId] ?? { ...emptyBucket(), startedAt: stamp, lastUpdatedAt: stamp };
      bump(session, result);
      session.lastUpdatedAt = stamp;
      stats.sessions[sessionId] = session;
    }

    const cutoff = now.getTime() - SESSION_RETENTION_DAYS * 24 * 60 * 60 * 1000;
    for (const [id, session] of Object.entries(stats.sessions)) {
      const last = Date.parse(session.lastUpdatedAt);
      if (Number.isNaN(last) || last < cutoff) delete stats.sessions[id];
    }

    // Write to a temp file then rename, so a concurrent reader never sees a
    // half-written file.
    fs.mkdirSync(cacheDir, { recursive: true });
    const tmpPath = `${filePath}.${process.pid}.tmp`;
    fs.writeFileSync(tmpPath, JSON.stringify(stats, null, 2));
    fs.renameSync(tmpPath, filePath);
    return stats;
  } catch {
    return null;
  }
}
