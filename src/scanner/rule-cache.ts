/**
 * On-disk cache for the vetted external rule set.
 *
 * Loading data/regex_list_1.json means parsing it, compiling every regex and
 * running each through safe-regex2 - identical work on every prompt, because the
 * hook is a fresh process each time. The result only depends on the data file's
 * bytes, the coding-only filter and the code that does the vetting, so it is
 * cached keyed on exactly those.
 *
 * Only the vetted external rules are cached. disabledRules and the allowlists
 * are applied after loading, so editing them takes effect immediately and never
 * needs to invalidate anything here.
 *
 * Every failure (missing, unreadable, corrupt or stale cache; unwritable
 * directory) falls back to a normal load. The cache can make the hook faster,
 * never different or broken.
 */

import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { DetectionRule } from '../types/findings.js';
import { loadExternalRulesFromJson } from './detectors.js';

// Bump when the vetting logic in loadExternalRulesFromJson changes without a
// package version bump, so stale caches from older code are never trusted.
const CACHE_SCHEMA = 1;

const CACHE_FILE = 'rules-cache.json';

export interface RuleCacheOptions {
  /** Directory the cache file lives in. Created on first write. */
  dir: string;
  /** Plugin version; a different version never reuses another version's cache. */
  version: string;
}

export interface ExternalRulesLoadResult {
  rules: DetectionRule[];
  cacheHit: boolean;
}

interface CacheFile {
  key: string;
  rules: DetectionRule[];
}

function computeKey(raw: Buffer, codingOnly: boolean, version: string): string {
  return createHash('sha256')
    .update(`${CACHE_SCHEMA}\0${version}\0${codingOnly ? 'coding-only' : 'all'}\0`)
    .update(raw)
    .digest('hex');
}

// A cache file is only trusted if every rule has the exact shape the vetting
// step produces, so a truncated or hand-edited file is rejected rather than fed
// to the scanner.
function isValidRule(value: unknown): value is DetectionRule {
  if (!value || typeof value !== 'object') return false;
  const rule = value as Record<string, unknown>;
  return (
    typeof rule.id === 'string' &&
    typeof rule.title === 'string' &&
    typeof rule.description === 'string' &&
    typeof rule.severity === 'string' &&
    typeof rule.category === 'string' &&
    typeof rule.pattern === 'string' &&
    Array.isArray(rule.examples) &&
    typeof rule.redactionStrategy === 'string' &&
    rule.enabled === true
  );
}

function readCache(file: string, key: string): DetectionRule[] | null {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf-8')) as Partial<CacheFile>;
    if (parsed.key !== key || !Array.isArray(parsed.rules)) return null;
    return parsed.rules.every(isValidRule) ? parsed.rules : null;
  } catch {
    return null;
  }
}

// Write to a temp file and rename so a concurrent hook (several sessions can
// fire at once) never reads a half-written cache.
function writeCache(file: string, key: string, rules: DetectionRule[]): void {
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ key, rules } satisfies CacheFile));
    fs.renameSync(tmp, file);
  } catch {
    // Best-effort only; the next invocation simply loads normally again.
  }
}

/**
 * Same result as {@link loadExternalRulesFromJson}, served from the on-disk
 * cache when the data file, filter and plugin version are unchanged.
 */
export function loadExternalRulesCached(
  jsonPath: string,
  options: { codingOnly?: boolean },
  cache: RuleCacheOptions
): ExternalRulesLoadResult {
  let raw: Buffer;
  try {
    raw = fs.readFileSync(jsonPath);
  } catch {
    // Missing or unreadable data file: let the regular loader decide what that means.
    return { rules: loadExternalRulesFromJson(jsonPath, options), cacheHit: false };
  }

  const key = computeKey(raw, options.codingOnly ?? true, cache.version);
  const file = path.join(cache.dir, CACHE_FILE);

  const cached = readCache(file, key);
  if (cached) return { rules: cached, cacheHit: true };

  const rules = loadExternalRulesFromJson(jsonPath, options);
  writeCache(file, key, rules);
  return { rules, cacheHit: false };
}
