/**
 * Persistent cache for the vetted external rule set.
 *
 * Loading the external ruleset parses the JSON, compiles every regex and runs
 * safe-regex2 over each one. That work is identical on every hook invocation
 * until the rules file, the plugin version or the loader options change, so we
 * keep the result on disk and skip it when the key still matches.
 *
 * Only the external rules are cached: built-in rules are compiled in-process
 * and are effectively free. Config that is applied after loading
 * (disabledRules, allowlists, piiProfile) is deliberately not part of the key -
 * it is filtered in on every run, so changing it can never serve stale rules.
 *
 * The cache is strictly best-effort: any read, parse or write failure falls
 * back to a normal load, so it can never break or block the hook.
 */
import * as fs from 'fs';
import * as path from 'path';
import { createHash } from 'crypto';
import { loadExternalRulesFromJson } from './detectors.js';
// Bump when the cached rule shape or the vetting logic changes in a way the
// plugin version alone would not capture (e.g. during development).
const CACHE_SCHEMA = 1;
const CACHE_FILE = 'external-rules-cache.json';
// Several projects can point at different rule files; keep a few entries so
// they don't evict each other on every run, but never grow without bound.
const MAX_ENTRIES = 8;
export function computeCacheKey(jsonPath, content, options, version) {
    const contentHash = createHash('sha256').update(content).digest('hex');
    return createHash('sha256')
        .update(JSON.stringify([CACHE_SCHEMA, version, path.resolve(jsonPath), options.codingOnly ?? true, contentHash]))
        .digest('hex');
}
function readCache(file) {
    try {
        const parsed = JSON.parse(fs.readFileSync(file, 'utf-8'));
        if (parsed && parsed.schema === CACHE_SCHEMA && parsed.entries && typeof parsed.entries === 'object') {
            return parsed;
        }
    }
    catch {
        // Missing or corrupt cache - treat as empty.
    }
    return null;
}
function writeCache(file, cache) {
    try {
        fs.mkdirSync(path.dirname(file), { recursive: true });
        // Write-then-rename so a concurrent hook invocation never reads a
        // half-written file.
        const tmp = `${file}.${process.pid}.tmp`;
        fs.writeFileSync(tmp, JSON.stringify(cache));
        fs.renameSync(tmp, file);
    }
    catch {
        // Best-effort only.
    }
}
/**
 * Same result as loadExternalRulesFromJson, served from the on-disk cache when
 * the rules file, options and plugin version are unchanged.
 */
export function loadExternalRulesCached(jsonPath, options, cacheOptions) {
    let content;
    try {
        content = fs.readFileSync(jsonPath);
    }
    catch {
        return loadExternalRulesFromJson(jsonPath, options);
    }
    const key = computeCacheKey(jsonPath, content, options, cacheOptions.version);
    const cacheFile = path.join(cacheOptions.cacheDir, CACHE_FILE);
    const cache = readCache(cacheFile);
    const hit = cache?.entries[key];
    if (Array.isArray(hit))
        return hit;
    const rules = loadExternalRulesFromJson(jsonPath, options);
    const entries = { ...(cache?.entries ?? {}) };
    delete entries[key];
    entries[key] = rules;
    // Object key order is insertion order: drop the oldest beyond the cap.
    for (const oldest of Object.keys(entries).slice(0, Math.max(0, Object.keys(entries).length - MAX_ENTRIES))) {
        delete entries[oldest];
    }
    writeCache(cacheFile, { schema: CACHE_SCHEMA, entries });
    return rules;
}
