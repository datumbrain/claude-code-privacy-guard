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
import { DetectionRule } from '../types/findings.js';
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
/**
 * Same result as {@link loadExternalRulesFromJson}, served from the on-disk
 * cache when the data file, filter and plugin version are unchanged.
 */
export declare function loadExternalRulesCached(jsonPath: string, options: {
    codingOnly?: boolean;
}, cache: RuleCacheOptions): ExternalRulesLoadResult;
