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
import { DetectionRule } from '../types/findings.js';
import { ExternalRuleOptions } from './detectors.js';
export interface RuleCacheOptions {
    /** Directory the cache file lives in. */
    cacheDir: string;
    /** Plugin version; a different version invalidates the cache. */
    version: string;
}
export declare function computeCacheKey(jsonPath: string, content: Buffer, options: ExternalRuleOptions, version: string): string;
/**
 * Same result as loadExternalRulesFromJson, served from the on-disk cache when
 * the rules file, options and plugin version are unchanged.
 */
export declare function loadExternalRulesCached(jsonPath: string, options: ExternalRuleOptions, cacheOptions: RuleCacheOptions): DetectionRule[];
