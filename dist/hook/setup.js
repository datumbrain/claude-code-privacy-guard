/**
 * Shared scanner setup for the hook scripts (prompt guard and tool guard), so
 * both apply exactly the same rules, cache, opt-in PII detectors, disabled
 * rules and allowlists.
 *
 * Paths that depend on where the plugin is installed (bundled ruleset,
 * package.json) are passed in by the calling script, which keeps this module
 * free of import.meta and testable under Jest.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { PrivacyScanner } from '../scanner/engine.js';
import { BUILTIN_RULES } from '../scanner/detectors.js';
import { loadExternalRulesCached } from '../scanner/rule-cache.js';
import { getPiiRules } from '../scanner/pii.js';
/** Per-user cache dir: %LOCALAPPDATA% on Windows, XDG_CACHE_HOME or ~/.cache elsewhere. */
export function getCacheDir() {
    if (os.platform() === 'win32') {
        const base = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
        return path.join(base, 'claude-code-privacy-guard');
    }
    const base = process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache');
    return path.join(base, 'claude-code-privacy-guard');
}
/** Version from a package.json path, or "unknown" (cache still works, minus upgrade invalidation). */
export function readPluginVersion(packageJsonPath) {
    try {
        return JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8')).version ?? 'unknown';
    }
    catch {
        return 'unknown';
    }
}
export function buildScanner({ config, configPath, defaultRulesPath, version, maxScanLength }) {
    let externalRulesPath = defaultRulesPath;
    if (config.externalRulesJsonPath) {
        const baseDir = configPath ? path.dirname(configPath) : process.cwd();
        externalRulesPath = path.resolve(baseDir, config.externalRulesJsonPath);
    }
    const codingOnly = (config.externalRulesMode ?? 'coding-only') === 'coding-only';
    // The vetted external rule set is cached on disk (keyed on the rules file's
    // content, options and plugin version) so unchanged rules are not re-parsed
    // and re-vetted on every invocation.
    const externalRules = loadExternalRulesCached(externalRulesPath, { codingOnly }, { cacheDir: getCacheDir(), version });
    // disabledRules applies to built-in, external and opt-in PII rules alike.
    const disabledRules = new Set(config.disabledRules);
    return new PrivacyScanner([...BUILTIN_RULES, ...externalRules, ...getPiiRules(config.piiProfile)].filter((rule) => !disabledRules.has(rule.id)), {
        allowedDomains: config.allowedDomains,
        allowedValues: config.allowedValues,
        allowedPatterns: config.allowedPatterns,
        ...(maxScanLength !== undefined ? { maxScanLength } : {}),
    });
}
