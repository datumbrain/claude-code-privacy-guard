/**
 * Shared scanner setup for the hook scripts (prompt guard and tool guard), so
 * both apply exactly the same rules, cache, opt-in PII detectors, disabled
 * rules and allowlists.
 *
 * Paths that depend on where the plugin is installed (bundled ruleset,
 * package.json) are passed in by the calling script, which keeps this module
 * free of import.meta and testable under Jest.
 */
import { PrivacyScanner } from '../scanner/engine.js';
import { PrivacyGuardConfig } from '../types/findings.js';
/** Per-user cache dir: %LOCALAPPDATA% on Windows, XDG_CACHE_HOME or ~/.cache elsewhere. */
export declare function getCacheDir(): string;
/** Version from a package.json path, or "unknown" (cache still works, minus upgrade invalidation). */
export declare function readPluginVersion(packageJsonPath: string): string;
export interface ScannerSetup {
    config: PrivacyGuardConfig;
    /** Path of the config file in use, if any (relative paths resolve from its dir). */
    configPath: string | null;
    /** The bundled ruleset, used unless config.externalRulesJsonPath overrides it. */
    defaultRulesPath: string;
    /** Plugin version, for rule-cache invalidation. */
    version: string;
}
export declare function buildScanner({ config, configPath, defaultRulesPath, version }: ScannerSetup): PrivacyScanner;
