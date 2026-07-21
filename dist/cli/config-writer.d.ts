/**
 * Reads and writes the disabledRules array in .privacy-guard.json without
 * disturbing any other keys the user has set.
 */
/**
 * Resolves which config file to edit. An existing project-level config
 * (found by searching upward from cwd) always wins, since it's an explicit
 * per-project override. Otherwise this falls back to the user's home
 * directory rather than creating a new file in whatever project the CLI
 * happened to be run from - Privacy Guard protects the person, not one repo,
 * so a systemwide default is the sane default for a first save.
 */
export declare function resolveConfigPath(startDir?: string): string;
export declare function isGlobalConfigPath(configPath: string): boolean;
export declare function writeDisabledRules(configPath: string, disabledRules: string[]): void;
