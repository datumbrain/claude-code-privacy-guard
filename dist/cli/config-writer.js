/**
 * Reads and writes the disabledRules array in .privacy-guard.json without
 * disturbing any other keys the user has set.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { ConfigLoader } from '../config/loader.js';
/**
 * Resolves which config file to edit. An existing project-level config
 * (found by searching upward from cwd) always wins, since it's an explicit
 * per-project override. Otherwise this falls back to the user's home
 * directory rather than creating a new file in whatever project the CLI
 * happened to be run from - Privacy Guard protects the person, not one repo,
 * so a systemwide default is the sane default for a first save.
 */
export function resolveConfigPath(startDir = process.cwd()) {
    return ConfigLoader.findConfig(startDir) || path.join(os.homedir(), '.privacy-guard.json');
}
export function isGlobalConfigPath(configPath) {
    return path.dirname(configPath) === os.homedir();
}
export function writeDisabledRules(configPath, disabledRules) {
    let existing = {};
    if (fs.existsSync(configPath)) {
        try {
            existing = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
        }
        catch {
            // Malformed existing config - fail loudly rather than silently clobbering it.
            throw new Error(`Could not parse existing config at ${configPath}; fix or remove it before saving.`);
        }
    }
    const updated = { ...existing, disabledRules: [...disabledRules].sort() };
    fs.writeFileSync(configPath, JSON.stringify(updated, null, 2) + '\n', 'utf-8');
}
