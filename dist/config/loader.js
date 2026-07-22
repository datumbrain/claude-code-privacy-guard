/**
 * Configuration loading and management
 */
import * as fs from 'fs';
import * as path from 'path';
const VALID_MODES = ['block', 'redact', 'warn'];
const DEFAULT_CONFIG = {
    enabled: true,
    mode: 'block',
    allowedDomains: [],
    disabledRules: [],
    allowedValues: [],
    allowedPatterns: [],
};
export class ConfigLoader {
    config;
    constructor(configPath) {
        this.config = this.loadConfig(configPath);
    }
    getConfig() {
        return { ...this.config };
    }
    loadConfig(configPath) {
        if (!configPath) {
            return { ...DEFAULT_CONFIG };
        }
        try {
            if (fs.existsSync(configPath)) {
                const fileContent = fs.readFileSync(configPath, 'utf-8');
                const userConfig = JSON.parse(fileContent);
                const merged = { ...DEFAULT_CONFIG, ...userConfig };
                if (!VALID_MODES.includes(merged.mode)) {
                    console.warn(`Privacy Guard: invalid "mode" value "${merged.mode}" in config, falling back to "block"`);
                    merged.mode = 'block';
                }
                return merged;
            }
        }
        catch (error) {
            console.error('Failed to load config, using defaults:', error);
        }
        return { ...DEFAULT_CONFIG };
    }
    /**
     * Find config file in standard locations
     */
    static findConfig(startDir = process.cwd()) {
        const configNames = [
            '.privacy-guard.json',
            'privacy-guard.json',
            '.privacy-guard.config.json',
        ];
        let currentDir = startDir;
        while (currentDir !== path.dirname(currentDir)) {
            for (const name of configNames) {
                const configPath = path.join(currentDir, name);
                if (fs.existsSync(configPath)) {
                    return configPath;
                }
            }
            currentDir = path.dirname(currentDir);
        }
        return null;
    }
}
