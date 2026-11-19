/**
 * Configuration loading and management
 */
import { PrivacyGuardConfig } from '../types/findings.js';
export declare class ConfigLoader {
    private config;
    constructor(configPath?: string);
    getConfig(): PrivacyGuardConfig;
    private loadConfig;
    /**
     * Find the config file: the nearest one walking up from startDir (the
     * filesystem root included), else the global one in the home directory, so
     * ~/.privacy-guard.json also covers projects that live outside $HOME.
     */
    static findConfig(startDir?: string, homeDir?: string): string | null;
}
