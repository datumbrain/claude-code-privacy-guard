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
     * Find config file in standard locations
     */
    static findConfig(startDir?: string): string | null;
}
