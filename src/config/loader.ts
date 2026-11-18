/**
 * Configuration loading and management
 */

import { PiiProfile, PrivacyGuardConfig } from '../types/findings.js';
import * as fs from 'fs';
import * as path from 'path';

const VALID_MODES = ['block', 'redact', 'warn'];

// Every key PrivacyGuardConfig recognizes. Used only to warn on typos (e.g.
// "alowedValues") - unknown keys are still merged through untouched so the
// config-UI's "preserve unknown keys on save" behavior keeps working.
const KNOWN_CONFIG_KEYS = new Set([
  'enabled',
  'mode',
  'allowedDomains',
  'disabledRules',
  'externalRulesJsonPath',
  'externalRulesMode',
  'allowedValues',
  'allowedPatterns',
  'piiProfile',
]);

const DEFAULT_CONFIG: PrivacyGuardConfig = {
  enabled: true,
  mode: 'block',
  allowedDomains: [],
  disabledRules: [],
  allowedValues: [],
  allowedPatterns: [],
  piiProfile: {},
};

const PII_PROFILE_KEYS = ['creditCard', 'ssn', 'phone'] as const;

// Only a literal `true` enables a detector; anything malformed is treated as
// off so a typo can never silently widen what the guard scans.
function normalizePiiProfile(value: unknown): PiiProfile {
  const profile: PiiProfile = {};
  if (!value || typeof value !== 'object' || Array.isArray(value)) return profile;
  for (const key of PII_PROFILE_KEYS) {
    if ((value as Record<string, unknown>)[key] === true) profile[key] = true;
  }
  return profile;
}

export class ConfigLoader {
  private config: PrivacyGuardConfig;

  constructor(configPath?: string) {
    this.config = this.loadConfig(configPath);
  }

  getConfig(): PrivacyGuardConfig {
    return { ...this.config };
  }

  private loadConfig(configPath?: string): PrivacyGuardConfig {
    if (!configPath) {
      return { ...DEFAULT_CONFIG };
    }

    try {
      if (fs.existsSync(configPath)) {
        const fileContent = fs.readFileSync(configPath, 'utf-8');
        const userConfig = JSON.parse(fileContent);
        for (const key of Object.keys(userConfig)) {
          if (!KNOWN_CONFIG_KEYS.has(key)) {
            console.warn(`Privacy Guard: unknown config key "${key}" in ${configPath} - check for a typo`);
          }
        }
        const merged = { ...DEFAULT_CONFIG, ...userConfig };
        if (!VALID_MODES.includes(merged.mode)) {
          console.warn(`Privacy Guard: invalid "mode" value "${merged.mode}" in config, falling back to "block"`);
          merged.mode = 'block';
        }
        merged.piiProfile = normalizePiiProfile(merged.piiProfile);
        return merged;
      }
    } catch (error) {
      console.error('Failed to load config, using defaults:', error);
    }

    return { ...DEFAULT_CONFIG };
  }

  /**
   * Find config file in standard locations
   */
  static findConfig(startDir: string = process.cwd()): string | null {
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
