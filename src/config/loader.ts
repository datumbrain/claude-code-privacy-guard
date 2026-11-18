/**
 * Configuration loading and management
 */

import { PiiProfile, PrivacyGuardConfig, ToolGuardConfig } from '../types/findings.js';
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
  'toolGuard',
]);

const DEFAULT_CONFIG: PrivacyGuardConfig = {
  enabled: true,
  mode: 'block',
  allowedDomains: [],
  disabledRules: [],
  allowedValues: [],
  allowedPatterns: [],
  piiProfile: {},
  toolGuard: {},
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

// Keep only well-typed toolGuard fields; anything malformed falls back to the
// default for that field (see DEFAULT_TOOL_GUARD in hook/tool-guard.ts).
function normalizeToolGuard(value: unknown): ToolGuardConfig {
  const out: ToolGuardConfig = {};
  if (!value || typeof value !== 'object' || Array.isArray(value)) return out;
  const v = value as Record<string, unknown>;
  if (typeof v.enabled === 'boolean') out.enabled = v.enabled;
  if (v.preToolUse === 'ask' || v.preToolUse === 'deny' || v.preToolUse === 'off') out.preToolUse = v.preToolUse;
  if (v.postToolUse === 'warn' || v.postToolUse === 'off') out.postToolUse = v.postToolUse;
  const strings = (x: unknown) => (Array.isArray(x) ? x.filter((s): s is string => typeof s === 'string' && s.length > 0) : undefined);
  const sensitive = strings(v.sensitivePaths);
  if (sensitive) out.sensitivePaths = sensitive;
  const allowed = strings(v.allowedPaths);
  if (allowed) out.allowedPaths = allowed;
  if (typeof v.maxScanBytes === 'number' && Number.isFinite(v.maxScanBytes) && v.maxScanBytes > 0) {
    out.maxScanBytes = Math.floor(v.maxScanBytes);
  }
  for (const key of Object.keys(v)) {
    if (!['enabled', 'preToolUse', 'postToolUse', 'sensitivePaths', 'allowedPaths', 'maxScanBytes'].includes(key)) {
      console.warn(`Privacy Guard: unknown toolGuard key "${key}" - check for a typo`);
    }
  }
  return out;
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
        merged.toolGuard = normalizeToolGuard(merged.toolGuard);
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
