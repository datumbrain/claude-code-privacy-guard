/**
 * Configuration loading and management
 */

import { PiiProfile, PrivacyGuardConfig, ToolGuardConfig } from '../types/findings.js';
import * as fs from 'fs';
import * as os from 'os';
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

const STRING_LIST_KEYS = ['allowedDomains', 'disabledRules', 'allowedValues', 'allowedPatterns'] as const;

// The scanner iterates these lists. A bare string would be iterated one
// character at a time - "allowedPatterns": "^sk-test-.*$" became the patterns
// "^", "s", "k", ".", ... and "." allowed every finding - and any other type
// crashed the hook, which then let the prompt through unscanned. A single
// string is taken as a one-item list; anything else falls back to [].
function normalizeStringList(key: string, value: unknown, configPath: string): string[] {
  if (typeof value === 'string') {
    console.warn(`Privacy Guard: "${key}" in ${configPath} should be a list of strings - treating it as ["${value}"]`);
    return value ? [value] : [];
  }
  if (!Array.isArray(value)) {
    if (value !== undefined && value !== null) {
      console.warn(`Privacy Guard: "${key}" in ${configPath} should be a list of strings - ignoring it`);
    }
    return [];
  }
  const strings = value.filter((item): item is string => typeof item === 'string' && item.length > 0);
  if (strings.length !== value.length) {
    console.warn(`Privacy Guard: ignoring non-string entries in "${key}" in ${configPath}`);
  }
  return strings;
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
        if (!userConfig || typeof userConfig !== 'object' || Array.isArray(userConfig)) {
          throw new Error('config must be a JSON object');
        }
        const merged = { ...DEFAULT_CONFIG, ...userConfig };
        if (typeof merged.enabled !== 'boolean') {
          console.warn(`Privacy Guard: "enabled" in ${configPath} must be true or false - keeping the guard enabled`);
          merged.enabled = true;
        }
        if (!VALID_MODES.includes(merged.mode)) {
          console.warn(`Privacy Guard: invalid "mode" value "${merged.mode}" in config, falling back to "block"`);
          merged.mode = 'block';
        }
        for (const key of STRING_LIST_KEYS) merged[key] = normalizeStringList(key, merged[key], configPath);
        if (merged.externalRulesMode !== undefined && merged.externalRulesMode !== 'coding-only' && merged.externalRulesMode !== 'all') {
          console.warn(`Privacy Guard: invalid "externalRulesMode" "${merged.externalRulesMode}" in ${configPath}, using "coding-only"`);
          delete merged.externalRulesMode;
        }
        if (merged.externalRulesJsonPath !== undefined && (typeof merged.externalRulesJsonPath !== 'string' || !merged.externalRulesJsonPath)) {
          console.warn(`Privacy Guard: "externalRulesJsonPath" in ${configPath} must be a non-empty string - using the bundled rules`);
          delete merged.externalRulesJsonPath;
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
   * Find the config file: the nearest one walking up from startDir (the
   * filesystem root included), else the global one in the home directory, so
   * ~/.privacy-guard.json also covers projects that live outside $HOME.
   */
  static findConfig(startDir: string = process.cwd(), homeDir: string = os.homedir()): string | null {
    const configNames = [
      '.privacy-guard.json',
      'privacy-guard.json',
      '.privacy-guard.config.json',
    ];
    const inDir = (dir: string): string | null => {
      for (const name of configNames) {
        const configPath = path.join(dir, name);
        if (fs.existsSync(configPath)) return configPath;
      }
      return null;
    };

    let currentDir = path.resolve(startDir);
    for (;;) {
      const found = inDir(currentDir);
      if (found) return found;
      const parent = path.dirname(currentDir);
      if (parent === currentDir) break;
      currentDir = parent;
    }

    return inDir(homeDir);
  }
}
