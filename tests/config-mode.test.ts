import { describe, expect, test, afterEach, jest } from '@jest/globals';
import { ConfigLoader } from '../src/config/loader';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const tmpFiles: string[] = [];

function writeConfig(content: unknown): string {
  const file = path.join(os.tmpdir(), `privacy-guard-test-${Date.now()}-${Math.random()}.json`);
  fs.writeFileSync(file, JSON.stringify(content));
  tmpFiles.push(file);
  return file;
}

afterEach(() => {
  while (tmpFiles.length) {
    fs.rmSync(tmpFiles.pop() as string, { force: true });
  }
});

describe('ConfigLoader mode', () => {
  test('defaults to "block" when no config file is given', () => {
    const config = new ConfigLoader().getConfig();
    expect(config.mode).toBe('block');
  });

  test('defaults to "block" when the config file omits mode', () => {
    const file = writeConfig({ enabled: true });
    const config = new ConfigLoader(file).getConfig();
    expect(config.mode).toBe('block');
  });

  test('honors an explicit valid mode', () => {
    const file = writeConfig({ mode: 'redact' });
    const config = new ConfigLoader(file).getConfig();
    expect(config.mode).toBe('redact');
  });

  test('falls back to "block" for an invalid mode value', () => {
    const file = writeConfig({ mode: 'delete-everything' });
    const config = new ConfigLoader(file).getConfig();
    expect(config.mode).toBe('block');
  });
});

describe('ConfigLoader unknown keys', () => {
  test('warns on an unrecognized key (e.g. a typo)', () => {
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const file = writeConfig({ alowedValues: ['oops'] });
      new ConfigLoader(file).getConfig();
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('unknown config key "alowedValues"'));
    } finally {
      warnSpy.mockRestore();
    }
  });

  test('does not warn when every key is recognized', () => {
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const file = writeConfig({
        enabled: true,
        mode: 'warn',
        allowedDomains: ['example.com'],
        disabledRules: ['some-rule'],
        allowedValues: ['ok'],
        allowedPatterns: ['^ok$'],
        externalRulesJsonPath: './rules.json',
        externalRulesMode: 'all',
      });
      new ConfigLoader(file).getConfig();
      expect(warnSpy).not.toHaveBeenCalled();
    } finally {
      warnSpy.mockRestore();
    }
  });
});
