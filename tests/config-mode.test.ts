import { describe, expect, test, afterEach } from '@jest/globals';
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
