#!/usr/bin/env node
/**
 * Benchmark for the compiled-rules cache (issue #57).
 *
 *   node scripts/bench-rules.mjs [iterations]
 *
 * Compares loading the external rule set from scratch (parse + compile +
 * safe-regex2 vetting) with loading it from the on-disk cache, using a
 * throwaway cache directory. Requires `npm run build` first.
 */

import { fileURLToPath } from 'url';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import * as path from 'path';
import { loadExternalRulesFromJson } from '../dist/scanner/detectors.js';
import { loadExternalRulesCached } from '../dist/scanner/rule-cache.js';

const iterations = Number(process.argv[2]) || 50;
const rulesPath = fileURLToPath(new URL('../data/regex_list_1.json', import.meta.url));
const cacheDir = mkdtempSync(path.join(tmpdir(), 'pg-bench-'));

function time(fn) {
  const times = [];
  for (let i = 0; i < iterations; i++) {
    const start = process.hrtime.bigint();
    fn();
    times.push(Number(process.hrtime.bigint() - start) / 1e6);
  }
  times.sort((a, b) => a - b);
  return { median: times[Math.floor(times.length / 2)], p95: times[Math.floor(times.length * 0.95)] };
}

const origWarn = console.warn;
console.warn = () => {};

const cold = time(() => loadExternalRulesFromJson(rulesPath, { codingOnly: true }));
loadExternalRulesCached(rulesPath, { codingOnly: true }, { cacheDir, version: 'bench' }); // prime
const warm = time(() => loadExternalRulesCached(rulesPath, { codingOnly: true }, { cacheDir, version: 'bench' }));

console.warn = origWarn;
rmSync(cacheDir, { recursive: true, force: true });

const fmt = (n) => `${n.toFixed(2)} ms`;
console.log(`iterations: ${iterations}`);
console.log(`uncached load  median ${fmt(cold.median)}  p95 ${fmt(cold.p95)}`);
console.log(`cached load    median ${fmt(warm.median)}  p95 ${fmt(warm.p95)}`);
console.log(`speedup        ${(cold.median / warm.median).toFixed(1)}x`);
