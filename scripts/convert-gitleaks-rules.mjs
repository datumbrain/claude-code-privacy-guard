#!/usr/bin/env node
/**
 * Convert gitleaks' default ruleset (MIT licensed) into this project's
 * external-rule JSON format.
 *
 *   curl -fsSL -o /tmp/gitleaks.toml \
 *     https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/config/gitleaks.toml
 *   npm run build
 *   node scripts/convert-gitleaks-rules.mjs /tmp/gitleaks.toml data/gitleaks-rules.json
 *
 * Every converted rule must:
 *   - translate from Go RE2 syntax to a JavaScript regex that compiles,
 *   - pass safe-regex2 and not match the empty string (same checks the loader
 *     applies at runtime), and
 *   - pass the catastrophic-backtracking probe in src/scanner/regex-audit.ts.
 *
 * gitleaks' per-rule `keywords` and `entropy` are carried over: the scanner
 * only runs a rule when one of its keywords is present, and drops matches
 * whose secret is below the entropy threshold. Per-rule and global allowlists
 * (stopwords, path filters) are not ported.
 * Rules that fail any step are dropped and listed in the report, so the
 * shipped file loads with zero rejections.
 *
 * Rule IDs follow the existing stable scheme: the loader derives
 * `external-<slug(name)>`, and `name` is the gitleaks rule id, so e.g.
 * gitleaks' `stripe-access-token` becomes `external-stripe-access-token`.
 */

import { readFileSync, writeFileSync } from 'fs';
import safeRegex from 'safe-regex2';
import { probeRegex } from '../dist/scanner/regex-audit.js';

// Rules we deliberately leave out, with the reason recorded in the report.
const SKIP = {
  // Relies on large per-rule stopword allowlists we don't port; the built-in
  // generic-code-secret-assignment, env-unquoted-secret-assignment and
  // high-entropy-secret rules cover this ground with our own FP corpus.
  'generic-api-key': 'covered by built-in generic/entropy rules; needs gitleaks stopword allowlists',
};

// Rules that are private-key material get the top risk score.
const CRITICAL = /private-key|privatekey/;

// Probe budget: a linear regex takes well under 5 ms on 20k chars.
const PROBE_LENGTH = 20_000;
const PROBE_MAX_MS = 50;

// ---------------------------------------------------------------------------
// Minimal TOML reader for the subset gitleaks.toml uses: comments, [table],
// [[array-of-tables]] (incl. dotted names), key = value with '''literal''',
// 'literal', "basic", numbers, booleans and (multi-line) arrays of those.
// Only top-level [[rules]] entries and their direct keys are returned.
// ---------------------------------------------------------------------------
function parseGitleaksToml(text) {
  const rules = [];
  let current = null; // the [[rules]] table being filled, or null
  let i = 0;

  const skipWsAndComments = () => {
    while (i < text.length) {
      const ch = text[i];
      if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') i++;
      else if (ch === '#') while (i < text.length && text[i] !== '\n') i++;
      else break;
    }
  };

  const parseValue = () => {
    if (text.startsWith("'''", i)) {
      const end = text.indexOf("'''", i + 3);
      let v = text.slice(i + 3, end);
      if (v.startsWith('\n')) v = v.slice(1);
      i = end + 3;
      return v;
    }
    if (text[i] === "'") {
      const end = text.indexOf("'", i + 1);
      const v = text.slice(i + 1, end);
      i = end + 1;
      return v;
    }
    if (text[i] === '"') {
      let v = '';
      i++;
      while (text[i] !== '"') {
        if (text[i] === '\\') {
          const n = text[i + 1];
          const map = { n: '\n', t: '\t', '"': '"', '\\': '\\', r: '\r' };
          if (n === 'u') {
            v += String.fromCharCode(parseInt(text.slice(i + 2, i + 6), 16));
            i += 6;
            continue;
          }
          v += map[n] ?? n;
          i += 2;
        } else {
          v += text[i++];
        }
      }
      i++;
      return v;
    }
    if (text[i] === '[') {
      i++;
      const arr = [];
      for (;;) {
        skipWsAndComments();
        if (text[i] === ']') {
          i++;
          return arr;
        }
        arr.push(parseValue());
        skipWsAndComments();
        if (text[i] === ',') i++;
      }
    }
    const m = /^[^\s,\]#]+/.exec(text.slice(i, i + 64));
    i += m[0].length;
    if (m[0] === 'true') return true;
    if (m[0] === 'false') return false;
    return Number(m[0]);
  };

  for (;;) {
    skipWsAndComments();
    if (i >= text.length) break;
    if (text[i] === '[') {
      const lineEnd = text.indexOf('\n', i);
      const header = text.slice(i, lineEnd === -1 ? text.length : lineEnd).trim();
      i = lineEnd === -1 ? text.length : lineEnd;
      if (header === '[[rules]]') {
        current = {};
        rules.push(current);
      } else {
        current = null; // [allowlist], [[rules.allowlists]], ... - not ported
      }
      continue;
    }
    const keyMatch = /^([A-Za-z0-9_.-]+)\s*=\s*/.exec(text.slice(i, i + 128));
    if (!keyMatch) throw new Error(`TOML parse error near: ${text.slice(i, i + 60)}`);
    i += keyMatch[0].length;
    const value = parseValue();
    if (current) current[keyMatch[1]] = value;
  }
  return rules;
}

// ---------------------------------------------------------------------------
// Go RE2 -> JavaScript translation.
// ---------------------------------------------------------------------------
const POSIX = {
  alnum: 'A-Za-z0-9',
  alpha: 'A-Za-z',
  digit: '0-9',
  xdigit: '0-9A-Fa-f',
  upper: 'A-Z',
  lower: 'a-z',
  space: '\\s',
  word: '\\w',
};

function translate(goRegex) {
  let src = goRegex;
  const flags = new Set();

  // JavaScript (as of Node 18/20) has no inline flag groups. Hoist any
  // case-insensitive marker to the whole-pattern "i" flag. This can only
  // widen a match (never narrow it), and the FP corpus guards the result.
  if (/\(\?i\)|\(\?i:|\(\?-i[):]/.test(src)) flags.add('i');
  src = src.replace(/\(\?i\)/g, '').replace(/\(\?-?i:/g, '(?:').replace(/\(\?-i\)/g, '');
  if (/\(\?s\)|\(\?s:/.test(src)) flags.add('s');
  src = src.replace(/\(\?s\)/g, '').replace(/\(\?s:/g, '(?:');

  src = src.replace(/\(\?P</g, '(?<');
  src = src.replace(/\\z/g, '$').replace(/\\A/g, '^');
  src = src.replace(/\[:(\^?)([a-z]+):\]/g, (whole, neg, name) => {
    if (neg || !POSIX[name]) throw new Error(`unsupported POSIX class ${whole}`);
    return POSIX[name];
  });
  if (/\(\?[a-zA-Z-]/.test(src.replace(/\(\?<[=!]|\(\?<[A-Za-z]/g, ''))) {
    throw new Error('unsupported inline flag group');
  }
  return { regex: src, flags: [...flags].sort().join('') };
}

// ---------------------------------------------------------------------------

function main() {
  const [tomlPath, outPath] = process.argv.slice(2);
  if (!tomlPath || !outPath) {
    console.error('usage: node scripts/convert-gitleaks-rules.mjs <gitleaks.toml> <out.json>');
    process.exit(1);
  }

  const text = readFileSync(tomlPath, 'utf-8');
  const rules = parseGitleaksToml(text);
  const headerCount = (text.match(/^\[\[rules\]\]\s*$/gm) ?? []).length;
  if (rules.length !== headerCount) {
    throw new Error(`parsed ${rules.length} rules but found ${headerCount} [[rules]] headers`);
  }

  const out = [];
  const skipped = [];

  for (const rule of rules) {
    const id = rule.id;
    const skip = (reason) => skipped.push({ id, reason });

    if (SKIP[id]) { skip(SKIP[id]); continue; }
    if (typeof rule.regex !== 'string') { skip('no content regex (file-name rule)'); continue; }
    if (typeof rule.path === 'string') { skip('path-scoped rule (only meaningful for files)'); continue; }

    let translated;
    try {
      translated = translate(rule.regex);
    } catch (error) {
      skip(`translation: ${error.message}`);
      continue;
    }

    let compiled;
    try {
      compiled = new RegExp(translated.regex, translated.flags);
    } catch (error) {
      skip(`does not compile in JS: ${error.message}`);
      continue;
    }
    if (compiled.test('')) { skip('matches the empty string'); continue; }
    if (!safeRegex(translated.regex)) { skip('rejected by safe-regex2'); continue; }

    const probe = probeRegex(new RegExp(translated.regex, translated.flags + 'm'), PROBE_LENGTH);
    if (probe.worstMs > PROBE_MAX_MS) {
      skip(`slow on adversarial input (${probe.worstMs.toFixed(0)} ms on ${JSON.stringify(probe.shape)})`);
      continue;
    }

    out.push({
      name: id,
      description: rule.description,
      regex: translated.regex,
      ...(translated.flags ? { flags: translated.flags } : {}),
      ...(typeof rule.entropy === 'number' ? { entropy: rule.entropy } : {}),
      ...(typeof rule.secretGroup === 'number' ? { secretGroup: rule.secretGroup } : {}),
      ...(Array.isArray(rule.keywords) && rule.keywords.length > 0
        ? { keywords: rule.keywords.map((k) => String(k).toLowerCase()) }
        : {}),
      // gitleaks patterns carry context and a terminator around the secret;
      // report just the secret so redaction keeps the surrounding text.
      ...(/\((?!\?)/.test(translated.regex) || /\(\?<[A-Za-z]/.test(translated.regex) ? { secretOnly: true } : {}),
      risk: CRITICAL.test(id) ? 9 : 7,
      category: 'Credentials',
      coding: true,
    });
  }

  out.sort((a, b) => a.name.localeCompare(b.name));
  writeFileSync(outPath, JSON.stringify(out, null, 2) + '\n');

  console.log(`gitleaks rules: ${rules.length}`);
  console.log(`converted:      ${out.length}`);
  console.log(`skipped:        ${skipped.length}`);
  for (const s of skipped) console.log(`  - ${s.id}: ${s.reason}`);
}

main();
