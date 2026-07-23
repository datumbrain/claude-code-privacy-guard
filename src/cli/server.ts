/**
 * Local-only HTTP server for the rules-picker UI. Binds to loopback only,
 * requires a random per-run token on the save endpoint (defense in depth -
 * the JSON content-type already blocks simple cross-origin POSTs), and
 * shuts itself down after a period of inactivity (saving keeps it alive so
 * you can toggle and save again without restarting).
 */

import * as http from 'http';
import * as fs from 'fs';
import { randomBytes } from 'crypto';
import { fileURLToPath } from 'url';

import { BUILTIN_RULES, loadExternalRulesFromJson } from '../scanner/detectors.js';
import { ConfigLoader } from '../config/loader.js';
import { renderPage, RuleRow } from './page.js';
import { resolveConfigPath, isGlobalConfigPath, writeDisabledRules, writeAllowlists } from './config-writer.js';
import { parseAllowlists, validateAllowedPattern, AllowlistPayload } from './validate.js';

const INACTIVITY_TIMEOUT_MS = 10 * 60 * 1000;

export async function startRulesServer(): Promise<void> {
  const configPath = resolveConfigPath();
  const configLoader = new ConfigLoader(configPath);
  const config = configLoader.getConfig();

  const defaultExternalRulesPath = fileURLToPath(new URL('../../data/regex_list_1.json', import.meta.url));
  const externalRulesPath = config.externalRulesJsonPath || defaultExternalRulesPath;
  const externalRules = loadExternalRulesFromJson(externalRulesPath, {
    codingOnly: config.externalRulesMode !== 'all',
  });

  const disabledRules = new Set(config.disabledRules);
  const allRules = [...BUILTIN_RULES, ...externalRules];
  const rules: RuleRow[] = allRules.map((rule) => ({
    id: rule.id,
    title: rule.title,
    severity: rule.severity,
    category: rule.category,
    source: rule.id.startsWith('external-') ? 'external' : 'builtin',
    disabled: disabledRules.has(rule.id),
  }));

  const allowlists: AllowlistPayload = {
    allowedDomains: [...config.allowedDomains],
    allowedValues: [...config.allowedValues],
    allowedPatterns: [...config.allowedPatterns],
  };

  const logoPath = fileURLToPath(new URL('../../assets/claude-code-privacy-guard-logo.png', import.meta.url));

  const token = randomBytes(16).toString('hex');

  const server = http.createServer((req, res) => {
    resetInactivityTimer();

    if (req.method === 'GET' && req.url === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(renderPage(rules, allowlists, token, configPath, isGlobalConfigPath(configPath)));
      return;
    }

    if (req.method === 'GET' && req.url === '/logo.png') {
      fs.readFile(logoPath, (err, data) => {
        if (err) {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('Not found');
          return;
        }
        res.writeHead(200, { 'Content-Type': 'image/png', 'Cache-Control': 'no-cache' });
        res.end(data);
      });
      return;
    }

    if (req.method === 'POST' && (req.url === '/save' || req.url === '/save-allowlists')) {
      const isAllowlistSave = req.url === '/save-allowlists';
      readJsonBody(req, res, (parsed) => {
        if (parsed.token !== token) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'Invalid token' }));
          return;
        }

        if (isAllowlistSave) {
          const next = parseAllowlists(parsed);
          writeAllowlists(configPath, next);
          allowlists.allowedDomains = next.allowedDomains;
          allowlists.allowedValues = next.allowedValues;
          allowlists.allowedPatterns = next.allowedPatterns;

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, allowlists: next }));
          return;
        }

        if (!Array.isArray(parsed.disabledRules) || !parsed.disabledRules.every((id) => typeof id === 'string')) {
          throw new Error('disabledRules must be a string array');
        }

        writeDisabledRules(configPath, parsed.disabledRules as string[]);
        disabledRules.clear();
        for (const id of parsed.disabledRules as string[]) disabledRules.add(id);
        for (const rule of rules) rule.disabled = disabledRules.has(rule.id);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      });
      return;
    }

    // Live feedback for the regex field so a bad pattern is caught while
    // typing, using the exact check the scanner applies at load time.
    if (req.method === 'POST' && req.url === '/validate-pattern') {
      readJsonBody(req, res, (parsed) => {
        if (parsed.token !== token) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'Invalid token' }));
          return;
        }
        if (typeof parsed.pattern !== 'string') {
          throw new Error('pattern must be a string');
        }
        const error = validateAllowedPattern(parsed.pattern);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, valid: error === null, error }));
      });
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
  });

  let inactivityTimer: NodeJS.Timeout;
  function resetInactivityTimer() {
    clearTimeout(inactivityTimer);
    inactivityTimer = setTimeout(() => server.close(), INACTIVITY_TIMEOUT_MS);
  }

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  resetInactivityTimer();

  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  const url = `http://127.0.0.1:${port}/`;

  console.log(`Privacy Guard rules editor running at ${url}`);
  console.log(`Config file: ${configPath}${isGlobalConfigPath(configPath) ? ' (global - applies to every project unless it has its own .privacy-guard.json)' : ' (project-level override)'}`);
  console.log(`Loaded ${rules.length} rules (${disabledRules.size} currently disabled).`);
  console.log(
    `Allowlists: ${allowlists.allowedDomains.length} domains, ${allowlists.allowedValues.length} values, ${allowlists.allowedPatterns.length} patterns.`
  );
  console.log('Press Ctrl+C to stop (the server also exits after 10 minutes of inactivity).');

  await openInBrowser(url);

  await new Promise<void>((resolve) => server.on('close', resolve));
}

/**
 * Collects a JSON request body (capped) and hands the parsed object to the
 * handler, turning any thrown validation error into a 400 so each route can
 * just throw with a message.
 */
function readJsonBody(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  handler: (parsed: Record<string, unknown>) => void
): void {
  let body = '';
  req.on('data', (chunk) => {
    body += chunk;
    if (body.length > 1_000_000) req.destroy();
  });
  req.on('end', () => {
    try {
      if (req.headers['content-type'] !== 'application/json') {
        throw new Error('Expected application/json');
      }
      handler(JSON.parse(body) as Record<string, unknown>);
    } catch (error) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: (error as Error).message }));
    }
  });
}

async function openInBrowser(url: string): Promise<void> {
  const { spawn } = await import('child_process');
  const platform = process.platform;
  const command = platform === 'darwin' ? 'open' : platform === 'win32' ? 'start' : 'xdg-open';
  try {
    spawn(command, [url], { stdio: 'ignore', detached: true, shell: platform === 'win32' }).unref();
  } catch {
    console.log('Could not auto-open a browser - open the URL above manually.');
  }
}
