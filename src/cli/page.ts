/**
 * HTML page for the local rules-picker UI. Everything is inlined except the
 * logo, which the server serves from the local-only /logo.png route - no
 * external CDNs or network calls.
 */

export interface RuleRow {
  id: string;
  title: string;
  severity: string;
  category: string;
  source: 'builtin' | 'external';
  disabled: boolean;
}

export interface Allowlists {
  allowedDomains: string[];
  allowedValues: string[];
  allowedPatterns: string[];
}

export function renderPage(
  rules: RuleRow[],
  allowlists: Allowlists,
  token: string,
  configPath: string,
  isGlobal: boolean
): string {
  const rulesJson = JSON.stringify(rules).replace(/</g, '\\u003c');
  const allowlistsJson = JSON.stringify(allowlists).replace(/</g, '\\u003c');
  const scopeLabel = isGlobal
    ? 'Global config - applies to every project unless it has its own .privacy-guard.json'
    : 'Project-level override';

  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Privacy Guard - Rules &amp; Allowlists</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; padding: 2rem; max-width: 860px; margin-inline: auto; }
  .brand { display: flex; align-items: center; gap: 0.5rem; }
  .brand img { height: 1.3rem; width: 1.3rem; border-radius: 4px; position: relative; top: 4px; }
  h1 { font-size: 1.3rem; margin-bottom: 0.25rem; }
  .subtitle { color: #888; font-size: 0.85rem; margin-bottom: 1.5rem; }
  .toolbar { display: flex; gap: 0.5rem; margin-bottom: 1rem; align-items: center; flex-wrap: wrap; }
  input[type="search"] { flex: 1; min-width: 200px; padding: 0.5rem 0.75rem; border-radius: 6px; border: 1px solid #8888; font-size: 0.9rem; }
  .group { margin-bottom: 1.25rem; }
  .group h2 { font-size: 0.95rem; text-transform: uppercase; letter-spacing: 0.04em; color: #888; border-bottom: 1px solid #8884; padding-bottom: 0.35rem; margin-bottom: 0.5rem; }
  .rule { display: flex; align-items: center; gap: 0.6rem; padding: 0.35rem 0.25rem; border-radius: 6px; }
  .rule:hover { background: #8881; }
  .rule label { flex: 1; cursor: pointer; }
  .rule .id { color: #888; font-size: 0.78rem; font-family: ui-monospace, monospace; }
  .badge { font-size: 0.68rem; padding: 0.1rem 0.45rem; border-radius: 999px; text-transform: uppercase; letter-spacing: 0.03em; }
  .badge.critical { background: #dc26261a; color: #dc2626; }
  .badge.high { background: #ea580c1a; color: #ea580c; }
  .badge.medium { background: #ca8a041a; color: #ca8a04; }
  .badge.low { background: #6b72801a; color: #6b7280; }
  #status { font-size: 0.85rem; margin-left: 0.5rem; }
  #status.ok { color: #16a34a; }
  #status.err { color: #dc2626; }
  footer { margin-top: 1.5rem; font-size: 0.78rem; color: #888; }
  .tabs { display: flex; gap: 0.25rem; border-bottom: 1px solid #8884; margin-bottom: 1.25rem; }
  .tabs button { background: none; border: none; border-bottom: 2px solid transparent; padding: 0.5rem 0.9rem; font: inherit; font-size: 0.9rem; color: #888; cursor: pointer; }
  .tabs button[aria-selected="true"] { color: inherit; border-bottom-color: currentColor; }
  .panel[hidden] { display: none; }
  .list { margin-bottom: 1.75rem; }
  .list h2 { font-size: 0.95rem; text-transform: uppercase; letter-spacing: 0.04em; color: #888; border-bottom: 1px solid #8884; padding-bottom: 0.35rem; margin-bottom: 0.4rem; }
  .list .hint { font-size: 0.8rem; color: #888; margin: 0 0 0.6rem; }
  .entry { display: flex; align-items: center; gap: 0.6rem; padding: 0.3rem 0.25rem; border-radius: 6px; }
  .entry:hover { background: #8881; }
  .entry code { flex: 1; font-family: ui-monospace, monospace; font-size: 0.85rem; word-break: break-all; }
  .entry button { background: none; border: 1px solid #8886; color: #888; border-radius: 6px; font: inherit; font-size: 0.75rem; padding: 0.1rem 0.5rem; cursor: pointer; }
  .entry button:hover { color: #dc2626; border-color: #dc2626; }
  .empty { font-size: 0.83rem; color: #888; font-style: italic; padding: 0.3rem 0.25rem; }
  .adder { display: flex; gap: 0.5rem; margin-top: 0.5rem; align-items: flex-start; flex-wrap: wrap; }
  .adder input { flex: 1; min-width: 220px; padding: 0.45rem 0.65rem; border-radius: 6px; border: 1px solid #8888; font-size: 0.9rem; font-family: ui-monospace, monospace; }
  .adder input.invalid { border-color: #dc2626; }
  .adder button { padding: 0.45rem 0.9rem; border-radius: 6px; border: 1px solid #8888; background: none; color: inherit; font: inherit; font-size: 0.85rem; cursor: pointer; }
  .adder button:hover:not(:disabled) { background: #8881; }
  .adder button:disabled { opacity: 0.45; cursor: not-allowed; }
  .field-error { flex-basis: 100%; font-size: 0.8rem; color: #dc2626; }
</style>
</head>
<body>
  <div class="brand">
    <img src="/logo.png" alt="Claude Code Privacy Guard logo">
    <h1>Privacy Guard - Rules &amp; Allowlists</h1>
  </div>
  <div class="subtitle">${escapeHtml(scopeLabel)}<br>Config: <code>${escapeHtml(configPath)}</code> - every change saves automatically</div>

  <div class="tabs" role="tablist">
    <button role="tab" id="tab-rules" aria-selected="true" aria-controls="panel-rules">Rules</button>
    <button role="tab" id="tab-allowlists" aria-selected="false" aria-controls="panel-allowlists">Allowlists</button>
    <span id="status"></span>
  </div>

  <div class="panel" id="panel-rules" role="tabpanel">
    <div class="toolbar">
      <input type="search" id="search" placeholder="Filter by id, title, or category...">
    </div>
    <div id="groups"></div>
  </div>

  <div class="panel" id="panel-allowlists" role="tabpanel" hidden>
    <div class="list" id="list-allowedDomains">
      <h2>Allowed domains</h2>
      <p class="hint">Email findings whose domain matches (or is a subdomain of) an entry are ignored. Example: <code>example.com</code> allows <code>a@example.com</code> and <code>a@mail.example.com</code>.</p>
      <div class="entries"></div>
      <div class="adder">
        <input type="text" placeholder="example.com" aria-label="Add an allowed domain">
        <button type="button">Add</button>
        <div class="field-error"></div>
      </div>
    </div>

    <div class="list" id="list-allowedValues">
      <h2>Allowed values</h2>
      <p class="hint">Exact matched text to never flag, for any rule. Use this for known-safe sample data - the value is stored in plain text in your config file.</p>
      <div class="entries"></div>
      <div class="adder">
        <input type="text" placeholder="AKIAIOSFODNN7EXAMPLE" aria-label="Add an allowed value">
        <button type="button">Add</button>
        <div class="field-error"></div>
      </div>
    </div>

    <div class="list" id="list-allowedPatterns">
      <h2>Allowed patterns</h2>
      <p class="hint">Regexes tested against the matched text; a hit suppresses the finding for any rule. Checked for validity and catastrophic backtracking before saving - the scanner silently drops patterns that fail either check.</p>
      <div class="entries"></div>
      <div class="adder">
        <input type="text" placeholder="^test-[a-z0-9]+$" aria-label="Add an allowed pattern">
        <button type="button">Add</button>
        <div class="field-error"></div>
      </div>
    </div>
  </div>

  <footer>${rules.length} rules total. Changes save automatically - stop the server from the terminal (Ctrl+C) when you're done, or it exits after 10 minutes of inactivity.</footer>

<script>
const RULES = ${rulesJson};
const ALLOWLISTS = ${allowlistsJson};
const TOKEN = ${JSON.stringify(token)};
const state = new Map(RULES.map(r => [r.id, !r.disabled]));

function render(filter) {
  const q = (filter || '').toLowerCase();
  const groupsEl = document.getElementById('groups');
  groupsEl.innerHTML = '';
  const byCategory = new Map();
  for (const r of RULES) {
    if (q && !(r.id.includes(q) || r.title.toLowerCase().includes(q) || r.category.toLowerCase().includes(q))) continue;
    if (!byCategory.has(r.category)) byCategory.set(r.category, []);
    byCategory.get(r.category).push(r);
  }
  for (const [category, items] of [...byCategory.entries()].sort()) {
    const group = document.createElement('div');
    group.className = 'group';
    const h2 = document.createElement('h2');
    h2.textContent = category + ' (' + items.length + ')';
    group.appendChild(h2);
    for (const r of items) {
      const row = document.createElement('div');
      row.className = 'rule';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.id = 'cb-' + r.id;
      cb.checked = state.get(r.id);
      cb.addEventListener('change', () => {
        state.set(r.id, cb.checked);
        scheduleSave();
      });
      const label = document.createElement('label');
      label.htmlFor = cb.id;
      label.innerHTML = r.title + ' <span class="id">(' + r.id + ')</span>';
      const badge = document.createElement('span');
      badge.className = 'badge ' + r.severity;
      badge.textContent = r.severity;
      row.append(cb, label, badge);
      group.appendChild(row);
    }
    groupsEl.appendChild(group);
  }
}

document.getElementById('search').addEventListener('input', (e) => render(e.target.value));

let saveTimer = null;
let saveInFlight = false;
let saveAgainAfter = false;

function scheduleSave() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(doSave, 300);
}

async function doSave() {
  if (saveInFlight) {
    saveAgainAfter = true;
    return;
  }
  saveInFlight = true;
  const disabledRules = RULES.filter(r => !state.get(r.id)).map(r => r.id);
  setStatus('Saving...', '');
  try {
    await postJson('/save', { disabledRules });
    setStatus('Saved (' + disabledRules.length + ' disabled).', 'ok');
  } catch (err) {
    setStatus('Error: ' + err.message, 'err');
  } finally {
    saveInFlight = false;
    if (saveAgainAfter) {
      saveAgainAfter = false;
      doSave();
    }
  }
}

function setStatus(text, cls) {
  const status = document.getElementById('status');
  status.className = cls;
  status.textContent = text;
}

async function postJson(url, payload) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(Object.assign({ token: TOKEN }, payload)),
  });
  const data = await res.json();
  if (!res.ok || !data.ok) throw new Error(data.error || 'Request failed');
  return data;
}

// ---- Tabs ----

for (const tab of document.querySelectorAll('[role="tab"]')) {
  tab.addEventListener('click', () => {
    for (const other of document.querySelectorAll('[role="tab"]')) {
      const selected = other === tab;
      other.setAttribute('aria-selected', String(selected));
      document.getElementById(other.getAttribute('aria-controls')).hidden = !selected;
    }
  });
}

// ---- Allowlists ----

const LIST_LABELS = {
  allowedDomains: 'domain',
  allowedValues: 'value',
  allowedPatterns: 'pattern',
};

function renderList(key) {
  const entriesEl = document.querySelector('#list-' + key + ' .entries');
  entriesEl.innerHTML = '';
  const items = ALLOWLISTS[key];
  if (items.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = 'No ' + LIST_LABELS[key] + 's allowlisted.';
    entriesEl.appendChild(empty);
    return;
  }
  items.forEach((item, index) => {
    const row = document.createElement('div');
    row.className = 'entry';
    const code = document.createElement('code');
    code.textContent = item;
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.textContent = 'Remove';
    remove.setAttribute('aria-label', 'Remove ' + item);
    remove.addEventListener('click', () => {
      ALLOWLISTS[key].splice(index, 1);
      renderList(key);
      saveAllowlists();
    });
    row.append(code, remove);
    entriesEl.appendChild(row);
  });
}

function setupAdder(key) {
  const listEl = document.getElementById('list-' + key);
  const input = listEl.querySelector('.adder input');
  const button = listEl.querySelector('.adder button');
  const error = listEl.querySelector('.field-error');

  function showError(message) {
    error.textContent = message || '';
    input.classList.toggle('invalid', Boolean(message));
    button.disabled = Boolean(message);
  }

  async function add() {
    const raw = input.value.trim();
    if (!raw) return;
    const value = key === 'allowedDomains' ? raw.toLowerCase() : raw;
    if (ALLOWLISTS[key].includes(value)) {
      showError('Already in the list.');
      return;
    }
    if (key === 'allowedPatterns') {
      const check = await validatePattern(value);
      if (!check.valid) {
        showError(check.error);
        return;
      }
    }
    ALLOWLISTS[key].push(value);
    input.value = '';
    showError('');
    renderList(key);
    saveAllowlists();
  }

  button.addEventListener('click', add);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      add();
    }
  });

  // Live validation for regexes, using the same check the scanner applies.
  let validateTimer = null;
  input.addEventListener('input', () => {
    showError('');
    if (key !== 'allowedPatterns') return;
    clearTimeout(validateTimer);
    const value = input.value.trim();
    if (!value) return;
    validateTimer = setTimeout(async () => {
      const check = await validatePattern(value);
      if (input.value.trim() === value) showError(check.valid ? '' : check.error);
    }, 300);
  });
}

async function validatePattern(pattern) {
  try {
    return await postJson('/validate-pattern', { pattern });
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

let allowlistSaveInFlight = false;
let allowlistSaveAgain = false;

async function saveAllowlists() {
  if (allowlistSaveInFlight) {
    allowlistSaveAgain = true;
    return;
  }
  allowlistSaveInFlight = true;
  setStatus('Saving...', '');
  try {
    await postJson('/save-allowlists', ALLOWLISTS);
    const total = ALLOWLISTS.allowedDomains.length + ALLOWLISTS.allowedValues.length + ALLOWLISTS.allowedPatterns.length;
    setStatus('Saved (' + total + ' allowlist entries).', 'ok');
  } catch (err) {
    setStatus('Error: ' + err.message, 'err');
  } finally {
    allowlistSaveInFlight = false;
    if (allowlistSaveAgain) {
      allowlistSaveAgain = false;
      saveAllowlists();
    }
  }
}

for (const key of Object.keys(LIST_LABELS)) {
  renderList(key);
  setupAdder(key);
}

render('');
</script>
</body>
</html>`;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string));
}
