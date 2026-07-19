/**
 * Self-contained HTML page for the local rules-picker UI. No external
 * assets/CDNs - everything is inlined so it works fully offline.
 */

export interface RuleRow {
  id: string;
  title: string;
  severity: string;
  category: string;
  source: 'builtin' | 'external';
  disabled: boolean;
}

export function renderPage(rules: RuleRow[], token: string, configPath: string, isGlobal: boolean): string {
  const rulesJson = JSON.stringify(rules).replace(/</g, '\\u003c');
  const scopeLabel = isGlobal
    ? 'Global config - applies to every project unless it has its own .privacy-guard.json'
    : 'Project-level override';

  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Privacy Guard - Rule Toggles</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; padding: 2rem; max-width: 860px; margin-inline: auto; }
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
</style>
</head>
<body>
  <h1>Privacy Guard - Rule Toggles</h1>
  <div class="subtitle">${escapeHtml(scopeLabel)}<br>Config: <code>${escapeHtml(configPath)}</code> - uncheck a rule to disable it, saved automatically to <code>disabledRules</code></div>
  <div class="toolbar">
    <input type="search" id="search" placeholder="Filter by id, title, or category...">
    <span id="status"></span>
  </div>
  <div id="groups"></div>
  <footer>${rules.length} rules total. Toggles save automatically - stop the server from the terminal (Ctrl+C) when you're done, or it exits after 10 minutes of inactivity.</footer>

<script>
const RULES = ${rulesJson};
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
  const status = document.getElementById('status');
  status.className = '';
  status.textContent = 'Saving...';
  try {
    const res = await fetch('/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: TOKEN, disabledRules }),
    });
    const data = await res.json();
    if (!res.ok || !data.ok) throw new Error(data.error || 'Save failed');
    status.className = 'ok';
    status.textContent = 'Saved (' + disabledRules.length + ' disabled).';
  } catch (err) {
    status.className = 'err';
    status.textContent = 'Error: ' + err.message;
  } finally {
    saveInFlight = false;
    if (saveAgainAfter) {
      saveAgainAfter = false;
      doSave();
    }
  }
}

render('');
</script>
</body>
</html>`;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string));
}
