// clients.js: the nimbus product views (spec docs/design/cwm-dashboard-spec.md v2.5 and §6).
// Every view is registered in window.CWM.commands as {name, title, render}; cwm.js (loaded after
// this file) renders sections into panels and drill-downs (finding, node) into the right-hand pane,
// calling render(root, api, arg) with api = {open, D, live, panel, setTitle, setArg, onClose}.
// Styles live in cwm.css (.view). All data strings are written with textContent only.
(function () {
'use strict';
const C = window.CWM = window.CWM || { commands: [] };
if (!Array.isArray(C.commands)) C.commands = [];

// ---------------------------------------------------------------- helpers
const SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const SEV_SHORT = { CRITICAL: 'CRIT', HIGH: 'HIGH', MEDIUM: 'MED', LOW: 'LOW', INFO: 'INFO' };
const FONT = '"Menlo","DejaVu Sans Mono","Liberation Mono",monospace';

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = String(text);
  return e;
}
function str(v) { return v == null ? '' : String(v).replace(/[\r\n\t]+/g, ' '); }
// fit: left-align s in exactly n cells, truncating with "…".
function fit(s, n) {
  s = str(s);
  if (n <= 0) return '';
  if (s.length > n) return n === 1 ? '…' : s.slice(0, n - 1) + '…';
  return s + ' '.repeat(n - s.length);
}
function rfit(s, n) {
  s = str(s);
  if (s.length >= n) return s.length > n ? s.slice(0, n) : s;
  return ' '.repeat(n - s.length) + s;
}
function num(n) { return n == null ? '-' : Number(n).toLocaleString('en-US'); }
function f1(n) { return n == null || isNaN(n) ? '-' : Number(n).toFixed(1); }
function wk(w) { return str(w).replace(/_/g, ' ').toLowerCase(); }
function ago(iso) {
  const t = Date.parse(iso || '');
  if (isNaN(t)) return '-';
  let s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return s + 's ago';
  s = Math.round(s / 60); if (s < 60) return s + 'm ago';
  s = Math.round(s / 60); if (s < 48) return s + 'h ago';
  return Math.round(s / 24) + 'd ago';
}
function sqlq(s) { return "'" + str(s).replace(/'/g, "''") + "'"; }
function acctOf(f) { return (f.tags && f.tags.account_label) || f.account || ''; }

// line builders: a line is a <div class="ln"> of <span>s.
function line(parent, cls) { const d = el('div', 'ln' + (cls ? ' ' + cls : '')); parent.appendChild(d); return d; }
function blank(parent) { return line(parent); }
function seg(ln, text, cls) { const s = el('span', cls || null, text); ln.appendChild(s); return s; }
function link(ln, text, fn, cls, open) {
  const s = el('span', 'row' + (cls ? ' ' + cls : ''), text);
  if (open) s.setAttribute('data-open', open);
  s.addEventListener('click', e => { e.stopPropagation(); fn(); });
  ln.appendChild(s);
  return s;
}
function rowLine(parent, fn, cls, open) {
  const d = line(parent, 'row' + (cls ? ' ' + cls : ''));
  if (open) d.setAttribute('data-open', open);
  d.addEventListener('click', e => { e.stopPropagation(); fn(); });
  return d;
}
function text(parent, s, cls) { const d = line(parent, cls); d.textContent = str(s) === '' ? '' : String(s); return d; }
// act: a plain-text action such as [show dead ends] (not a list row, so j/k skip it).
function act(ln, label, fn, toggle) {
  const s = el('span', 'act', label);
  s.setAttribute('role', 'button');
  if (toggle) s.setAttribute('data-toggle', toggle);
  s.addEventListener('click', e => { e.stopPropagation(); fn(); });
  ln.appendChild(s);
  return s;
}

// cell metrics and available columns for a client root.
function cellW(root) {
  const m = el('span', null, 'MMMMMMMMMM');
  m.style.cssText = 'position:absolute;visibility:hidden;white-space:pre;font:inherit';
  root.appendChild(m);
  const w = m.getBoundingClientRect().width / 10;
  m.remove();
  return w > 0 ? w : 7.8;
}
function availCols(root, def) {
  const w = root.clientWidth;
  if (!w) return def;
  const n = Math.floor((w - 4) / cellW(root));
  return n > 20 ? n : def;
}

// fitCols drops optional columns (highest `opt` first) until the w:0 column gets at least
// minRest cells, so a narrow panel keeps a readable title column instead of "Adminis…".
function fitCols(cols, width, minRest) {
  let use = cols.slice();
  const fixedOf = cs => cs.reduce((a, c) => a + (c.w || 0), 0) + (cs.length - 1);
  while (width - fixedOf(use) < (minRest || 28)) {
    const d = use.filter(c => c.opt).sort((a, b) => b.opt - a.opt)[0];
    if (!d) break;
    use = use.filter(c => c !== d);
  }
  return use;
}
// hang: wrap a long line at word boundaries with its continuation indented n cells.
function hang(ln, n) {
  ln.classList.add('wrap');
  ln.style.paddingLeft = n + 'ch';
  ln.style.textIndent = (-n) + 'ch';
  return ln;
}
// table: cols = [{h, w, r(ight), get(row), cls(row), opt}]; one column may have w:0 (= rest);
// columns with `opt` are dropped (highest first) when the panel is too narrow.
function table(parent, cols, rows, width, onClick, openName) {
  cols = fitCols(cols, width);
  const fixed = cols.reduce((a, c) => a + (c.w || 0), 0) + (cols.length - 1);
  const rest = Math.max(8, width - fixed);
  const W = cols.map(c => c.w || rest);
  const hd = line(parent, 'b nw thead');
  hd.textContent = cols.map((c, i) => (c.r ? rfit(c.h, W[i]) : fit(c.h, W[i]))).join(' ').replace(/\s+$/, '');
  rows.forEach(r => {
    const ln = onClick ? rowLine(parent, () => onClick(r), 'nw', openName) : line(parent, 'nw');
    cols.forEach((c, i) => {
      if (i) seg(ln, ' ');
      const v = c.get(r);
      seg(ln, c.r ? rfit(v, W[i]) : fit(v, W[i]), c.cls ? c.cls(r) : null);
    });
  });
  return W;
}

// data indexes, cached per findings array.
const idxCache = new WeakMap();
function idx(D) {
  const fs = D.findings || [];
  let x = idxCache.get(fs);
  if (x && x.paths === D.paths && x.risk === D.risk) return x;
  const byId = Object.create(null);
  fs.forEach(f => { byId[f.id] = f; });
  const riskBy = Object.create(null);
  (D.risk || []).forEach(r => { if (r && r.finding) riskBy[r.finding.id] = r; });
  const nodeBy = Object.create(null);
  ((D.graph && D.graph.nodes) || []).forEach(n => { nodeBy[n.id] = n; });
  x = { byId, riskBy, nodeBy, open: fs.filter(f => f.status === 'FAIL'), paths: D.paths, risk: D.risk };
  idxCache.set(fs, x);
  return x;
}
function analysisOf(D) { return D.analysis || {}; }

// ---------------------------------------------------------------- Issues (Track G)
// An Issue is one canonical check on one resource; every tool's findings are its evidence.
// A `combination` Issue is a declared toxic combination of weaknesses on one resource.
// TOXIC mirrors model.ToxicCombinations (render_test.go keeps the two in step).
const TOXIC = {
  TOXIC_PUBLIC_UNENCRYPTED_SENSITIVE: ['PUBLIC_DATA_STORE', 'UNENCRYPTED_AT_REST', 'SENSITIVE_DATA'],
  TOXIC_PUBLIC_ADMIN: ['PUBLIC_NETWORK_EXPOSURE', 'OVERPRIVILEGED_IDENTITY'],
  TOXIC_NO_MFA_ADMIN: ['NO_MFA', 'OVERPRIVILEGED_IDENTITY'],
};
// issuesOf returns the Issue list, or null for a payload that predates Issues (the views then
// fall back to raw findings).
function issuesOf(D) {
  const is = D.issues;
  if (!Array.isArray(is)) return null;
  if (!is.length && (D.findings || []).some(f => f.status === 'FAIL')) return null;
  return is;
}
function issueOpen(i) { const s = str(i.state).toLowerCase(); return !s || s === 'open' || s === 'reopened'; }
function isCombo(i) { return i.kind === 'combination'; }
function comboWeak(i, X) {
  const w = TOXIC[i.canonical_id];
  if (w) return w.slice();
  const s = new Set();
  (i.finding_ids || []).forEach(id => { const f = X.byId[id]; ((f && f.weaknesses) || []).forEach(x => s.add(x)); });
  return [...s];
}
// isDead(resource id): true only when the analysis classified it as reaching no crown jewel.
function deadFn(D) { const r = analysisOf(D).reaches_crown_jewel || {}; return id => r[id] === false; }
function bestRisk(X, ids) {
  let b = null;
  (ids || []).forEach(id => { const r = X.riskBy[id]; if (r && (!b || (r.risk_score || 0) > (b.risk_score || 0))) b = r; });
  return b;
}
// issueCounts: live /api/summary Issue counts (top level with unit "issues", or an `issues`
// object) win; otherwise they are counted from the Issue list; null when there are no Issues.
function issueCounts(D) {
  const s = D.summary;
  // store.Headline (W5-ISSUES): the numbers the CLI and /api/summary print — every Issue kind,
  // critical = the Issue's severity. A live summary's headline wins over the payload's; once a
  // live summary has arrived the payload's (scan-time) headline is stale and is not used.
  const h = (s && s.headline && typeof s.headline === 'object') ? s.headline : (!s && D.headline && typeof D.headline === 'object' ? D.headline : null);
  if (h && typeof h.issues === 'number') {
    return { open: h.issues, total: h.issues, combos: h.combinations || 0, bySev: h.by_severity || {}, from: 'headline',
      paths: h.path_issues || 0, variants: h.path_variants || 0, findingIssues: h.finding_issues || 0,
      critical: h.critical || 0, pathCritical: h.path_critical || 0, findingCritical: h.finding_critical || 0 };
  }
  let ic = null;
  if (s && typeof s === 'object') ic = s.unit === 'issues' ? s : (s.issues && typeof s.issues === 'object' && !Array.isArray(s.issues) ? s.issues : null);
  if (ic && typeof ic.open === 'number') return { open: ic.open, total: ic.total, combos: ic.combinations || 0, bySev: ic.by_severity || {}, from: 'summary' };
  const is = issuesOf(D);
  if (!is) return null;
  const open = is.filter(issueOpen);
  const bySev = {};
  open.forEach(i => { bySev[i.severity] = (bySev[i.severity] || 0) + 1; });
  return { open: open.length, total: is.length, combos: open.filter(isCombo).length, bySev, from: 'issues' };
}
function nodeName(X, id, fids) {
  const n = X.nodeBy[id];
  if (n && n.name) return n.name;
  const f = (fids || []).map(x => X.byId[x]).find(Boolean);
  return (f && f.resource && f.resource.name) || id;
}
function pathsSorted(D) { return (D.paths || []).slice().sort((a, b) => (b.score || 0) - (a.score || 0)); }

// ---------------------------------------------------------------- live registry
const registry = [];   // {root, api, name}
const liveLog = [];    // lines printed in overview
let lastD = null;

// teardown releases everything a view attached outside its own DOM subtree: the Cytoscape
// instance (which registers window listeners), its ResizeObserver and its restyle entry.
function teardown(root) {
  if (root._cy) {
    const cy = root._cy;
    root._cy = null;
    for (let i = cyRegistry.length - 1; i >= 0; i--) if (cyRegistry[i].cy === cy) cyRegistry.splice(i, 1);
    try { cy.destroy(); } catch (e) { /* ignore */ }
  }
  if (root._ro) { try { root._ro.disconnect(); } catch (e) { /* ignore */ } root._ro = null; }
  root._cwmRefresh = null;
}
function draw(name, root, api, arg) {
  const v = VIEWS[name];
  teardown(root);
  root.textContent = '';
  v(root, api, arg);
}
// focusKey identifies an input across a re-render (same data-role / id / aria-label).
function focusKey(e) {
  return e && e.tagName === 'INPUT' ? (e.getAttribute('data-role') || e.id || e.getAttribute('aria-label') || '') : '';
}
function mount(name, live) {
  return function (root, api, arg) {
    api = api || {};
    if (api.D) lastD = api.D;
    if (!api.panel || name !== 'overview') root.classList.add('view');
    root._cwmArg = arg;
    if (!root._cwmMounted) {
      // once per window: register for live updates and clean up when the window closes.
      root._cwmMounted = true;
      const entry = { root, api, name };
      if (live) registry.push(entry);
      // Re-layout: tables are truncated to the panel's width in character cells, so when the
      // panel changes width (pane opens/closes, window resizes) the view is redrawn.
      if (live && window.ResizeObserver) {
        let cols = 0, t = 0;
        const ro = new ResizeObserver(() => {
          if (!root.isConnected) return;
          const c = availCols(root, 0);
          if (!cols) { cols = c; return; }
          if (c === cols) return;
          cols = c;
          clearTimeout(t);
          t = setTimeout(() => {
            if (!root.isConnected) return;
            try { redraw(entry); } catch (e) { if (window.console) console.error(e); }
            if (typeof C.applyFocus === 'function') C.applyFocus();
          }, 40);
        });
        ro.observe(root);
        root._wro = ro;
      }
      if (typeof api.onClose === 'function') {
        api.onClose(() => {
          teardown(root);
          if (root._wro) { try { root._wro.disconnect(); } catch (e) { /* ignore */ } root._wro = null; }
          const i = registry.indexOf(entry);
          if (i >= 0) registry.splice(i, 1);
        });
      }
    }
    draw(name, root, api, arg);
  };
}
// redraw re-renders one live view. Views that can update in place (root._cwmRefresh) keep
// their DOM, so a focused input keeps focus, caret and pending keystrokes; otherwise a
// focused input inside the window is found again by focusKey and its value/selection restored.
function redraw(r) {
  const root = r.root;
  if (typeof root._cwmRefresh === 'function') { root._cwmRefresh(); return; }
  const a = document.activeElement;
  const key = a && root.contains(a) ? focusKey(a) : '';
  const saved = key ? { value: a.value, s: a.selectionStart, e: a.selectionEnd } : null;
  const st = root.scrollTop;
  draw(r.name, root, r.api, root._cwmArg);
  root.scrollTop = st;
  if (!saved) return;
  const n = [...root.querySelectorAll('input')].find(x => focusKey(x) === key);
  if (!n) return;
  n.value = saved.value;
  try { n.focus({ preventScroll: true }); n.setSelectionRange(saved.s, saved.e); } catch (e) { /* ignore */ }
}
function rerenderAll() {
  for (let i = registry.length - 1; i >= 0; i--) {
    const r = registry[i];
    if (!r.root.isConnected) { registry.splice(i, 1); continue; }
    try { redraw(r); } catch (e) { if (window.console) console.error(e); }
  }
}
C.onLive = function (event, fresh) {
  const type = typeof event === 'string' ? event : (event && event.type) || '';
  // spec §6: only these three events change what is drawn; anything else (e.g. the
  // server's `hello` on connect) must not re-render views or print a line.
  if (type !== 'findings_updated' && type !== 'scan_started' && type !== 'monitor_event') return;
  const payload = (event && typeof event === 'object' && event.payload) || {};
  const t = new Date().toTimeString().slice(0, 8);
  const D = lastD || (registry[0] && registry[0].api.D);
  if (type === 'findings_updated') {
    if (D && fresh && Array.isArray(fresh.findings)) {
      // /api/findings?status=FAIL returns the open set; keep non-failing results as they were.
      D.findings = (D.findings || []).filter(f => f.status !== 'FAIL').concat(fresh.findings);
    }
    if (D && fresh && fresh.summary) D.summary = fresh.summary;
    if (D && fresh && Array.isArray(fresh.issues)) D.issues = fresh.issues;
    liveLog.push(t + ' findings updated');
  } else if (type === 'scan_started') {
    liveLog.push(t + ' scan running…');
  } else if (type === 'monitor_event') {
    liveLog.push(t + ' change detected: ' + str(payload.title || ''));
  }
  while (liveLog.length > 6) liveLog.shift();
  rerenderAll();
};

// ---------------------------------------------------------------- overview
// A grid of panels (spec v2.2). api.panel(key, title, wide) adds a bordered box to the grid and
// returns its body; every number is a drill-through to the matching filtered view.
function vOverview(root, api) {
  const D = api.D || {}, X = idx(D), A = analysisOf(D);
  const open = X.open, fs = D.findings || [];
  const go = (cmd, arg) => () => api.open(cmd, arg);
  const box = (key, title, wide) => (api.panel ? api.panel(key, title, wide) : root);
  const ic = issueCounts(D);
  const issues = issuesOf(D);

  // risk: Issues first (one per check × resource); raw findings are the secondary line.
  let p = box('risk', 'risk');
  let ln = line(p, 'dim');
  seg(ln, 'nimbus ' + str(D.generated_at) + ' · ' + str(D.mode || 'static') + ' · ' +
    (D.accounts && D.accounts.length ? D.accounts.length + ' account(s): ' + D.accounts.join(', ') : 'ingested results'));
  liveLog.forEach(s => text(p, s, 'dim'));
  const bySev = {}; SEV.forEach(s => { bySev[s] = 0; });
  if (ic) {
    SEV.forEach(s => { bySev[s] = ic.bySev[s] || 0; });
    ln = line(p);
    // The CLI's headline, word for word (store.Headline.Text, W7-POLISH r5 #13 / R4):
    // "83 open Issues: 19 attack path Issues (22 hop variants) + 64 finding Issues; 12 critical (2 path, 10 finding)".
    // Toxic combinations are a separate count after it, never inside the critical parenthesis.
    const pl = (n, one, many) => ' ' + (n === 1 ? one : many);
    link(ln, num(ic.open), go('findings', { deadends: 1 }), 'ov-open b', 'findings');
    seg(ln, pl(ic.open, 'open Issue', 'open Issues'));
    if (ic.from === 'headline') {
      seg(ln, ': ');
      link(ln, num(ic.paths), go('paths'), null, 'paths');
      seg(ln, pl(ic.paths, 'attack path Issue', 'attack path Issues') + ' (' + num(ic.variants) + pl(ic.variants, 'hop variant', 'hop variants') + ') + ' +
        num(ic.findingIssues) + pl(ic.findingIssues, 'finding Issue', 'finding Issues') + '; ');
      seg(ln, num(ic.critical) + ' critical', ic.critical ? 'sev-CRITICAL' : 'dim');
      seg(ln, ' (' + num(ic.pathCritical) + ' path, ' + num(ic.findingCritical) + ' finding)');
    }
    if (ic.combos) {
      seg(ln, ' · ');
      link(ln, num(ic.combos) + pl(ic.combos, 'toxic combination', 'toxic combinations'), go('findings', { q: 'TOXIC_', deadends: 1 }), 'red', 'findings');
    }
    ln = line(p, 'dim');
    seg(ln, 'findings: ');
    link(ln, num(open.length), go('findings', { status: 'FAIL', view: 'findings' }), null, 'findings');
    seg(ln, ' open of ');
    link(ln, num(fs.length), go('findings', { status: 'all', view: 'findings' }), null, 'findings');
    seg(ln, ' results, as evidence');
  } else {
    open.forEach(f => { bySev[f.severity] = (bySev[f.severity] || 0) + 1; });
    ln = line(p);
    link(ln, num(open.length), go('findings', { status: 'FAIL' }), 'ov-open b', 'findings');
    seg(ln, ' open findings of ');
    link(ln, num(fs.length), go('findings', { status: 'all' }), null, 'findings');
    seg(ln, ' results');
  }
  ln = line(p, 'nw');
  SEV.forEach((s, i) => {
    if (i) seg(ln, '  ');
    link(ln, num(bySev[s]), go('findings', { severity: s, deadends: 1 }), 'sev-' + s, 'findings');
    seg(ln, ' ' + s.toLowerCase());
  });
  const top = (D.risk || [])[0];
  ln = line(p);
  seg(ln, 'top risk ');
  if (top) {
    link(ln, f1(top.risk_score), go('finding', top.finding.id), 'band-' + top.band, 'finding');
    seg(ln, ' ' + str(top.band) + '  ');
    link(ln, str(top.finding.title), go('finding', top.finding.id), null, 'finding');
  } else seg(ln, '-');
  if (D.scan && D.scan.started_at) {
    const since = Date.parse(D.scan.started_at);
    const nw = issues ? issues.filter(i => issueOpen(i) && Date.parse(i.first_seen) >= since).length
      : open.filter(f => Date.parse(f.first_seen) >= since).length;
    ln = line(p);
    link(ln, num(nw), go('findings', { deadends: 1 }), null, 'findings');
    seg(ln, (issues ? ' issues' : '') + ' new since last scan (' + str(D.scan.scan_id) + ')');
  }

  // owners: governance (docs/governance.md) - open and overdue Issues by owner, MTTR by
  // severity and the on-time rate, from D.governance (internal/server.GovernanceMetrics).
  p = box('owners', 'owners');
  const G = D.governance;
  if (G && typeof G === 'object') {
    ln = line(p);
    seg(ln, 'overdue ');
    link(ln, num(G.open_past_due || 0), go('findings', { q: 'overdue', deadends: 1 }), (G.open_past_due ? 'red b' : null), 'findings');
    seg(ln, '  past grace ' + num(G.open_past_grace || 0) + '  open ' + num(G.open || 0), 'dim');
    ln = line(p);
    const done = (G.on_time || 0) + (G.late || 0);
    seg(ln, 'on-time ' + (done ? Math.round((G.on_time_rate || 0) * 100) + '% (' + G.on_time + '/' + done + ')' : '-'));
    ln = line(p, 'nw');
    seg(ln, 'MTTR ');
    const mh = G.mttr_hours_by_severity || {};
    ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].forEach((sv, n) => {
      if (n) seg(ln, ' ');
      const h = mh[sv];
      seg(ln, ({ CRITICAL: 'crit', HIGH: 'high', MEDIUM: 'med', LOW: 'low' })[sv] + ' ', 'dim');
      const has = typeof h === 'number';
      seg(ln, has ? (h < 48 ? h.toFixed(1) + 'h' : (h / 24).toFixed(1) + 'd') : '-', has ? 'sev-' + sv : 'dim');
    });
    text(p, 'open / overdue by owner', 'b');
    const rows = G.owners || [];
    if (!rows.length) text(p, '  none', 'dim');
    rows.slice(0, 6).forEach(o => {
      ln = line(p, 'nw');
      ln.setAttribute('data-owner', str(o.owner));
      seg(ln, '  ' + fit(str(o.owner), 26) + ' ');
      link(ln, rfit(num(o.open), 4), go('findings', { q: o.owner === '(unassigned)' ? '' : o.owner, deadends: 1 }), null, 'findings');
      seg(ln, ' ');
      link(ln, rfit(num(o.overdue), 4), go('findings', { q: 'overdue ' + (o.owner === '(unassigned)' ? '' : o.owner), deadends: 1 }), o.overdue ? 'red' : 'dim', 'findings');
    });
  } else {
    // payload without governance (no store): open criticals by ranking owner tag
    const crits = (D.risk || []).filter(r => r.finding && r.finding.severity === 'CRITICAL' && r.finding.status === 'FAIL');
    const own = {};
    crits.forEach(r => { const o = r.owner || '(unassigned)'; own[o] = (own[o] || 0) + 1; });
    text(p, 'open criticals by owner', 'b');
    const ok = Object.keys(own).sort((a, b) => own[b] - own[a]);
    if (!ok.length) text(p, '  none', 'dim');
    ok.slice(0, 6).forEach(o => {
      ln = line(p, 'nw');
      seg(ln, '  ' + fit(o, 28) + ' ');
      link(ln, rfit(num(own[o]), 5), go('risk'), 'sev-CRITICAL', 'risk');
    });
  }

  // attack paths
  p = box('attack paths', 'attack paths', true);
  const W = Math.min(120, availCols(p, 100));
  // One count per path Issue (D.path_groups, the `paths` CLI's rows), not per hop variant.
  const gs = pathGroupsOf(D);
  const ps = gs.map(g => g.best);
  const crit = gs.filter(g => (g.severity || g.best.severity) === 'CRITICAL').length;
  ln = line(p);
  link(ln, num(gs.length), go('paths'), 'ov-paths b', 'paths');
  seg(ln, ' attack path Issue' + (gs.length === 1 ? '' : 's') + ', ');
  link(ln, num(crit), go('paths'), 'sev-CRITICAL', 'paths');
  seg(ln, ' critical; ');
  link(ln, num((A.entry_points || []).length), go('paths'), null, 'paths');
  seg(ln, ' entry points, ');
  link(ln, num((A.targets || []).length), go('paths'), null, 'paths');
  seg(ln, ' targets; min fix set ');
  link(ln, num((A.min_fix_set || []).length), go('paths'), null, 'paths');
  seg(ln, ' fixes remove ' + (A.min_fix_coverage || 0) + '% of path risk');
  if (A.dead_ends && A.dead_ends.count) {
    seg(ln, '; dead ends ');
    link(ln, num(A.dead_ends.count), go('paths', { deadends: 1 }), 'dim', 'paths');
  }
  if ((A.incomplete || []).length) seg(ln, '  ' + A.incomplete.length + ' incomplete', 'dim');
  if (ps.length) {
    blank(p);
    table(p, [
      { h: 'SCORE', w: 5, r: 1, get: x => f1(x.score), cls: x => x.weak_link ? 'dim' : 'sev-' + x.severity },
      { h: 'PATH', w: 0, get: x => pathLabel(D, x), cls: x => x.weak_link ? 'dim' : null },
      { h: 'STEPS', w: 5, r: 1, get: x => (x.steps || []).length },
    ], ps.slice(0, 5), W, x => api.open('paths', { pathId: x.id }), 'paths');
  }
  const cps = (A.choke_points || []).slice().sort((a, b) => (b.paths - a.paths) || (b.score_sum - a.score_sum)).slice(0, 5);
  if (cps.length) {
    blank(p);
    table(p, [
      { h: 'CHOKE POINT', w: 30, get: c => c.name },
      { h: 'TYPE', w: 20, get: c => c.type },
      { h: 'PATHS', w: 5, r: 1, get: c => c.paths },
      { h: 'CLOSES', w: 6, r: 1, get: c => c.closes_n == null ? '-' : c.closes_n },
      { h: 'WEAKNESSES', w: 0, get: c => (c.weaknesses || []).map(wk).join(', ') },
    ], cps, W, c => api.open('paths', { choke: c.node_id }), 'paths');
  }

  // issues by severity x provider (Issues; open findings when the payload has no Issues)
  p = box('issues', 'issues by severity × provider');
  const Wi = availCols(p, 60);
  const units = issues ? issues.filter(issueOpen) : open;
  const provs = [...new Set(units.map(f => f.provider))].sort();
  if (!provs.length) text(p, issues ? 'no open issues' : 'no open findings', 'dim');
  else {
    const cnt = {}; provs.forEach(x => { cnt[x] = {}; SEV.forEach(s => { cnt[x][s] = 0; }); });
    units.forEach(f => { if (cnt[f.provider]) cnt[f.provider][f.severity] = (cnt[f.provider][f.severity] || 0) + 1; });
    const tot = x => SEV.reduce((a, s) => a + cnt[x][s], 0);
    const max = Math.max(1, ...provs.map(tot));
    const barW = Math.max(6, Math.min(40, Wi - 52));
    ln = line(p, 'b nw');
    seg(ln, fit('PROVIDER', 10) + SEV.map(s => rfit(SEV_SHORT[s], 6)).join('') + rfit('TOTAL', 7));
    provs.forEach(x => {
      ln = line(p, 'nw');
      link(ln, fit(x, 10), go('findings', { provider: x, deadends: 1 }), null, 'findings');
      SEV.forEach(s => {
        const n = cnt[x][s];
        if (n) { seg(ln, ' '.repeat(Math.max(0, 6 - String(n).length))); link(ln, String(n), go('findings', { severity: s, provider: x, deadends: 1 }), 'sev-' + s, 'findings'); }
        else seg(ln, rfit('.', 6), 'dim');
      });
      seg(ln, ' '.repeat(Math.max(0, 7 - String(tot(x)).length)));
      link(ln, String(tot(x)), go('findings', { provider: x, deadends: 1 }), null, 'findings');
      seg(ln, '  ');
      SEV.forEach(s => {
        const n = cnt[x][s]; if (!n) return;
        seg(ln, '#'.repeat(Math.max(1, Math.round(barW * n / max))), 'sev-' + s);
      });
    });
  }

  // trend: one monochrome sparkline per severity over the scan history (oldest → newest)
  p = box('trend', 'trend');
  trendBlock(p, D);

  // compliance
  p = box('compliance', 'compliance');
  const Wc = availCols(p, 60);
  const comp = (D.compliance || []).slice().sort((a, b) => (b.score_percent || 0) - (a.score_percent || 0));
  if (!comp.length) text(p, 'no framework data', 'dim');
  else {
    const nm = Math.max(16, Math.min(40, Wc - 26));
    ln = line(p, 'b nw');
    seg(ln, fit('FRAMEWORK', nm) + rfit('SCORE', 7) + rfit('FAIL', 6) + rfit('PASS', 6) + rfit('N/A', 6));
    comp.forEach(r => {
      ln = line(p, 'nw');
      const fw = r.framework || {};
      const g = go('compliance', { framework: fw.key });
      link(ln, fit(fw.name || fw.key, nm), g, null, 'compliance');
      const sp = r.score_percent || 0;
      const scs = String(sp) + '%';
      seg(ln, ' '.repeat(Math.max(0, 7 - scs.length)));
      link(ln, scs, g, sp >= 80 ? 'ok' : sp < 50 ? 'red' : null, 'compliance');
      [[r.failing, 'red'], [r.passing, null], [r.not_assessed, 'dim']].forEach(([n, c]) => {
        const s = num(n || 0);
        seg(ln, ' '.repeat(Math.max(0, 6 - s.length)));
        link(ln, s, g, n ? c : null, 'compliance');
      });
    });
  }

  // coverage: what actually ran (coverage table), else the scan's tool runs
  p = box('coverage', 'coverage');
  const cov = D.coverage || [];
  const sc = D.scan;
  if (cov.length) {
    const st = covCounts(cov);
    ln = line(p);
    link(ln, num(cov.length), go('coverage'), 'b', 'coverage');
    seg(ln, ' API calls / tool runs recorded');
    ln = line(p, 'nw');
    COV.forEach((s, i) => {
      if (i) seg(ln, ', ');
      link(ln, num(st[s]), go('coverage'), 'c-' + s + (st[s] ? ' ' + COV_CLS[s] : ''), 'coverage');
      seg(ln, ' ' + s);
    });
    const accts = new Set(cov.map(covKey)).size;
    text(p, accts + ' provider/account(s) · scan ' + str(cov[0].scan_id) + ' · ' + ago(cov[0].at), 'dim');
  } else if (sc && sc.tools && sc.tools.length) {
    const st = { ok: 0, skipped: 0, failed: 0 };
    sc.tools.forEach(t => { st[t.status] = (st[t.status] || 0) + 1; });
    ln = line(p);
    link(ln, num(sc.tools.length), go('coverage'), 'b', 'coverage'); seg(ln, ' tool runs: ');
    link(ln, num(st.ok), go('coverage'), 'ok', 'coverage'); seg(ln, ' ok, ');
    link(ln, num(st.skipped), go('coverage'), st.skipped ? 'dim' : null, 'coverage'); seg(ln, ' skipped, ');
    link(ln, num(st.failed), go('coverage'), st.failed ? 'red' : null, 'coverage'); seg(ln, ' failed');
    const accts = (sc.accounts && sc.accounts.length) ? sc.accounts : (D.accounts || []);
    text(p, (accts.length ? accts.length + ' account(s)' : 'no live accounts') + '; last scan ' + ago(sc.finished_at || sc.started_at), 'dim');
  } else {
    text(p, 'no scan metadata: results were ingested from files.', 'dim');
    ln = line(p);
    link(ln, 'open coverage', go('coverage'), null, 'coverage');
  }

  // savings
  p = box('savings', 'savings');
  ln = line(p);
  if (D.cost && D.cost.total_monthly_savings != null) {
    link(ln, '$' + num(Math.round(D.cost.total_monthly_savings)), go('cost'), 'b', 'cost');
    seg(ln, '/month (zombies + rightsizing)');
  } else {
    seg(ln, 'no cost data; run ', 'dim');
    link(ln, 'cloud-posture cost', go('cost'), null, 'cost');
  }
}

// trendBlock: scans are newest first; the sparkline runs oldest → newest, one cell per scan,
// all severities on one scale (the largest count). Block characters only, no colour (spec v2.1).
const BLOCKS = '▁▂▃▄▅▆▇█';
const TREND_KEYS = [['new', 'new'], ['resolved', 'resolved'], ['reopened', 'reopened'], ['verified_fixed', 'verified'], ['regressed', 'regressed']];
function trendBlock(p, D) {
  const sc = (D.scans || []).slice(0, 24).reverse();
  if (!sc.length) { text(p, 'no scan history yet', 'dim'); return; }
  text(p, sc.length + ' scan(s), oldest → newest · open findings by severity', 'dim');
  const mx = Math.max(0, ...sc.map(x => Math.max(0, ...SEV.map(s => Number((x.by_severity || {})[s] || 0)))));
  SEV.forEach(s => {
    const v = sc.map(x => Number((x.by_severity || {})[s] || 0));
    const sp = v.map(n => BLOCKS[mx && n ? Math.max(1, Math.round(n / mx * 7)) : 0]).join('');
    const ln = line(p, 'nw');
    seg(ln, fit(SEV_SHORT[s].toLowerCase(), 5));
    seg(ln, sp, 'spark').setAttribute('data-sev', s);
    const cur = v[v.length - 1];
    seg(ln, ' ' + rfit(num(cur), 4));
    if (v.length > 1) {
      const d = cur - v[v.length - 2];
      seg(ln, '  ' + (d > 0 ? '+' + d : d < 0 ? '-' + (-d) : '±0'), 'dim');
    }
  });
  // Issue lifecycle per scan (r4 #12): new / resolved / reopened / verified fixed / regressed,
  // one monochrome sparkline each on a shared scale, plus the verified share of closures.
  const lc = issueTrend(D);
  if (lc.length) {
    text(p, 'Issues per scan, oldest → newest (' + lc.length + ' scan(s) with lifecycle counts)', 'dim');
    const mxL = Math.max(0, ...lc.map(t => Math.max(...TREND_KEYS.map(k => Number(t[k[0]] || 0)))));
    TREND_KEYS.forEach(([k, label]) => {
      const v = lc.map(t => Number(t[k] || 0));
      const ln = line(p, 'nw');
      seg(ln, fit(label, 9));
      seg(ln, v.map(n => BLOCKS[mxL && n ? Math.max(1, Math.round(n / mxL * 7)) : 0]).join(''), 'spark').setAttribute('data-trend', k);
      seg(ln, ' ' + rfit(num(v[v.length - 1]), 4));
    });
    const sh = lc.map(t => Number(t.verified_share || 0));
    const ln = line(p, 'nw');
    seg(ln, fit('verified%', 9));
    seg(ln, sh.map(x => BLOCKS[x > 0 ? Math.max(1, Math.round(x * 7)) : 0]).join(''), 'spark').setAttribute('data-trend', 'verified_share');
    seg(ln, ' ' + rfit(Math.round(sh[sh.length - 1] * 100) + '%', 4));
    const t = lc[lc.length - 1];
    text(p, num(t.new || 0) + ' new / ' + num(t.resolved || 0) + ' resolved / ' + num(t.reopened || 0) + ' reopened / ' +
      num(t.verified_fixed || 0) + ' verified fixed / ' + num(t.regressed || 0) + ' regressed since last scan · ' +
      Math.round(Number(t.verified_share || 0) * 100) + '% of closures verified');
    return;
  }
  // older payloads: lifecycle counts directly on the scan rows (new / resolved / reopened)
  const last = D.scans[0] || {};
  const lc0 = last.lifecycle && typeof last.lifecycle === 'object' ? last.lifecycle : last;
  if (lc0.new != null || lc0.resolved != null) {
    text(p, num(lc0.new || 0) + ' new / ' + num(lc0.resolved || 0) + ' resolved' + (lc0.reopened ? ' / ' + num(lc0.reopened) + ' reopened' : '') + ' since last scan');
  } else {
    text(p, 'scan history carries totals only (no new/resolved counts per scan)', 'dim');
  }
}

// issueTrend: the per-scan Issue trend, oldest → newest, from governance.scan_trend (payload and
// /api/governance/metrics) or the issue_trend of /api/scans rows; scans without counts skipped.
function issueTrend(D) {
  const g = D.governance && Array.isArray(D.governance.scan_trend) ? D.governance.scan_trend.map(r => r && r.issue_trend) : [];
  const s = (D.scans || []).map(r => r && r.issue_trend);
  const rows = (g.some(Boolean) ? g : s).filter(t => t && typeof t === 'object');
  return rows.slice(0, 24).reverse();
}

// coverage helpers
const COV = ['ok', 'denied', 'skipped', 'error', 'timeout'];
const COV_CLS = { ok: 'ok', denied: 'red', skipped: 'dim', error: 'red', timeout: 'red' };
function covKey(c) { return (str(c.provider) || '-') + '/' + str(c.account); }
function covCounts(list) {
  const st = {}; COV.forEach(s => { st[s] = 0; });
  list.forEach(c => { st[c.status] = (st[c.status] || 0) + 1; });
  return st;
}

// ---------------------------------------------------------------- attack paths
const cyRegistry = [];
function cssVar(name, fb) {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fb;
}
function solid(c, fb) { return (!c || c === 'transparent' || /rgba\(.*,\s*0\)$/.test(c)) ? fb : c; }
function cyColors(root) {
  const rv = document.documentElement.classList.contains('cwm-rv');
  const cs = getComputedStyle(root);
  return {
    fg: solid(cs.color, rv ? '#FFFFFF' : '#000000'),
    bg: solid(cs.backgroundColor, rv ? '#000000' : '#FFFFFF'),
    red: cssVar('--ansi-1', '#CD0000'),
    gray: cssVar('--ansi-8', '#7F7F7F'),
  };
}
function cyStyle(k) {
  return [
    { selector: 'node', style: { 'label': 'data(label)', 'font-family': FONT, 'font-size': 11, 'color': k.fg,
      'text-valign': 'bottom', 'text-margin-y': 3, 'shape': 'rectangle', 'width': 12, 'height': 12,
      'background-color': k.bg, 'border-width': 1, 'border-color': k.fg } },
    { selector: 'node[?entry]', style: { 'shape': 'ellipse', 'width': 18, 'height': 18 } },
    { selector: 'node[?target]', style: { 'shape': 'diamond', 'width': 20, 'height': 20 } },
    { selector: 'node[?up]', style: { 'text-valign': 'top', 'text-margin-y': -3 } },
    { selector: 'node[weak > 0]', style: { 'border-color': k.red } },
    { selector: 'node[?choke]', style: { 'border-width': 3 } },
    { selector: 'edge', style: { 'width': 1, 'line-color': k.fg, 'target-arrow-color': k.fg, 'target-arrow-shape': 'triangle',
      'curve-style': 'bezier', 'arrow-scale': 0.7, 'label': '', 'font-family': FONT, 'font-size': 11,
      'color': k.gray, 'text-rotation': 'autorotate', 'text-background-color': k.bg, 'text-background-opacity': 1 } },
    { selector: 'node.dim', style: { 'border-color': k.gray, 'color': k.gray } },
    { selector: 'edge.dim', style: { 'line-color': k.gray, 'target-arrow-color': k.gray, 'color': k.gray } },
    { selector: 'node.hl', style: { 'border-color': k.red, 'color': k.red, 'border-width': 2 } },
    { selector: 'node.hl[?choke]', style: { 'border-width': 3 } },
    { selector: 'edge.hl', style: { 'line-color': k.red, 'target-arrow-color': k.red, 'color': k.red, 'width': 2, 'label': 'data(kind)' } },
    { selector: 'node.hl', style: { 'z-index': 10 } },
  ];
}
function restyleGraphs() {
  for (let i = cyRegistry.length - 1; i >= 0; i--) {
    const g = cyRegistry[i];
    if (g.cy.destroyed() || !g.root.isConnected) { cyRegistry.splice(i, 1); continue; }
    g.cy.style(cyStyle(cyColors(g.root)));
  }
}
try {
  new MutationObserver(() => setTimeout(restyleGraphs, 0))
    .observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
} catch (e) { /* no MutationObserver */ }

function highlightPath(cy, p) {
  if (!cy) return;
  cy.elements().removeClass('hl dim');
  if (!p) return;
  const ids = new Set(['internet', ...(p.steps || []).map(s => s.resource)]);
  cy.elements().addClass('dim');
  cy.nodes().filter(n => ids.has(n.id())).removeClass('dim').addClass('hl');
  cy.edges().filter(e => ids.has(e.source().id()) && ids.has(e.target().id())).removeClass('dim').addClass('hl');
}

function fixLines(parent, fixes, kind, total, api, W) {
  if (!fixes || !fixes.length) { text(parent, '  none', 'dim'); return; }
  fixes.slice(0, 8).forEach(f => {
    const n = kind === 'break' ? (f.breaks || []).length : (f.reduces || []).length;
    const fid = f.finding_ids && f.finding_ids[0];
    const ln = fid ? rowLine(parent, () => api.open('finding', fid), null, 'finding') : line(parent);
    const lead = kind === 'break' ? 'breaks ' + rfit(n + '/' + total, 5) : 'lowers ' + rfit(n + '/' + total, 5);
    ln.classList.add('nw');
    const head = '  ' + lead + '  removes ' + rfit(f1(f.score_removed), 4) + '  ';
    const fw = Math.max(20, Math.min(40, W - head.length - 30));
    seg(ln, head);
    seg(ln, fit(wk(f.weakness) + ' on ' + str(f.name), fw));
    seg(ln, '  ' + fit(f.command, Math.max(10, W - head.length - fw - 2)).replace(/\s+$/, ''), 'dim');
  });
}

// pathSteps prints a path's hops; each hop's `because` (why the hop is possible) goes on its own
// grey line under the step, wrapped and indented to the step text.
function pathSteps(parent, api, p) {
  (p.steps || []).forEach(s => {
    const l2 = s.finding_id ? rowLine(parent, () => api.open('finding', s.finding_id), null, 'finding') : line(parent);
    hang(l2, 6);
    seg(l2, '  ' + rfit(s.stage, 2) + '. ' + str(s.summary || s.title));
    if (s.relation) seg(l2, '  (' + str(s.relation) + ')', 'dim');
    if (s.because) text(parent, 'because: ' + str(s.because), 'because dim');
  });
}

// pathLabel is a path's one-line label: its path Issue's title plus what it does
// (D.path_titles, the label `paths` and `plan` print — never "X → X → Privilege escalation to X");
// older payloads without it fall back to name → impact.
function pathLabel(D, p) {
  const t = D && D.path_titles && p && D.path_titles[p.id];
  return t ? str(t) : str(p && p.name) + ' → ' + str(p && p.impact);
}

// pathGroupsOf is the paths view's list: D.path_groups (one row per path Issue — entry, impact
// anchor, rule — exactly the `paths` CLI's rows, best variant first) resolved against the
// complete paths. A payload without it (older reports) gets one group per path.
function pathGroupsOf(D) {
  const ps = pathsSorted(D);
  const byId = {};
  ps.forEach(p => { byId[p.id] = p; });
  const raw = Array.isArray(D.path_groups) ? D.path_groups
    : ps.map(p => ({ issue_id: p.id, best_id: p.id, path_ids: [p.id], variants: 0, score: p.score, severity: p.severity, name: pathLabel(D, p) }));
  return raw.map(g => {
    const paths = (g.path_ids && g.path_ids.length ? g.path_ids : [g.best_id]).map(id => byId[id]).filter(Boolean);
    const best = byId[g.best_id] || paths[0];
    return Object.assign({}, g, { paths, best, variants: Math.max(0, paths.length - 1) });
  }).filter(g => g.best);
}

// pathNodeIds: the nodes one path visits, in order — the internet (unless the first hop is a
// credential entry) and each hop's resource once.
function pathNodeIds(p) {
  const st = (p && p.steps) || [];
  const out = [];
  if (!(st[0] && st[0].relation === 'entry')) out.push('internet');
  st.forEach(s => { if (s.resource && !out.includes(s.resource)) out.push(s.resource); });
  return out;
}

function dropGraph(root) {
  if (root._cy) {
    const cy = root._cy;
    root._cy = null;
    for (let i = cyRegistry.length - 1; i >= 0; i--) if (cyRegistry[i].cy === cy) cyRegistry.splice(i, 1);
    try { cy.destroy(); } catch (e) { /* ignore */ }
  }
  if (root._ro) { try { root._ro.disconnect(); } catch (e) { /* ignore */ } root._ro = null; }
}

// ---------------------------------------------------------------- graph query (W7-POLISH r5 #8)
// The `paths --from/--to/--through/--max-hops` query in the attack-paths view, over the report's
// attack paths (every hop already an engine-evaluated attack step): a path matches when it visits
// a --from node, then a --to node within --max-hops hops, passing through a --through node in
// between; the match is the segment from that --from node to the first --to node after it (the
// CLI also ends a path at its first --to node). `cloud-posture paths --from …` searches the whole
// graph, including footholds no reported path starts from; the view prints that command.
// Saved queries (--save <name>, --forget <name>) live in this browser's localStorage.
const PQ_KEY = 'nimbus.pathQueries';
const PQ_MAX_HOPS = 10;
function pqLoad() {
  try {
    const v = JSON.parse(window.localStorage.getItem(PQ_KEY) || '[]');
    return Array.isArray(v) ? v.filter(x => x && typeof x.name === 'string' && typeof x.q === 'string').slice(0, 50) : [];
  } catch (e) { return []; }
}
function pqStore(list) {
  try { window.localStorage.setItem(PQ_KEY, JSON.stringify(list.slice(0, 50))); return true; } catch (e) { return false; }
}
function parsePathQuery(s) {
  const toks = str(s).match(/"[^"]*"|'[^']*'|\S+/g) || [];
  const q = { from: '', to: '', through: '', maxHops: 6, save: '', forget: '' };
  const unq = v => str(v).replace(/^(["'])(.*)\1$/, '$2');
  for (let i = 0; i < toks.length; i++) {
    let t = toks[i], v = null;
    const eq = t.indexOf('=');
    if (t.startsWith('--') && eq > 2) { v = t.slice(eq + 1); t = t.slice(0, eq); }
    const take = () => unq(v != null ? v : (toks[++i] == null ? '' : toks[i]));
    switch (t) {
      case '--from': q.from = take(); break;
      case '--to': q.to = take(); break;
      case '--through': q.through = take(); break;
      case '--max-hops': q.maxHops = Number(take()); break;
      case '--save': q.save = take(); break;
      case '--forget': q.forget = take(); break;
      default: return { error: 'unknown word ' + JSON.stringify(t) + ': use --from, --to, --through, --max-hops, --save <name>, --forget <name>' };
    }
  }
  return q;
}
// pqSelector resolves one selector the way attackpath.ResolveSelector does: a comma-separated list
// of internet, type:<type>, class:<class>, a node id, an exact name, or a bare type.
function pqSelector(D, sel, flag) {
  const nodes = ((D.graph && D.graph.nodes) || []).slice();
  if (!nodes.some(n => n.id === 'internet')) nodes.push({ id: 'internet', type: 'internet', class: 'internet', name: 'Internet' });
  const out = new Set();
  for (const raw of str(sel).split(',')) {
    const part = raw.trim();
    if (!part) continue;
    const n0 = out.size;
    if (part.toLowerCase() === 'internet') out.add('internet');
    else if (part.startsWith('type:')) nodes.forEach(n => { if (n.type === part.slice(5)) out.add(n.id); });
    else if (part.startsWith('class:')) nodes.forEach(n => { if (str(n.class).toLowerCase() === part.slice(6).toLowerCase()) out.add(n.id); });
    else {
      nodes.forEach(n => { if (n.id === part || n.name === part) out.add(n.id); });
      if (out.size === n0) nodes.forEach(n => { if (n.type === part) out.add(n.id); });
    }
    if (out.size === n0) return { error: flag + ': selector ' + JSON.stringify(part) + ' matches no node in the graph (use internet, type:<type>, class:<class>, a node id or an exact name)' };
  }
  if (!out.size) return { error: flag + ': empty selector' };
  return { ids: out };
}
function pathQueryCmd(q) {
  const sh = v => /^[\w:./@-]+$/.test(v) ? v : "'" + v.replace(/'/g, "'\\''") + "'";
  return 'cloud-posture paths --from ' + sh(q.from) + ' --to ' + sh(q.to) + (q.through ? ' --through ' + sh(q.through) : '') + ' --max-hops ' + q.maxHops;
}
// runPathQuery: { matches: [{ path, ids }], byPath: {path id: ids}, nodes: Set, ... } or { error }.
function runPathQuery(D, q) {
  if (!q.from || !q.to) return { error: 'a path query needs both --from and --to (internet, type:<type>, class:<class>, a node id or name)' };
  if (!Number.isInteger(q.maxHops) || q.maxHops < 1 || q.maxHops > PQ_MAX_HOPS) return { error: '--max-hops must be 1..' + PQ_MAX_HOPS + ' (got ' + q.maxHops + ')' };
  const from = pqSelector(D, q.from, '--from'); if (from.error) return from;
  const to = pqSelector(D, q.to, '--to'); if (to.error) return to;
  let through = null;
  if (q.through) { through = pqSelector(D, q.through, '--through'); if (through.error) return through; }
  const matches = [], byPath = {}, seen = new Set(), nodes = new Set();
  pathsSorted(D).forEach(p => {
    const ids = pathNodeIds(p);
    for (let i = 0; i < ids.length; i++) {
      if (!from.ids.has(ids[i])) continue;
      let j = -1;
      for (let k = i + 1; k < ids.length && k - i <= q.maxHops; k++) if (to.ids.has(ids[k])) { j = k; break; }
      if (j < 0) continue;
      const seg = ids.slice(i, j + 1);
      if (through && !seg.slice(1, -1).some(id => through.ids.has(id))) continue;
      byPath[p.id] = seg;
      const key = seg.join('\u0001');
      if (!seen.has(key)) { seen.add(key); matches.push({ path: p, ids: seg }); seg.forEach(id => nodes.add(id)); }
      break;
    }
  });
  return { q, matches, byPath, nodes, from: from.ids, to: to.ids, through: through ? through.ids : null };
}

function vPaths(root, api, arg) {
  const D = api.D || {}, X = idx(D), A = analysisOf(D);
  const W = availCols(root, 120);
  const ps = pathsSorted(D);   // complete paths only; A.incomplete is never counted
  const groups = pathGroupsOf(D);   // one row per path Issue (the CLI's `paths` rows)
  const a = arg && typeof arg === 'object' ? arg : (arg ? { pathId: arg } : {});
  const cpsAll = (A.choke_points || []).slice().sort((x, y) => ((y.path_ids || []).length - (x.path_ids || []).length) || (y.score_sum - x.score_sum));
  let choke = cpsAll.find(c => c.node_id === a.choke) || null;
  let showDead = !!a.deadends && String(a.deadends) !== '0';
  let fan = !!a.graph && a.graph === 'all';   // the full fan of every path, behind [show all paths]
  let query = null;   // runPathQuery result while a graph query is active
  const inChoke = p => !choke || (choke.path_ids || []).includes(p.id);
  const inQuery = p => !query || !!query.byPath[p.id];
  const gInChoke = g => g.paths.some(inChoke);
  const groupOf = {};
  groups.forEach(g => g.paths.forEach(p => { groupOf[p.id] = g; }));
  let sel = ps.find(p => p.id === a.pathId && inChoke(p)) || null;
  const expanded = new Set();
  if (sel && groupOf[sel.id] && groupOf[sel.id].best !== sel) expanded.add(groupOf[sel.id].issue_id);
  const cw = cellW(root);
  const nInc = (A.incomplete || []).length;
  const de = A.dead_ends || {};
  const nDead = de.count != null ? de.count : (de.ids || []).length;

  const hd = line(root, 'paths-head nw');
  const chl = line(root, 'nw');
  const warn = line(root, 'red');
  // graph query box (r5 #8): the CLI's flags, Enter runs; saved queries below it.
  const qbox = el('div', 'prompt pq-box');
  const qin = el('input', 'term');
  qin.type = 'text'; qin.spellcheck = false; qin.autocomplete = 'off';
  qin.setAttribute('aria-label', 'paths query');
  qbox.append(el('span', null, 'paths> '), qin);
  root.appendChild(qbox);
  const qsaved = line(root, 'nw pq-saved');
  const qres = line(root, 'nw pq-result');

  const split = el('div', 'split');
  const LISTW = 44;
  split.style.gridTemplateColumns = Math.round(LISTW * cw) + 'px ' + Math.round(cw) + 'px 1fr';
  root.appendChild(split);
  const ROWS = Math.max(22, Math.floor((root.clientHeight || 0) * 0.5 / 15));
  const list = el('div', 'pane-l');
  list.style.height = (ROWS * 15) + 'px';
  const gap = el('div');
  const gcol = el('div');
  const gbar = line(gcol, 'nw graph-bar');
  const gbox = el('div', 'cy');
  gbox.style.height = ((ROWS - 1) * 15) + 'px';
  gcol.appendChild(gbox);
  split.append(list, gap, gcol);

  const detail = el('div');
  root.appendChild(detail);
  const rowsBy = {};      // group issue_id -> row
  const varBy = {};       // variant path id -> row
  const varBox = {};      // group issue_id -> container of its variant rows

  if (!groups.length) text(list, 'no attack paths', 'dim');
  groups.forEach(g => {
    const p = g.best;
    const ln = rowLine(list, () => select(choke ? (g.paths.find(inChoke) || p) : p), 'nw', 'path');
    ln.setAttribute('data-path', p.id);
    ln.setAttribute('data-group', g.issue_id);
    ln.setAttribute('data-hops', String((p.steps || []).length));
    rowsBy[g.issue_id] = ln;
    seg(ln, ' ');
    seg(ln, rfit(f1(g.score != null ? g.score : p.score), 4), p.weak_link ? 'dim' : 'sev-' + (g.severity || p.severity));
    const st = '(' + (p.steps || []).length + ')';
    const badge = g.variants > 0 ? '+' + g.variants : '';
    seg(ln, ' ' + fit(g.name || p.name, LISTW - 8 - st.length - (badge ? badge.length + 1 : 0)) + ' ' + st, 'pname' + (p.weak_link ? ' dim' : ''));
    if (badge) {
      const b = link(ln, ' ' + badge, () => toggleVariants(g), 'variants dim');
      b.setAttribute('data-variants', String(g.variants));
      b.title = g.variants + ' more hop variant' + (g.variants === 1 ? '' : 's') + ' of this Issue — click to list them';
      const box = el('div', 'variant-rows');
      list.appendChild(box);
      varBox[g.issue_id] = box;
      g.paths.slice(1).forEach(v => {
        const vl = rowLine(box, () => select(v), 'nw', 'path-variant');
        vl.setAttribute('data-path', v.id);
        vl.setAttribute('data-hops', String((v.steps || []).length));
        varBy[v.id] = vl;
        seg(vl, ' ');
        seg(vl, '   ' + rfit(f1(v.score), 4), v.weak_link ? 'dim' : 'sev-' + v.severity);
        const vs = '(' + (v.steps || []).length + ')';
        seg(vl, ' ' + fit('variant: ' + str(v.name), LISTW - 11 - vs.length) + ' ' + vs, 'dim');
      });
    }
  });
  function toggleVariants(g) {
    if (expanded.has(g.issue_id)) expanded.delete(g.issue_id); else expanded.add(g.issue_id);
    applyRows();
  }
  function applyRows() {
    groups.forEach(g => {
      const on = g.paths.some(p => inChoke(p) && inQuery(p));
      rowsBy[g.issue_id].classList.toggle('gone', !on);
      const box = varBox[g.issue_id];
      if (box) box.classList.toggle('gone', !expanded.has(g.issue_id) || !on);
      g.paths.slice(1).forEach(v => { if (varBy[v.id]) varBy[v.id].classList.toggle('gone', !(inChoke(v) && inQuery(v))); });
    });
  }
  function drawSaved() {
    qsaved.textContent = '';
    const list = pqLoad();
    seg(qsaved, 'saved queries: ', 'dim');
    if (!list.length) { seg(qsaved, 'none — add --save <name> to a query (e.g. --from internet --to type:aws_s3_bucket --save buckets)', 'dim'); return; }
    list.forEach((x, i) => {
      if (i) seg(qsaved, ' ');
      const l = act(qsaved, '[' + x.name + ']', () => { qin.value = x.q; runQuery(x.q); });
      l.setAttribute('data-saved', x.name);
      l.title = x.q;
    });
  }
  function drawQueryResult(msg, cls) {
    qres.textContent = '';
    if (msg) { seg(qres, msg, cls); return; }
    if (!query) return;
    const q = query.q, n = query.matches.length;
    const ng = groups.filter(g => g.paths.some(p => query.byPath[p.id])).length;
    seg(qres, 'query: ', 'b');
    seg(qres, n + ' path' + (n === 1 ? '' : 's') + ' (' + ng + ' Issue' + (ng === 1 ? '' : 's') + ') from ' + q.from + ' to ' + q.to + (q.through ? ' through ' + q.through : '') + ' (max ' + q.maxHops + ' hops) over the report\'s ' + ps.length + ' attack paths  ');
    act(qres, '[clear query]', () => { qin.value = ''; setQuery(null); }, 'pq-clear');
    qres.appendChild(el('br'));
    seg(qres, '  whole graph (footholds no reported path starts from too): ' + pathQueryCmd(q), 'dim');
  }
  function setQuery(r) {
    query = r;
    applyRows();
    record();
    drawQueryResult();
    if (query && (!sel || !query.byPath[sel.id])) {
      const m = query.matches[0];
      sel = m ? m.path : sel;
    }
    if (query) fan = false;
    select(sel, true);
  }
  function runQuery(text) {
    const q = parsePathQuery(text);
    if (q.error) { drawQueryResult('error: ' + q.error, 'red'); return; }
    if (q.forget) {
      pqStore(pqLoad().filter(x => x.name !== q.forget));
      drawSaved();
      if (!q.from && !q.to) { drawQueryResult('forgot saved query ' + q.forget, 'dim'); return; }
    }
    const r = runPathQuery(D, q);
    if (r.error) { drawQueryResult('error: ' + r.error, 'red'); return; }
    if (q.save) {
      const name = q.save.trim().slice(0, 40);
      const body = str(text).replace(/\s*--save(=|\s+)("[^"]*"|'[^']*'|\S+)/, '').trim();
      const list = pqLoad().filter(x => x.name !== name);
      list.push({ name, q: body });
      if (!pqStore(list)) { drawQueryResult('error: this browser does not keep saved queries (storage unavailable)', 'red'); }
      drawSaved();
    }
    setQuery(r);
  }
  qin.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.altKey && !e.ctrlKey && !e.metaKey) {
      e.preventDefault(); e.stopPropagation();
      const v = qin.value.trim();
      if (!v) { setQuery(null); drawQueryResult(); return; }
      runQuery(v);
    }
  });

  function drawHead() {
    hd.textContent = '';
    const nv = ps.length;
    seg(hd, groups.length + ' attack path Issue' + (groups.length === 1 ? '' : 's'), 'b');
    if (nv !== groups.length) seg(hd, ' from ' + nv + ' hop variant' + (nv === 1 ? '' : 's'), 'dim');
    if (nInc) { seg(hd, ' · '); seg(hd, nInc + ' incomplete', 'dim incomplete'); }
    seg(hd, ' · dead ends: ' + nDead + ' ');
    act(hd, showDead ? '[hide dead ends]' : '[show dead ends]', () => { showDead = !showDead; record(); drawHead(); showDetail(); }, 'deadends');
    seg(hd, '  (click an Issue to draw its path; +N lists its hop variants; a step opens its finding)', 'dim');
    chl.textContent = '';
    if (choke) {
      const n = (choke.path_ids || []).length, c = choke.closes_n == null ? n : choke.closes_n;
      const gi = groups.filter(gInChoke).length;
      seg(chl, 'choke point ', 'b');
      seg(chl, str(choke.name || choke.node_id) + ': ' + gi + ' of ' + groups.length + ' path Issues (' + n + ' of ' + nv + ' hop variants) go through it; fixing it closes ' + c + ' path' + (c === 1 ? '' : 's') + '  ');
      act(chl, '[show all paths]', () => setChoke(null), 'choke');
    }
  }
  function drawBar() {
    gbar.textContent = '';
    if (query) {
      seg(gbar, 'graph: query result (' + query.matches.length + ' paths, ' + query.nodes.size + ' nodes)  ', 'dim');
      act(gbar, '[clear query]', () => { qin.value = ''; setQuery(null); drawQueryResult(); }, 'pq-clear');
      return;
    }
    if (fan) {
      seg(gbar, 'graph: all ' + ps.length + ' paths  ', 'dim');
      act(gbar, '[selected path only]', () => { fan = false; record(); drawGraph(); }, 'fan');
    } else {
      const n = sel ? pathNodeIds(sel).length : 0;
      seg(gbar, 'graph: selected path' + (sel ? ' (' + (sel.steps || []).length + ' hops, ' + n + ' nodes)' : '') + '  ', 'dim');
      act(gbar, '[show all paths]', () => { fan = true; record(); drawGraph(); }, 'fan');
    }
  }
  function record() {
    root._cwmArg = { pathId: sel ? sel.id : '', choke: choke ? choke.node_id : '', deadends: showDead ? 1 : '', graph: fan ? 'all' : '', q: query ? qin.value.trim() : '' };
    if (api.setArg) api.setArg(root._cwmArg);
  }
  function setChoke(c) {
    choke = c;
    applyRows();
    if (sel && !inChoke(sel)) sel = null;
    if (!sel) { const g = groups.find(gInChoke); sel = g ? (g.paths.find(inChoke) || g.best) : null; }
    drawHead();
    select(sel);
  }

  function showDetail() {
    detail.textContent = '';
    blank(detail);
    if (!sel) { text(detail, 'no path selected', 'dim'); }
    else {
      const g = groupOf[sel.id];
      let ln = line(detail);
      seg(ln, 'Path ', 'b'); seg(ln, f1(sel.score), sel.weak_link ? 'dim' : 'sev-' + sel.severity);
      seg(ln, ' ' + str(sel.severity) + '  ' + pathLabel(D, sel) + '  ' + str(sel.provider) + '/' + str(sel.account));
      if (sel.weak_link) seg(ln, '  weak link (×0.5: steps joined by account only)', 'dim');
      if (sel.mitre && sel.mitre.length) seg(ln, '  [' + sel.mitre.join(' ') + ']', 'dim');
      if (g && g.paths.length > 1) {
        const k = g.paths.indexOf(sel);
        text(detail, (k === 0 ? 'best of ' : 'hop variant ' + (k + 1) + ' of ') + g.paths.length + ' hop variants of this Issue (Issue score ' + f1(g.score) + ' ' + str(g.band || '') + ')', 'dim');
      }
      pathSteps(detail, api, sel);
    }
    blank(detail);
    text(detail, 'Choke points (' + cpsAll.length + ') — click one to show only the paths through it', 'b');
    if (!cpsAll.length) text(detail, '  none', 'dim');
    cpsAll.slice(0, 12).forEach(c => {
      const l = rowLine(detail, () => setChoke(choke === c ? null : c), 'nw' + (choke === c ? ' sel' : ''), 'choke');
      l.setAttribute('data-choke', c.node_id);
      const n = (c.path_ids || []).length || c.paths || 0;
      seg(l, (choke === c ? '> ' : '  ') + fit(c.name || c.node_id, 30) + ' ' + fit(c.type, 18) + ' ' + rfit(n, 3) + (n === 1 ? ' path ' : ' paths') + '  closes ' + rfit(c.closes_n == null ? '-' : c.closes_n, 3));
      if ((c.weaknesses || []).length) seg(l, '  ' + fit(c.weaknesses.map(wk).join(', '), Math.max(10, W - 70)).replace(/\s+$/, ''), 'dim');
    });
    blank(detail);
    text(detail, 'Recommendations — these break paths', 'b');
    fixLines(detail, A.break_fixes, 'break', ps.length, api, W);
    blank(detail);
    text(detail, 'Additional — these lower risk only', 'b');
    fixLines(detail, A.reduce_fixes, 'reduce', ps.length, api, W);
    blank(detail);
    const mfs = A.min_fix_set || [];
    const mh = line(detail, 'b mfs-head');
    seg(mh, 'Cheapest fix set (' + mfs.length + ' fixes, ' + (A.min_fix_coverage || 0) + '% of path risk)  ');
    seg(mh, A.min_fix_exact ? 'exact' : 'greedy (not proven minimal)', A.min_fix_exact ? 'ok' : 'dim');
    seg(mh, '  ');
    seg(mh, A.min_fix_verified ? 'verified by re-traversal' : 'unverified', A.min_fix_verified ? 'ok' : 'red');
    fixLines(detail, mfs, 'break', ps.length, api, W);
    if (showDead) {
      blank(detail);
      text(detail, 'Dead ends (' + nDead + ') — resources with findings on no path to a crown jewel', 'b');
      const issues = issuesOf(D) || [];
      (de.ids || []).forEach(id => {
        const ni = issues.filter(i => i.resource_id === id && issueOpen(i)).length;
        const l = rowLine(detail, () => api.open('node', id), 'nw', 'node');
        l.setAttribute('data-deadend', id);
        seg(l, '  ' + fit(nodeName(X, id), 40) + ' ');
        seg(l, ni + ' open issue' + (ni === 1 ? '' : 's'), 'dim');
      });
    }
    const sup = A.suppressed || [];
    if (sup.length) {
      blank(detail);
      text(detail, 'suppressed (trusted)', 'b');
      text(detail, '  internet exposure whose sources are all trusted or private: no path starts there', 'dim');
      sup.forEach(x => {
        const l = rowLine(detail, () => api.open('node', x.node_id), 'nw', 'node');
        seg(l, '  ' + fit(x.name || x.node_id, 30) + ' ' + fit(x.exposure, 8) + ' ' + fit((x.exposure_cidrs || []).join(','), 20) + ' ');
        seg(l, str(x.reason), 'dim');
      });
    }
  }
  function select(p, quiet) {
    sel = p;
    if (!quiet) record();
    const g = p && groupOf[p.id];
    if (g && g.best !== p && !expanded.has(g.issue_id)) { expanded.add(g.issue_id); applyRows(); }
    groups.forEach(x => {
      const r = rowsBy[x.issue_id];
      const on = !!g && g === x;
      r.classList.toggle('sel', on);
      r.firstChild.textContent = on ? '>' : ' ';
    });
    Object.keys(varBy).forEach(id => {
      const r = varBy[id];
      const on = !!p && id === p.id;
      r.classList.toggle('sel', on);
      r.firstChild.textContent = on ? '>' : ' ';
    });
    if (fan) {
      highlightPath(root._cy, p);
      if (root._cy && choke) root._cy.getElementById(choke.node_id).removeClass('dim').addClass('hl');
      drawBar();
    } else {
      drawGraph();
    }
    showDetail();
  }

  // graph: by default only the selected Issue's path (its hops in order, left to right); the
  // full fan of every path behind [show all paths].
  const graph = D.graph || { nodes: [], edges: [] };
  const entry = new Set(A.entry_points || []), target = new Set(A.targets || []);
  const chokeIds = new Set(cpsAll.map(c => c.node_id));
  function mount(elements, layout, maxZoom) {
    const cy = window.cytoscape({ container: gbox, elements, style: cyStyle(cyColors(root)), layout, wheelSensitivity: 0.3, maxZoom: maxZoom || 1e50 });
    root._cy = cy;
    cyRegistry.push({ cy, root });
    cy.on('tap', 'node', e => {
      const n = X.nodeBy[e.target.id()];
      if (n && n.finding_ids && n.finding_ids[0]) api.open('finding', n.finding_ids[0]);
      else if (n) api.open('node', n.id);
    });
    if (window.ResizeObserver) {
      const ro = new ResizeObserver(() => { if (!cy.destroyed()) { cy.resize(); cy.fit(undefined, 24); cy.center(); } });
      ro.observe(gbox);
      root._ro = ro;
    }
    return cy;
  }
  function drawGraph() {
    dropGraph(root);
    gbox.textContent = '';
    warn.textContent = '';
    drawBar();
    if (!window.cytoscape) { text(gbox, 'graph library unavailable — paths are listed on the left', 'dim'); return; }
    if (query) {
      if (!query.matches.length) { text(gbox, 'no path matches the query', 'dim'); return; }
      const qids = [...query.nodes];
      const elements = qids.map(id => {
        const n = X.nodeBy[id];
        const nm = (n && n.name) || (id === 'internet' ? 'internet' : nodeName(X, id));
        return { data: { id, label: fit(String(nm).split('/').pop(), 18).replace(/\s+$/, ''), weak: (n && n.weaknesses || []).length,
          entry: query.from.has(id), target: query.to.has(id), choke: !!(query.through && query.through.has(id)) }, classes: 'hl' };
      });
      const seenE = new Set();
      query.matches.forEach(m => {
        for (let i = 1; i < m.ids.length; i++) {
          const k = m.ids[i - 1] + '\u0001' + m.ids[i];
          if (seenE.has(k)) continue;
          seenE.add(k);
          const st = (m.path.steps || []).find(x => x.resource === m.ids[i]);
          elements.push({ data: { id: 'q' + seenE.size, source: m.ids[i - 1], target: m.ids[i], kind: str(st && st.relation) }, classes: 'hl' });
        }
      });
      const roots = qids.filter(id => query.from.has(id));
      const cy = mount(elements, { name: 'breadthfirst', directed: true, roots: roots.length ? roots : undefined, spacingFactor: 1.25, padding: 12, avoidOverlap: true }, 1.4);
      cy.fit(undefined, 24);
      return;
    }
    if (!fan) {
      if (!sel) { text(gbox, 'select an Issue to draw its path', 'dim'); return; }
      const ids = pathNodeIds(sel);
      const stepOf = {};
      (sel.steps || []).forEach(s => { if (!stepOf[s.resource]) stepOf[s.resource] = s; });
      const label = id => {
        const n = X.nodeBy[id];
        const s = stepOf[id];
        const nm = (n && n.name) || (id === 'internet' ? 'internet' : nodeName(X, id, s && s.finding_id ? [s.finding_id] : []));
        return fit(String(nm).split('/').pop(), 24).replace(/\s+$/, '');
      };
      const last = ids[ids.length - 1];
      const elements = ids.map((id, i) => {
        const n = X.nodeBy[id];
        // staggered left to right: upper nodes label above, lower nodes below, so node labels
        // and the hop (edge) labels between them never share a line.
        return { data: { id, label: label(id), weak: (n && n.weaknesses || []).length, entry: i === 0, target: id === last, choke: chokeIds.has(id), up: i % 2 === 0 },
          position: { x: i * 200, y: (i % 2) * 90 }, classes: 'hl' };
      });
      for (let i = 1; i < ids.length; i++) {
        const s = stepOf[ids[i]];
        elements.push({ data: { id: 'pe' + i, source: ids[i - 1], target: ids[i], kind: str(s && s.relation) }, classes: 'hl' });
      }
      const cy = mount(elements, { name: 'preset', padding: 24 }, 1.4);   // a 1-hop path must not fill the box
      cy.fit(undefined, 24);
      cy.center();
      return;
    }
    if (!graph.nodes || graph.nodes.length < 2) { text(gbox, 'no graph: run a collector scan or ingest Prowler/Steampipe output', 'dim'); return; }
    const inPaths = new Set(['internet']);
    ps.forEach(p => (p.steps || []).forEach(s => inPaths.add(s.resource)));
    let nodes = graph.nodes.filter(n => inPaths.has(n.id) || (n.weaknesses && n.weaknesses.length) || n.class === 'internet');
    const CAP = 400;
    if (nodes.length > CAP) {
      warn.textContent = 'warning: graph capped at ' + CAP + ' of ' + nodes.length + ' nodes';
      nodes = nodes.slice(0, CAP);
    }
    const ids = new Set(nodes.map(n => n.id));
    const edges = (graph.edges || []).filter(e => ids.has(e.from) && ids.has(e.to) && e.kind !== 'contains');
    const elements = nodes.map(n => ({ data: {
      id: n.id, label: fit(n.name || n.id, 13).replace(/\s+$/, ''), weak: (n.weaknesses || []).length,
      entry: entry.has(n.id) || n.class === 'internet', target: target.has(n.id), choke: chokeIds.has(n.id) } }))
      .concat(edges.map((e, i) => ({ data: { id: 'e' + i, source: e.from, target: e.to, kind: str(e.kind) } })));
    const roots = ids.has('internet') ? ['internet'] : undefined;
    const cy = mount(elements, { name: 'breadthfirst', directed: true, roots, spacingFactor: 1.25, padding: 12, avoidOverlap: true });
    highlightPath(cy, sel);
    if (choke) cy.getElementById(choke.node_id).removeClass('dim').addClass('hl');
  }
  drawSaved();
  if (a.q) {   // a query in the hash (reload, back/forward) runs again
    qin.value = str(a.q);
    const r0 = runPathQuery(D, parsePathQuery(a.q));
    if (!r0.error) { query = r0; fan = false; if (!sel || !query.byPath[sel.id]) sel = query.matches[0] ? query.matches[0].path : sel; }
  }
  applyRows();
  drawQueryResult();
  // The first Issue (or the choke point's first) is selected by default.
  let quiet = false;
  if (!sel) { const g = groups.find(gInChoke); sel = g ? (choke ? (g.paths.find(inChoke) || g.best) : g.best) : null; quiet = true; }
  drawHead();
  if (fan) drawGraph();
  select(sel, quiet);
  const sr = sel && (varBy[sel.id] || (groupOf[sel.id] && rowsBy[groupOf[sel.id].issue_id]));
  if (sr) sr.scrollIntoView({ block: 'nearest' });
}

// ---------------------------------------------------------------- risk
function vRisk(root, api) {
  const D = api.D || {};
  const W = availCols(root, 120);
  const rs = D.risk || [];
  text(root, fit('Top risks: severity × context (exposure, identity, data, criticality, CVEs, compliance, change, ownership, paths)', W).replace(/\s+$/, ''), 'dim nw');
  if (!rs.length) { text(root, 'no ranked findings yet; run cloud-posture prioritize'); return; }
  const cols = [
    { h: 'SCORE', w: 5, r: 1, get: r => f1(r.risk_score), cls: r => 'band-' + r.band },
    { h: 'BAND', w: 8, get: r => r.band, cls: r => 'band-' + r.band },
    { h: 'FINDING', w: 0, get: r => r.finding.title },
    { h: 'RESOURCE', w: 24, get: r => (r.finding.resource && (r.finding.resource.name || r.finding.resource.id)) },
    { h: 'OWNER', w: 12, get: r => r.owner || '-' },
    { h: 'DUE', w: 15, get: r => str(r.due_at).slice(0, 10) + ' ' + r.sla_days + 'd' },
    { h: 'PATHS', w: 5, r: 1, get: r => r.attack_paths || 0 },
  ];
  const Wd = table(root, cols, [], W);
  const indent = Wd[0] + Wd[1] + 2;
  rs.forEach(r => {
    const blk = el('div', 'row');
    blk.setAttribute('data-open', 'finding');
    blk.addEventListener('click', e => { e.stopPropagation(); api.open('finding', r.finding.id); });
    root.appendChild(blk);
    const ln = line(blk, 'nw');
    cols.forEach((c, i) => {
      if (i) seg(ln, ' ');
      seg(ln, c.r ? rfit(c.get(r), Wd[i]) : fit(c.get(r), Wd[i]), c.cls ? c.cls(r) : null);
    });
    const room = Math.max(20, W - indent);
    let cur = '';
    const flush = () => { if (cur) { const rl = line(blk, 'dim nw'); rl.textContent = ' '.repeat(indent) + cur; cur = ''; } };
    (r.reasons || []).forEach(x => {
      const chip = fit('[' + str(x) + ']', room).replace(/\s+$/, '');
      if (cur && cur.length + 1 + chip.length > room) flush();
      cur = cur ? cur + ' ' + chip : chip;
    });
    flush();
  });
}

// ---------------------------------------------------------------- findings
function parseFilter(s) {
  const o = { sev: '', prov: '', acct: '', src: '', status: 'FAIL', q: '', ctl: '' };
  const free = [];
  str(s).trim().split(/\s+/).filter(Boolean).forEach(tok => {
    const m = tok.match(/^(sev|prov|acct|src|status|q|ctl)=(.*)$/i);
    if (m) o[m[1].toLowerCase()] = m[2];
    else free.push(tok);
  });
  if (free.length) o.q = (o.q ? o.q + ' ' : '') + free.join(' ');
  if (/^(all|\*|any)$/i.test(o.status)) o.status = '';
  return o;
}
function filterString(o) {
  const parts = [];
  if (o.sev) parts.push('sev=' + o.sev);
  if (o.prov) parts.push('prov=' + o.prov);
  if (o.acct) parts.push('acct=' + o.acct);
  if (o.src) parts.push('src=' + o.src);
  if (o.ctl) parts.push('ctl=' + o.ctl);
  parts.push('status=' + (o.status || 'all'));
  if (o.q) parts.push('q=' + o.q);
  return parts.join(' ');
}
// The findings section lists Issues (one per check × resource); the same filter applies to the
// raw findings, which are counted on the secondary line and listed with [show findings].
// Dead-end Issues (resource on no path to a crown jewel) are hidden until [show dead ends].
function vFindings(root, api, arg) {
  const D = api.D || {};
  let fs = D.findings || [];
  arg = (arg && typeof arg === 'object') ? arg : (arg ? { q: String(arg) } : {});
  const init = {
    sev: str(arg.severity).toUpperCase(), prov: str(arg.provider), acct: str(arg.account), src: str(arg.source),
    status: arg.status != null ? str(arg.status).toUpperCase() : (arg.ids ? '' : 'FAIL'), q: str(arg.q),
    ctl: str(arg.control),
  };
  if (init.status === 'ALL') init.status = '';
  if (arg.filter != null) Object.assign(init, parseFilter(arg.filter));
  const ids = Array.isArray(arg.ids) ? new Set(arg.ids) : null;
  const ctlArg = init.ctl;
  let view = str(arg.view) === 'findings' ? 'findings' : 'issues';
  let showDead = !!arg.deadends && String(arg.deadends) !== '0';

  const top = el('div', 'sticky');
  root.appendChild(top);
  const pr = el('div', 'prompt');
  pr.appendChild(el('span', null, 'filter> '));
  const inp = el('input', 'term');
  inp.type = 'text'; inp.spellcheck = false; inp.autocomplete = 'off';
  inp.setAttribute('aria-label', 'filter');
  inp.setAttribute('data-role', 'filter');
  inp.value = filterString(init);
  pr.appendChild(inp);
  top.appendChild(pr);
  const count = line(top, 'dim count');
  const tog = line(top, 'nw');
  const body = el('div');
  root.appendChild(body);

  function apply() {
    fs = D.findings || [];
    const W = availCols(root, 120);
    const X = idx(D);
    const issues = issuesOf(D);
    const mode = issues && view === 'issues' ? 'issues' : 'findings';
    const o = parseFilter(inp.value);
    root._cwmArg = { filter: inp.value, ids: ids && o.ctl === ctlArg ? arg.ids : undefined, control: o.ctl,
      view: view === 'findings' ? 'findings' : '', deadends: showDead ? 1 : '' };
    // the filter is reflected in the hash query (spec v2.2): #findings?severity=HIGH&provider=aws
    if (api.setArg) {
      const st = o.status ? o.status.toUpperCase() : 'all';
      api.setArg({ severity: o.sev.toUpperCase(), provider: o.prov, account: o.acct, source: o.src,
        status: st === 'FAIL' ? '' : st, q: o.q, control: o.ctl, view: root._cwmArg.view, deadends: root._cwmArg.deadends });
    }
    const q = o.q.toLowerCase();
    let ctlFw = '', ctlId = '';
    if (o.ctl) { const i = o.ctl.indexOf(':'); ctlFw = i > 0 ? o.ctl.slice(0, i) : ''; ctlId = i > 0 ? o.ctl.slice(i + 1) : o.ctl; }
    const useIds = ids && o.ctl === ctlArg;
    const ctlHit = f => (useIds ? ids.has(f.id) : Object.keys(f.compliance || {}).some(k => (!ctlFw || k === ctlFw) && (f.compliance[k] || []).includes(ctlId)));
    const rows = fs.filter(f =>
      (!o.status || f.status === o.status.toUpperCase()) &&
      (!o.sev || f.severity === o.sev.toUpperCase()) &&
      (!o.prov || f.provider === o.prov) &&
      (!o.acct || f.account === o.acct || acctOf(f) === o.acct) &&
      (!o.src || f.source === o.src) &&
      (!o.ctl || ctlHit(f)) &&
      (!q || (str(f.title) + ' ' + str(f.canonical_id) + ' ' + str(f.resource && f.resource.id) + ' ' + str(f.resource && f.resource.name) + ' ' + f.id + ' ' + str(f.check_id)).toLowerCase().includes(q)));
    const SO = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    rows.sort((a, b) => ((a.status === 'FAIL' ? 0 : 1) - (b.status === 'FAIL' ? 0 : 1)) || ((SO[a.severity] ?? 9) - (SO[b.severity] ?? 9)));
    body.textContent = '';
    tog.textContent = '';
    if (mode === 'issues') {
      const dead = deadFn(D);
      const st = o.status.toUpperCase();
      let hidden = 0;
      const shown = issues.filter(i => {
        const ev = (i.finding_ids || []).map(x => X.byId[x]).filter(Boolean);
        const ok = (!st || (st === 'FAIL' ? issueOpen(i) : str(i.state).toUpperCase() === st)) &&
          (!o.sev || i.severity === o.sev.toUpperCase()) &&
          (!o.prov || i.provider === o.prov) &&
          (!o.acct || i.account === o.acct || ev.some(f => acctOf(f) === o.acct)) &&
          (!o.src || (i.sources || []).includes(o.src)) &&
          (!o.ctl || ev.some(ctlHit)) &&
          (!q || q.split(/\s+/).every(w => (str(i.title) + ' ' + str(i.canonical_id) + ' ' + str(i.resource_id) + ' ' + i.id + ' ' + str(i.owner) + (i.overdue ? ' overdue' : '') + ' ' + ev.map(f => str(f.title) + ' ' + str(f.resource && f.resource.name)).join(' ')).toLowerCase().includes(w)));
        if (ok && !showDead && dead(i.resource_id)) { hidden++; return false; }
        return ok;
      });
      shown.sort((a, b) => ((issueOpen(a) ? 0 : 1) - (issueOpen(b) ? 0 : 1)) || ((SO[a.severity] ?? 9) - (SO[b.severity] ?? 9)) ||
        ((isCombo(b) ? 1 : 0) - (isCombo(a) ? 1 : 0)) || str(a.title).localeCompare(str(b.title)));
      count.textContent = shown.length + ' issues shown of ' + issues.length + ' · findings: ' + rows.length + ' shown of ' + fs.length;
      const de = analysisOf(D).dead_ends || {};
      seg(tog, 'dead ends: ' + (de.count || 0) + ' resources' + (hidden ? ', ' + hidden + ' issue' + (hidden === 1 ? '' : 's') + ' hidden' : '') + '  ', 'dim');
      act(tog, showDead ? '[hide dead ends]' : '[show dead ends]', () => { showDead = !showDead; apply(); }, 'deadends');
      seg(tog, '  ');
      act(tog, '[show findings]', () => { view = 'findings'; apply(); }, 'view');
      if (shown.length > 500) text(body, 'warning: showing the first 500 of ' + shown.length + ' matches; narrow the filter', 'red');
      issueTable(body, shown.slice(0, 500), W, api, X, dead);
      return;
    }
    count.textContent = rows.length + ' shown of ' + fs.length + (issues ? ' · issues: ' + issues.filter(issueOpen).length + ' open' : '');
    if (issues) act(tog, '[show issues]', () => { view = 'issues'; apply(); }, 'view');
    if (rows.length > 500) text(body, 'warning: showing the first 500 of ' + rows.length + ' matches; narrow the filter', 'red');
    table(body, [
      { h: 'SEV', w: 8, get: f => f.status === 'FAIL' ? f.severity : f.status, cls: f => f.status === 'PASS' ? 'sev-PASS' : f.status === 'FAIL' ? 'sev-' + f.severity : 'dim' },
      { h: 'FINDING', w: 0, get: f => f.title },
      { h: 'RESOURCE', w: 24, get: f => (f.resource && (f.resource.name || f.resource.id)) + (f.file ? ' ' + f.file + ':' + (f.line_start || 0) : '') },
      { h: 'PROVIDER/ACCOUNT', w: 22, get: f => str(f.provider) + '/' + acctOf(f), opt: 1 },
      { h: 'SOURCE', w: 9, get: f => f.source, opt: 2 },
      { h: 'COMPLIANCE', w: 18, get: f => Object.keys(f.compliance || {}).join(','), opt: 3 },
    ], rows.slice(0, 500), W, f => api.open('finding', f.id), 'finding');
  }
  inp.addEventListener('input', apply);
  inp.addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); apply(); }
    else if (e.ctrlKey && !e.altKey && e.code === 'KeyU') { e.preventDefault(); inp.value = ''; apply(); }
  });
  apply();
  // live updates and re-layout refresh the table in place; the filter input is never replaced.
  root._cwmRefresh = () => { const st = root.scrollTop; apply(); root.scrollTop = st; };
}

// issueTable: one row block per Issue; a combination Issue gets a red "toxic" tag and a second
// line listing the weaknesses that combine.
function issueTable(parent, rows, width, api, X, dead) {
  const cols = fitCols([
    { k: 'sev', h: 'SEV', w: 8 }, { k: 'kind', h: 'KIND', w: 8 }, { k: 'title', h: 'ISSUE', w: 0 },
    { k: 'res', h: 'RESOURCE', w: 24, opt: 1 }, { k: 'due', h: 'DUE', w: 10, opt: 1 }, { k: 'own', h: 'OWNER', w: 18, opt: 3 },
    { k: 'acct', h: 'PROVIDER/ACCOUNT', w: 22, opt: 4 },
    { k: 'src', h: 'SOURCES', w: 12, opt: 5 }, { k: 'ev', h: 'EV', w: 3, r: 1, opt: 2 },
  ], width, 30);
  const fixed = cols.reduce((a, c) => a + (c.w || 0), 0) + (cols.length - 1);
  const W = {};
  cols.forEach(c => { W[c.k] = c.w || Math.max(8, width - fixed); });
  const hd = line(parent, 'b nw thead');
  hd.textContent = cols.map(c => (c.r ? rfit(c.h, W[c.k]) : fit(c.h, W[c.k]))).join(' ').replace(/\s+$/, '');
  rows.forEach(i => {
    const blk = el('div', 'row');
    blk.setAttribute('data-open', 'issue');
    blk.setAttribute('data-issue', str(i.id));
    blk.addEventListener('click', e => { e.stopPropagation(); api.open('issue', i.id); });
    parent.appendChild(blk);
    const ln = line(blk, 'nw');
    const op = issueOpen(i);
    const cell = {
      sev: () => seg(ln, fit(op ? i.severity : str(i.state).toUpperCase(), W.sev), op ? 'sev-' + i.severity : 'dim'),
      kind: () => {
        if (isCombo(i)) { seg(ln, 'toxic', 'toxic red b'); seg(ln, ' '.repeat(W.kind - 5)); }
        else if (dead(i.resource_id)) seg(ln, fit('dead end', W.kind), 'dim');
        else seg(ln, fit('', W.kind));
      },
      title: () => seg(ln, fit(i.title || i.canonical_id, W.title)),
      res: () => seg(ln, fit(nodeName(X, i.resource_id, i.finding_ids), W.res)),
      // due: the governance due date; an open Issue past it gets the red OVERDUE badge.
      due: () => {
        if (i.overdue && op) { seg(ln, 'OVERDUE', 'overdue red b'); seg(ln, ' '.repeat(Math.max(0, W.due - 7))); }
        else seg(ln, fit(i.due_at ? String(i.due_at).slice(0, 10) : '-', W.due), 'dim');
      },
      own: () => seg(ln, fit(str(i.owner) || '-', W.own), i.owner ? null : 'dim'),
      acct: () => seg(ln, fit(str(i.provider) + '/' + str(i.account), W.acct)),
      src: () => seg(ln, fit((i.sources || []).join(','), W.src), 'dim'),
      ev: () => seg(ln, rfit((i.finding_ids || []).length, W.ev)),
    };
    cols.forEach((c, n) => { if (n) seg(ln, ' '); cell[c.k](); });
    if (isCombo(i)) {
      const wl = line(blk, 'nw dim');
      const ind = W.sev + W.kind + 2;
      seg(wl, ' '.repeat(ind));
      seg(wl, fit(comboWeak(i, X).map(wk).join(' + '), Math.max(10, width - ind)).replace(/\s+$/, ''), 'weak');
    }
  });
}

// ---------------------------------------------------------------- finding detail
function kv(parent, k, v, onClick, cls) {
  if (v == null || v === '') return;
  const ln = onClick ? rowLine(parent, onClick, null, 'drill') : line(parent);
  seg(ln, fit(k, 14), 'b');
  seg(ln, str(v), cls);
  return ln;
}
function para(parent, s) {
  if (!str(s)) return;
  String(s).split(/\n/).forEach(p => { if (p.trim()) text(parent, p, 'prose'); });
}
// explainBlock prints the published score's explanation (Track F): base, each scored factor as
// "name ×mult — reason", not-scored factors and other gaps under "missing", and the top paths.
function explainBlock(parent, api, rr, from) {
  blank(parent);
  let ln = line(parent, 'b');
  seg(ln, 'Risk score ');
  seg(ln, f1(rr.risk_score), 'band-' + rr.band);
  seg(ln, ' (' + str(rr.band) + ')  owner ' + (rr.owner || '-') + '  due ' + str(rr.due_at).slice(0, 10) + ' (' + rr.sla_days + 'd SLA)');
  if (from) text(parent, '  ' + from, 'dim');
  const x = rr.explanation;
  if (!x) { (rr.reasons || []).forEach(r => text(parent, '  - ' + str(r))); return; }
  hang(text(parent, '  base ' + f1(x.base) + ' — ' + str(x.base_reason)), 4);
  const fac = x.factors || [];
  const scored = fac.filter(f => f.status !== 'not scored');
  const unscored = fac.filter(f => f.status === 'not scored');
  const nw = Math.min(22, Math.max(8, ...fac.map(f => str(f.name).length)));
  scored.forEach(f => {
    ln = hang(line(parent), nw + 11);
    seg(ln, '  ' + fit(f.name, nw) + ' ');
    seg(ln, '×' + Number(f.multiplier).toFixed(2), Number(f.multiplier) !== 1 ? 'b' : null);
    seg(ln, ' — ' + str(f.reason));
    if ((f.evidence || []).length) {
      const ev = text(parent, (f.evidence || []).map(str).join(', '), 'because dim');
      ev.style.paddingLeft = (nw + 11) + 'ch';
    }
  });
  const miss = unscored.map(f => str(f.name) + ' — ' + str(f.reason));
  (x.missing || []).forEach(m => { if (!unscored.some(f => str(m).startsWith(str(f.name)))) miss.push(str(m)); });
  if (miss.length) {
    text(parent, '  missing', 'b');
    miss.forEach(m => hang(text(parent, '    ' + m, 'dim'), 6));
  }
  const tp = x.top_paths || [];
  if (tp.length) {
    text(parent, '  top paths', 'b');
    tp.forEach(p => {
      const l = rowLine(parent, () => api.open('paths', { pathId: p.id }), 'nw', 'paths');
      l.setAttribute('data-top', '1');
      seg(l, '    ' + rfit(f1(p.score), 4) + '  ' + str(p.name));
    });
  }
}
function scoreFooter(parent, rr) {
  const v = rr && (rr.score_version || (rr.explanation && rr.explanation.version));
  if (!v) return;
  blank(parent);
  text(parent, 'score version ' + v, 'dim');
}
// relatedPaths lists the paths an evidence set sits on; the top one is printed hop by hop.
function relatedPaths(root, api, D, fids, W) {
  const set = new Set(fids);
  const rel = pathsSorted(D).filter(p => (p.finding_ids || []).some(x => set.has(x)) || (p.steps || []).some(s => set.has(s.finding_id)));
  if (!rel.length) return;
  blank(root);
  text(root, 'Attack paths (' + rel.length + ')', 'b');
  rel.slice(0, 12).forEach(p => {
    const l2 = rowLine(root, () => api.open('paths', { pathId: p.id }), 'nw', 'paths');
    seg(l2, '  ');
    seg(l2, rfit(f1(p.score), 4), p.weak_link ? 'dim' : 'sev-' + p.severity);
    seg(l2, '  ' + fit(pathLabel(D, p), W - 8).replace(/\s+$/, ''), p.weak_link ? 'dim' : null);
  });
  text(root, '  top path, hop by hop:', 'dim');
  pathSteps(root, api, rel[0]);
}
function vFinding(root, api, arg) {
  const D = api.D || {}, X = idx(D);
  const W = availCols(root, 100);
  const id = arg && typeof arg === 'object' ? arg.id : arg;
  const f = X.byId[id];
  if (!f) { if (api.setTitle) api.setTitle('finding'); text(root, 'finding ' + str(id) + ': not found'); return; }
  if (api.setTitle) api.setTitle(str(f.title));
  let ln = line(root);
  seg(ln, str(f.severity), 'sev-' + f.severity);
  seg(ln, ' · ');
  seg(ln, str(f.status), f.status === 'PASS' ? 'sev-PASS' : f.status === 'FAIL' ? 'red' : 'dim');
  seg(ln, '  ' + str(f.canonical_id));
  blank(root);
  const res = f.resource || {};
  const node = X.nodeBy[res.id];
  kv(root, 'resource', res.id, node ? () => api.open('node', res.id) : null);
  kv(root, 'name', res.name);
  kv(root, 'type', res.type);
  kv(root, 'provider', str(f.provider) + ' / ' + acctOf(f), () => api.open('findings', { provider: f.provider, account: f.account, view: 'findings' }));
  kv(root, 'region', f.region);
  kv(root, 'source', str(f.source) + ' (' + str(f.check_id) + ')', () => api.open('findings', { source: f.source, view: 'findings' }));
  if (f.file) kv(root, 'file', f.file + ':' + (f.line_start || 0) + (f.line_end ? '-' + f.line_end : ''));
  kv(root, 'first seen', f.first_seen);
  kv(root, 'last seen', f.last_seen);
  kv(root, 'weaknesses', (f.weaknesses || []).map(wk).join(', '));
  kv(root, 'id', f.id);
  if (f.tags && Object.keys(f.tags).length) kv(root, 'tags', Object.keys(f.tags).map(k => k + '=' + str(f.tags[k])).join(' '));
  const ofIssues = (issuesOf(D) || []).filter(i => (i.finding_ids || []).includes(f.id));
  ofIssues.forEach(i => {
    const l = rowLine(root, () => api.open('issue', i.id), 'nw', 'issue');
    seg(l, fit('evidence of', 14), 'b');
    if (isCombo(i)) { seg(l, 'toxic', 'red b'); seg(l, ' '); }
    seg(l, str(i.title || i.canonical_id));
  });
  if (f.description) { blank(root); text(root, 'Risk', 'b'); para(root, f.description); }
  if (f.remediation) { blank(root); text(root, 'Remediation', 'b'); para(root, f.remediation); }
  blank(root);
  text(root, 'Fix', 'b');
  text(root, '  $ cloud-posture fix --id ' + f.id + ' --generate-terraform');
  text(root, '  $ cloud-posture fix --finding ' + str(f.canonical_id) + ' --format terraform|cloudformation|bicep|kubernetes');
  relatedPaths(root, api, D, [f.id], W);
  const comp = f.compliance || {};
  if (Object.keys(comp).length) {
    blank(root);
    text(root, 'Compliance', 'b');
    Object.keys(comp).sort().forEach(k => {
      const l2 = rowLine(root, () => api.open('compliance', { framework: k }), null, 'compliance');
      seg(l2, '  ' + fit(k, 14) + (comp[k] || []).join(', '));
    });
  }
  const rr = X.riskBy[f.id];
  if (rr) explainBlock(root, api, rr);
  blank(root);
  const q = 'SELECT canonical_id, severity, status, source FROM findings WHERE resource_id = ' + sqlq(res.id);
  ln = rowLine(root, () => api.open('sql', { sql: q, run: true }), null, 'sql');
  seg(ln, fit('Open query', 14), 'b');
  seg(ln, q);
  scoreFooter(root, rr);
}

// ---------------------------------------------------------------- issue detail
function vIssue(root, api, arg) {
  const D = api.D || {}, X = idx(D);
  const W = availCols(root, 100);
  const id = arg && typeof arg === 'object' ? arg.id : arg;
  const is = (D.issues || []).find(i => i && i.id === id);
  if (!is) { if (api.setTitle) api.setTitle('issue'); text(root, 'issue ' + str(id) + ': not found'); return; }
  if (api.setTitle) api.setTitle(str(is.title || is.canonical_id));
  const op = issueOpen(is);
  let ln = line(root);
  seg(ln, str(is.severity), 'sev-' + is.severity);
  seg(ln, ' · ');
  seg(ln, str(is.state || 'open'), op ? 'red' : 'ok');
  if (isCombo(is)) { seg(ln, '  '); seg(ln, 'toxic', 'toxic red b'); }
  seg(ln, '  ' + str(is.canonical_id));
  blank(root);
  const fids = is.finding_ids || [];
  kv(root, 'resource', is.resource_id, X.nodeBy[is.resource_id] ? () => api.open('node', is.resource_id) : null);
  kv(root, 'name', nodeName(X, is.resource_id, fids));
  kv(root, 'provider', str(is.provider) + ' / ' + str(is.account), () => api.open('findings', { provider: is.provider, account: is.account, deadends: 1 }));
  kv(root, 'kind', isCombo(is) ? 'combination: these weaknesses together on one resource' : 'single check on one resource');
  if (isCombo(is)) kv(root, 'weaknesses', comboWeak(is, X).map(wk).join(' + '), null, 'red');
  kv(root, 'sources', (is.sources || []).join(', ') || '-');
  const ns = (is.sources || []).length;
  kv(root, 'confidence', Number(is.confidence || 0).toFixed(2) + '  (' + ns + ' independent source' + (ns === 1 ? '' : 's') + ' agree)');
  kv(root, 'first seen', is.first_seen);
  kv(root, 'last seen', is.last_seen);
  if (is.resolved_at) kv(root, 'resolved', is.resolved_at, null, 'ok');
  const rcj = analysisOf(D).reaches_crown_jewel || {};
  if (rcj[is.resource_id] === true) kv(root, 'crown jewel', 'reachable: on a complete attack path', null, 'red');
  else if (rcj[is.resource_id] === false) kv(root, 'crown jewel', 'not reachable (dead end)', null, 'dim');
  kv(root, 'id', is.id);
  const pg = (D.issue_pages || {})[is.id];
  if (pg) issueGovernance(root, pg);
  // Score journey (W7-VERIFY r5 #11): the same one-line sparkline `issues show` prints.
  const sh = pg && pg.score_history;
  if (sh && sh.line) kv(root, 'score', 'journey ' + str(sh.line));
  else if (pg) kv(root, 'score', 'journey: no scored scan recorded yet', null, 'dim');
  blank(root);
  text(root, 'Evidence (' + fids.length + ' finding' + (fids.length === 1 ? '' : 's') + ')', 'b');
  if (!fids.length) text(root, '  none', 'dim');
  fids.forEach(fid => {
    const f = X.byId[fid];
    const l = rowLine(root, () => api.open('finding', fid), 'nw', 'finding');
    l.setAttribute('data-ev', fid);
    seg(l, '  ');
    if (!f) { seg(l, fid + ' (not in this report)', 'dim'); return; }
    seg(l, fit(f.status === 'FAIL' ? f.severity : f.status, 9), f.status === 'PASS' ? 'sev-PASS' : f.status === 'FAIL' ? 'sev-' + f.severity : 'dim');
    seg(l, fit(f.source, 12) + ' ', 'dim');
    seg(l, fit(f.title, Math.max(10, W - 24)).replace(/\s+$/, ''));
  });
  relatedPaths(root, api, D, fids, W);
  if (pg) issuePageBlock(root, api, pg, is, W);
  const rr = bestRisk(X, fids);
  if (rr) explainBlock(root, api, rr, fids.length > 1 ? 'highest-scored evidence: ' + str(rr.finding.title) : '');
  scoreFooter(root, rr);
}
// issueGovernance: owner / SLA / due, confidence, suppression and ticket of the Issue page
// record (D.issue_pages, built by the CLI from internal/server.BuildIssuePage).
function issueGovernance(root, pg) {
  const o = pg.owner || {};
  kv(root, 'owner', (o.owner || 'unassigned') + '  (' + str(o.source) + (o.rule ? ', rule ' + o.rule : '') + ')', null, o.owner ? null : 'dim');
  if (o.why) kv(root, 'why', str(o.why), null, 'dim');
  const due = o.due_at ? String(o.due_at).slice(0, 10) : '-';
  const grace = o.grace_until ? ', grace until ' + String(o.grace_until).slice(0, 10) + (o.past_grace ? ' (PAST GRACE)' : '') : '';
  kv(root, 'SLA', (o.sla_days || 0) + ' days, due ' + due + (o.overdue ? '  OVERDUE' : '') + grace, null, o.overdue ? 'red' : null);
  const c = pg.confidence || {};
  if (c.label) kv(root, 'evidence', c.label + ' - ' + str(c.reason), null, 'dim');
  const sp = pg.suppression || {};
  if (sp.suppressed || sp.reason) kv(root, 'suppressed', str(sp.reason) + ' (expires ' + (sp.expires_at ? String(sp.expires_at).slice(0, 10) : '-') + ', approved by ' + (sp.approved_by || '-') + ')' + (sp.expired ? ' EXPIRED' : ''), null, 'red');
  else kv(root, 'suppressed', 'no', null, 'dim');
  const tk = pg.tickets || [];
  if (tk.length) tk.forEach(t => kv(root, 'ticket', str(t.channel) + ' ' + str(t.ref) + (t.url && t.url !== t.ref ? ' ' + str(t.url) : '') + (t.state ? ' (' + t.state + ')' : '')));
  else kv(root, 'ticket', 'none recorded', null, 'dim');
}
// issuePageBlock: hops with because (path Issues), linked Issues, the fix with its remediation
// phases (prerequisite, snapshot, fix, verify, rollback) and the timeline.
function issuePageBlock(root, api, pg, is, W) {
  const hops = pg.hops || [];
  if (is.kind === 'path' && hops.length) {
    blank(root);
    text(root, 'Hops (best path' + ((pg.paths || []).length > 1 ? ', ' + pg.paths.length + ' hop variants' : '') + ')', 'b');
    hops.forEach(h => {
      const l = h.finding_id ? rowLine(root, () => api.open('finding', h.finding_id), null, 'finding') : line(root);
      hang(l, 6);
      seg(l, '  ' + rfit(h.stage, 2) + '. ' + str(h.summary));
      if (h.relation) seg(l, '  (' + str(h.relation) + ')', 'dim');
      if (h.confidence) seg(l, '  [' + str(h.confidence) + ']', 'dim');
      hang(text(root, 'because: ' + str(h.because), 'dim'), 8);
    });
  }
  // Potential escalations (W7-POLISH item 13): inferred path-rule matches on this principal,
  // when the Issue page carries them (internal/server/issuepage.go: potential_escalations).
  const pot = Array.isArray(pg.potential_escalations) ? pg.potential_escalations : [];
  if (pot.length && is.kind !== 'path') {
    blank(root);
    text(root, 'Potential escalation (' + pot.length + ', inferred: the permissions allow it, the graph cannot prove it; not a path Issue)', 'b');
    pot.slice(0, 20).forEach(m => {
      const l = line(root, 'nw potential');
      l.setAttribute('data-potential', str(m.rule_id));
      seg(l, '  ' + str(m.rule_id) + ' ' + str(m.title || 'escalation') + ' → ');
      const tgt = str(m.target);
      link(l, nodeName(idx(api.D || {}), tgt), () => api.open('node', tgt), null, 'node');
      if (m.custom) seg(l, '  [custom rule]', 'dim');
      if ((m.because || []).length) hang(text(root, 'because ' + m.because.map(str).join('; '), 'dim'), 6);
      if (m.credit && m.credit.source) text(root, '      credit: ' + str(m.credit.source) + ' ' + str(m.credit.upstream_id || '') + ' (' + str(m.credit.licence || '') + ')', 'dim');
    });
  }
  const linked = pg.linked_issues || [];
  if (linked.length) {
    blank(root);
    text(root, (is.kind === 'path' ? 'Evidence Issues on this path' : 'Attack path Issues through this resource') + ' (' + linked.length + ')', 'b');
    linked.slice(0, 20).forEach(li => {
      const l = rowLine(root, () => api.open('issue', li.id), 'nw', 'issue');
      l.setAttribute('data-linked', str(li.id));
      seg(l, '  ');
      seg(l, fit(str(li.severity), 9), 'sev-' + li.severity);
      seg(l, fit(str(li.state), 9), 'dim');
      seg(l, fit(str(li.title) + (li.kind === 'path' ? '  ' + f1(li.score) + ' ' + str(li.band) : ''), Math.max(10, W - 22)).replace(/\s+$/, ''));
    });
  }
  const fixes = pg.fixes || [];
  if (fixes.length) {
    blank(root);
    text(root, 'Fix (' + fixes.length + ')', 'b');
    fixes.forEach(fx => {
      const l = rowLine(root, () => api.open('finding', fx.finding_id), 'nw', 'finding');
      l.setAttribute('data-fix', str(fx.template));
      seg(l, '  ' + str(fx.canonical_id) + '  template ' + str(fx.template) + ' (' + str(fx.format) + ')' + (fx.generic ? '  generic stub' : ''));
      const m = fx.metadata;
      if (m) hang(text(root, '    effort ' + str(m.effort) + ' · confidence ' + str(m.confidence), 'dim'), 4);
      (fx.phases || []).forEach((ph, i) => {
        const pl = text(root, '    ' + (i + 1) + '. ' + str(ph.name), 'phase');
        pl.setAttribute('data-phase', str(ph.name));
        (ph.steps || []).forEach(st => hang(text(root, '       ' + str(st), 'dim'), 7));
      });
    });
  }
  const tl = pg.timeline || [];
  if (tl.length) {
    blank(root);
    text(root, 'Timeline', 'b');
    tl.slice(-30).forEach(e => {
      const l = line(root);
      l.setAttribute('data-tl', '1');
      seg(l, '  ' + String(e.at || '').replace('T', ' ').slice(0, 16) + '  ', 'dim');
      seg(l, fit(str(e.event), 20));
      seg(l, str(e.detail), 'dim');
    });
  }
}

// ---------------------------------------------------------------- compliance
function fwName(fw) {
  const n = str(fw.name || fw.key), v = str(fw.version);
  return v && !n.endsWith(v) ? n + ' ' + v : n;
}
function vCompliance(root, api, arg) {
  const D = api.D || {};
  const W = availCols(root, 120);
  const reps = D.compliance || [];
  if (!reps.length) { text(root, 'no compliance data; findings carry no framework mappings yet'); return; }
  const want = str(arg && typeof arg === 'object' ? arg.framework : arg).toLowerCase();
  let cur = reps.find(r => want && (str(r.framework.key).toLowerCase() === want || str(r.framework.name).toLowerCase() === want)) || reps[0];
  const nm = Math.max(30, Math.min(60, W - 40));
  let ln = line(root, 'b nw');
  seg(ln, '  ' + fit('FRAMEWORK', nm) + rfit('SCORE', 7) + rfit('FAILING', 9) + rfit('PASSING', 9) + rfit('N/A', 6));
  const rows = reps.map(r => {
    const fw = r.framework || {};
    const l2 = rowLine(root, () => { cur = r; root._cwmArg = { framework: fw.key }; if (api.setArg) api.setArg(root._cwmArg); paint(); }, 'nw', 'framework');
    l2.setAttribute('data-fw', str(fw.key));
    const sp = r.score_percent || 0;
    seg(l2, '  ');
    seg(l2, fit(fwName(fw), nm));
    seg(l2, rfit(sp + '%', 7), sp >= 80 ? 'ok' : sp < 50 ? 'red' : null);
    seg(l2, rfit(num(r.failing), 9), r.failing ? 'red' : null);
    seg(l2, rfit(num(r.passing), 9));
    seg(l2, rfit(num(r.not_assessed), 6), 'dim');
    return { r, l2 };
  });
  blank(root);
  const body = el('div');
  root.appendChild(body);
  function paint() {
    rows.forEach(({ r, l2 }) => { l2.classList.toggle('sel', r === cur); l2.firstChild.textContent = r === cur ? '> ' : '  '; });
    body.textContent = '';
    const fw = cur.framework || {};
    const h = line(body, 'b');
    h.textContent = fwName(fw) + '  ' + (cur.score_percent || 0) + '%  ' +
      num(cur.passing) + ' pass / ' + num(cur.failing) + ' fail / ' + num(cur.not_assessed) + ' not assessed' + (cur.scope ? '  scope ' + str(cur.scope) : '');
    text(body, 'PASS = only passing checks map to the control · FAIL = any failing check · n/a = not assessed by the tools run', 'dim');
    if (!(cur.passing > 0)) {
      // r4 E15: a 0% with no explanation reads as "everything is broken".
      text(body, 'score 0%: no control has a PASS result — the input carries no passing checks (scanner output with failures only, such as the lab estate), so the score cannot rise above 0% until a scan records passes', 'dim compl-zero');
    }
    blank(body);
    const SC = { FAIL: 0, PASS: 1, NOT_ASSESSED: 2 };
    const ctls = (cur.controls || []).slice().sort((a, b) => (SC[a.status] - SC[b.status]) || 0);
    let l = line(body, 'b nw');
    l.textContent = fit('STATUS', 7) + ' ' + fit('ID', 16) + ' ' + fit('TITLE', Math.max(20, W - 7 - 16 - 2 - 9 - 5)) + rfit('FINDINGS', 9);
    ctls.forEach(c => {
      const click = c.finding_ids && c.finding_ids.length;
      l = click ? rowLine(body, () => api.open('findings', { ids: c.finding_ids, control: str(fw.key) + ':' + c.id, deadends: 1 }), 'nw', 'findings') : line(body, 'nw');
      const st = c.status === 'NOT_ASSESSED' ? 'n/a' : c.status;
      seg(l, fit(st, 7), c.status === 'FAIL' ? 'red' : c.status === 'PASS' ? 'ok' : 'dim');
      seg(l, ' ' + fit(c.id, 16) + ' ');
      seg(l, fit(c.title, Math.max(20, W - 7 - 16 - 2 - 9 - 5)));
      seg(l, rfit(click ? num(c.finding_ids.length) : '', 9));
      if (c.max_severity && c.status === 'FAIL') seg(l, ' ' + fit(SEV_SHORT[c.max_severity] || c.max_severity, 4), 'sev-' + c.max_severity);
    });
  }
  paint();
}

// ---------------------------------------------------------------- cost
function genericTable(parent, title, v, W) {
  if (v == null) return;
  blank(parent);
  text(parent, title, 'b');
  if (Array.isArray(v)) {
    if (!v.length) { text(parent, '  none', 'dim'); return; }
    if (typeof v[0] !== 'object' || v[0] === null) { v.forEach(x => text(parent, '  ' + str(x))); return; }
    const keys = [];
    v.forEach(o => Object.keys(o || {}).forEach(k => { if (!keys.includes(k) && (o[k] == null || typeof o[k] !== 'object')) keys.push(k); }));
    const ks = keys.slice(0, 8);
    const ws = ks.map(k => Math.min(30, Math.max(k.length, ...v.map(o => str(o && o[k] != null ? (typeof o[k] === 'number' ? Math.round(o[k] * 100) / 100 : o[k]) : '').length))));
    table(parent, ks.map((k, i) => ({ h: k.toUpperCase(), w: ws[i], r: typeof (v[0] || {})[k] === 'number',
      get: o => o == null || o[k] == null ? '' : typeof o[k] === 'number' ? String(Math.round(o[k] * 100) / 100) : o[k] })), v, W);
  } else if (typeof v === 'object') {
    Object.keys(v).forEach(k => text(parent, '  ' + fit(k, 28) + ' ' + (v[k] != null && typeof v[k] === 'object' ? JSON.stringify(v[k]) : str(v[k]))));
  } else text(parent, '  ' + str(v));
}
function vCost(root, api) {
  const D = api.D || {};
  const W = availCols(root, 100);
  const c = D.cost;
  if (!c) {
    text(root, 'no cost data in this report.');
    text(root, 'run `cloud-posture cost` after a collector scan to see zombie resources, rightsizing and security-driven savings.');
    return;
  }
  if (c.total_monthly_savings != null) {
    const ln = line(root, 'b');
    ln.textContent = 'total savings: $' + num(Math.round(c.total_monthly_savings)) + '/month';
    blank(root);
  }
  if (c.text) { String(c.text).split('\n').forEach(s => text(root, s)); return; }
  genericTable(root, 'Zombies', c.zombies, W);
  genericTable(root, 'Rightsizing', c.rightsizing, W);
  genericTable(root, 'Security cost wins', c.security_cost_wins, W);
  genericTable(root, 'ROI', c.roi, W);
}

// ---------------------------------------------------------------- coverage
// Coverage honesty (Track G): every API call / collector / tool run of the latest scan and
// whether it actually ran, per provider/account, with the reason for anything not "ok".
// Without a coverage table it falls back to the scan's tool runs.
function vCoverage(root, api) {
  const D = api.D || {};
  const W = availCols(root, 100);
  const sc = D.scan;
  const runs = (sc && sc.tools) || [];
  const cov = D.coverage || [];
  if (!cov.length && !runs.length) { text(root, 'no scan metadata (results were ingested from files).'); return; }
  let ln;
  if (cov.length) {
    const st = covCounts(cov);
    ln = line(root);
    seg(ln, 'scan ' + str(cov[0].scan_id), 'b');
    seg(ln, '  ' + num(cov.length) + ' API calls / tool runs recorded ' + ago(cov[0].at) + ': ');
    COV.forEach((s, i) => {
      if (i) seg(ln, ', ');
      seg(ln, num(st[s]) + ' ' + s, st[s] ? COV_CLS[s] : null);
    });
    text(root, 'what ran, what was skipped, what was denied: a silent skip is a blind spot.', 'dim');
    blank(root);
    // per provider/account counts
    const groups = {};
    cov.forEach(c => {
      const k = covKey(c);
      if (!groups[k]) { groups[k] = { prov: str(c.provider) || '-', acct: str(c.account), n: {} }; COV.forEach(s => { groups[k].n[s] = 0; }); }
      groups[k].n[c.status] = (groups[k].n[c.status] || 0) + 1;
    });
    const bad = g => g.n.denied + g.n.timeout + g.n.error;
    const keys = Object.keys(groups).sort((a, b) => (bad(groups[b]) - bad(groups[a])) || a.localeCompare(b));
    const aw = Math.max(16, Math.min(44, W - 10 - 5 * 9 - 2));
    ln = line(root, 'b nw thead');
    ln.textContent = fit('PROVIDER', 10) + ' ' + fit('ACCOUNT', aw) + COV.map(s => rfit(s.toUpperCase(), 9)).join('');
    keys.forEach(k => {
      const g = groups[k];
      ln = line(root, 'nw');
      ln.setAttribute('data-cov', k);
      seg(ln, fit(g.prov, 10) + ' ' + fit(g.acct, aw));
      COV.forEach(s => {
        const n = g.n[s];
        seg(ln, ' '.repeat(Math.max(0, 9 - String(n || '.').length)));
        seg(ln, n ? String(n) : '.', 'c-' + s + ' ' + (n ? COV_CLS[s] : 'dim'));
      });
    });
    // reasons for everything that did not run
    const ORDER = { denied: 0, timeout: 1, error: 2, skipped: 3 };
    const notOk = cov.filter(c => c.status !== 'ok').sort((a, b) => ((ORDER[a.status] ?? 9) - (ORDER[b.status] ?? 9)) || covKey(a).localeCompare(covKey(b)));
    blank(root);
    text(root, 'Not covered (' + notOk.length + ')', 'b');
    if (!notOk.length) text(root, '  none: every recorded call ran', 'ok');
    notOk.forEach(c => {
      ln = line(root);
      ln.setAttribute('data-reason', str(c.status));
      seg(ln, '  ' + fit(c.status, 8), COV_CLS[c.status] || null);
      seg(ln, fit(covKey(c), 28) + ' ' + fit(c.api, 34) + ' ');
      seg(ln, str(c.reason) || '(no reason recorded)', 'why ' + (c.status === 'skipped' ? 'dim' : 'red'));
    });
  }
  if (!runs.length) return;
  if (cov.length) { blank(root); text(root, 'Tool runs (scan metadata)', 'b'); }
  else {
    ln = line(root);
    seg(ln, 'scan ' + str(sc.scan_id), 'b');
    seg(ln, '  started ' + str(sc.started_at).slice(0, 19).replace('T', ' ') + '  finished ' + str(sc.finished_at).slice(0, 19).replace('T', ' ') + ' (' + ago(sc.finished_at || sc.started_at) + ')');
    ln = line(root);
    const accts = (sc.accounts && sc.accounts.length) ? sc.accounts : (D.accounts || []);
    const tf = runs.filter(r => r.status === 'failed').length, tsk = runs.filter(r => r.status === 'skipped').length;
    seg(ln, 'accounts: ' + (accts.length ? accts.join(', ') : 'none (ingested files)') + '  results ' + num(sc.total) + '  tools ' + runs.length + ': ');
    seg(ln, num(runs.length - tf - tsk) + ' ok', 'ok'); seg(ln, ', ');
    seg(ln, num(tsk) + ' skipped', tsk ? 'dim' : null); seg(ln, ', ');
    seg(ln, num(tf) + ' failed', tf ? 'red' : null);
    if (sc.attack_paths != null) seg(ln, '  attack paths ' + num(sc.attack_paths));
    text(root, 'what ran, what was skipped, what was denied: a silent skip is a blind spot.', 'dim');
    blank(root);
  }
  table(root, [
    { h: 'TOOL', w: 12, get: r => r.tool },
    { h: 'ACCOUNT', w: 34, get: r => r.account },
    { h: 'STATUS', w: 7, get: r => r.status, cls: r => r.status === 'failed' ? 'red' : r.status === 'skipped' ? 'dim' : 'ok' },
    { h: 'FINDINGS', w: 8, r: 1, get: r => num(r.findings || 0) },
    { h: 'DETAIL', w: 0, get: r => (str(r.message) + (r.output ? ' ' + str(r.output).slice(-200) : '')).trim(), cls: () => 'dim' },
  ], runs, W, r => api.open('findings', { source: r.tool, status: 'all', view: 'findings' }), 'findings');
}

// ---------------------------------------------------------------- node
function vNode(root, api, arg) {
  const D = api.D || {}, X = idx(D);
  const W = availCols(root, 100);
  const id = arg && typeof arg === 'object' ? arg.id : arg;
  let n = X.nodeBy[id];
  const fsOn = (D.findings || []).filter(f => f.resource && f.resource.id === id);
  if (!n && fsOn.length) { const r = fsOn[0].resource; n = { id, name: r.name, type: r.type, provider: fsOn[0].provider, account: fsOn[0].account, region: fsOn[0].region }; }
  if (!n) { if (api.setTitle) api.setTitle('resource'); text(root, 'resource ' + str(id) + ': not found'); return; }
  if (api.setTitle) api.setTitle(str(n.name || n.id));
  kv(root, 'id', n.id);
  kv(root, 'type', n.type);
  kv(root, 'class', n.class);
  kv(root, 'provider', n.provider);
  kv(root, 'account', n.account);
  kv(root, 'region', n.region || '-');
  kv(root, 'criticality', n.criticality || '-');
  kv(root, 'owner', n.owner || '-');
  kv(root, 'sensitive', n.sensitive ? 'yes' : 'no', null, n.sensitive ? 'red' : null);
  kv(root, 'weaknesses', (n.weaknesses || []).map(wk).join(', ') || 'none', null, (n.weaknesses || []).length ? 'red' : null);
  if (n.modified_at) kv(root, 'modified', n.modified_at);
  if (n.cve_count) kv(root, 'CVEs', n.cve_count);
  if (n.monthly_cost) kv(root, 'monthly cost', '$' + num(n.monthly_cost));
  const fids = new Set((n.finding_ids || []).concat(fsOn.map(f => f.id)));
  const fl = [...fids].map(i => X.byId[i]).filter(Boolean);
  blank(root);
  text(root, 'Findings (' + fl.length + ')', 'b');
  if (!fl.length) text(root, '  none', 'dim');
  fl.forEach(f => {
    const l = rowLine(root, () => api.open('finding', f.id), 'nw', 'finding');
    seg(l, '  ');
    seg(l, fit(f.status === 'FAIL' ? f.severity : f.status, 9), f.status === 'PASS' ? 'sev-PASS' : f.status === 'FAIL' ? 'sev-' + f.severity : 'dim');
    seg(l, fit(f.title, W - 11).replace(/\s+$/, ''));
  });
  const ps = pathsSorted(D).filter(p => (p.steps || []).some(s => s.resource === n.id));
  blank(root);
  text(root, 'Attack paths through it (' + ps.length + ')', 'b');
  if (!ps.length) text(root, '  none', 'dim');
  ps.forEach(p => {
    const l = rowLine(root, () => api.open('paths', { pathId: p.id }), 'nw', 'paths');
    seg(l, '  ');
    seg(l, rfit(f1(p.score), 4), 'sev-' + p.severity);
    seg(l, '  ' + fit(pathLabel(D, p), W - 8).replace(/\s+$/, ''));
  });
  const edges = ((D.graph && D.graph.edges) || []).filter(e => e.from === n.id || e.to === n.id);
  if (edges.length) {
    blank(root);
    text(root, 'Edges (' + edges.length + ')', 'b');
    edges.slice(0, 30).forEach(e => {
      const other = e.from === n.id ? e.to : e.from;
      const on = X.nodeBy[other];
      const l = on ? rowLine(root, () => api.open('node', other), 'nw', 'node') : line(root, 'nw');
      seg(l, '  ' + (e.from === n.id ? '-> ' : '<- ') + fit(e.kind, 14) + ' ' + str(on ? (on.name || on.id) : other));
    });
  }
  blank(root);
  const q = 'SELECT * FROM findings WHERE resource_id = ' + sqlq(n.id);
  const l = rowLine(root, () => api.open('sql', { sql: q, run: true }), null, 'sql');
  seg(l, fit('Open query', 14), 'b');
  seg(l, q);
}

// ---------------------------------------------------------------- REPL base
const histories = {};
function repl(root, api, promptText, onLine, opts) {
  opts = opts || {};
  const out = el('div');
  root.appendChild(out);
  const pr = el('div', 'prompt');
  const ps = el('span', null, promptText);
  const inp = el('input', 'term');
  inp.type = 'text'; inp.spellcheck = false; inp.autocomplete = 'off';
  inp.setAttribute('aria-label', promptText.trim());
  pr.append(ps, inp);
  root.appendChild(pr);
  const hist = histories[promptText] = histories[promptText] || [];
  let hi = hist.length, busy = false;
  const term = {
    out, inp, api,
    print(s, cls) { const d = line(out, cls); d.textContent = str(s) === '' ? '' : String(s); return d; },
    line(cls) { return line(out, cls); },
    clear() { out.textContent = ''; },
    scroll() { root.scrollTop = root.scrollHeight; },
    async run(cmd) {
      const echo = line(out);
      seg(echo, promptText); seg(echo, cmd);
      busy = true;
      try { await onLine(cmd, term); } catch (e) { term.print('error: ' + (e && e.message || e), 'red'); }
      busy = false;
      term.scroll();
    },
  };
  inp.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.altKey && !e.ctrlKey && !e.metaKey) {
      e.preventDefault(); e.stopPropagation();
      if (busy) return;
      const v = inp.value;
      inp.value = '';
      if (v.trim() && hist[hist.length - 1] !== v) hist.push(v);
      while (hist.length > 100) hist.shift();
      hi = hist.length;
      term.run(v);
    } else if (e.key === 'ArrowUp' && !e.altKey && !e.ctrlKey) {
      e.preventDefault(); e.stopPropagation();
      if (hi > 0) { hi--; inp.value = hist[hi]; }
    } else if (e.key === 'ArrowDown' && !e.altKey && !e.ctrlKey) {
      e.preventDefault(); e.stopPropagation();
      if (hi < hist.length - 1) { hi++; inp.value = hist[hi]; } else { hi = hist.length; inp.value = ''; }
    } else if (e.ctrlKey && !e.altKey && !e.metaKey && e.code === 'KeyL') {
      e.preventDefault(); e.stopPropagation();
      term.clear();
    } else if (e.ctrlKey && !e.altKey && !e.metaKey && e.code === 'KeyU') {
      e.preventDefault(); e.stopPropagation();
      inp.value = '';
    }
  });
  root.addEventListener('mouseup', e => {
    if (e.button !== 0 || e.altKey) return;
    const s = window.getSelection && window.getSelection();
    if (s && !s.isCollapsed) return;
    if (e.target.closest && e.target.closest('.row')) return;
    inp.focus({ preventScroll: true });
  });
  return term;
}

// fixed-width result table: columns separated by two spaces, header + dashes.
function printRows(term, cols, rows) {
  cols = cols || []; rows = rows || [];
  const cell = v => v == null ? 'NULL' : typeof v === 'object' ? JSON.stringify(v) : String(v);
  const ws = cols.map((c, i) => Math.min(40, Math.max(str(c).length, ...rows.slice(0, 1000).map(r => cell(r[i]).replace(/[\r\n\t]+/g, ' ').length), 1)));
  if (cols.length) {
    term.print(cols.map((c, i) => fit(c, ws[i])).join('  ').replace(/\s+$/, ''), 'b nw');
    term.print(ws.map(w => '-'.repeat(w)).join('  '), 'nw');
  }
  rows.slice(0, 1000).forEach(r => term.print(cols.map((c, i) => fit(cell(r[i]), ws[i])).join('  ').replace(/\s+$/, ''), 'nw'));
  if (rows.length > 1000) term.print('… ' + (rows.length - 1000) + ' more rows not shown', 'dim');
  term.print(rows.length + ' row' + (rows.length === 1 ? '' : 's'), 'dim');
}

// ---------------------------------------------------------------- sql
const SAVED = [
  ['Public buckets', 'SELECT name, provider, account, region FROM aws_s3_buckets WHERE public_access = 1'],
  ['Internet-exposed compute, all clouds', 'SELECT name, provider, account FROM aws_instances WHERE internet_exposed = 1 UNION ALL SELECT name, provider, account FROM azure_virtual_machines WHERE internet_exposed = 1 UNION ALL SELECT name, provider, account FROM gcp_compute_instances WHERE internet_exposed = 1'],
  ['Attack paths to databases', "SELECT name, entry_point, target, path_length, score FROM attack_path_summary WHERE target LIKE '%rds%' OR target LIKE '%sql%' OR target LIKE '%db%' ORDER BY score DESC"],
  ['CIS AWS failing controls', "SELECT control_id, title, reason FROM cis_aws_benchmark WHERE status = 'FAIL'"],
  ['SOC 2 status', 'SELECT control_id, title, status FROM soc2 ORDER BY control_id'],
  ['Findings by account', "SELECT provider, account, severity, COUNT(*) AS n FROM findings WHERE status='FAIL' GROUP BY 1,2,3 ORDER BY n DESC"],
];
async function runSQL(term, sql, api) {
  sql = str(sql).trim();
  if (!sql) return;
  const m = sql.match(/^\\([1-9])$/);
  if (m) {
    const s = SAVED[+m[1] - 1];
    if (!s) { term.print('no saved query \\' + m[1], 'red'); return; }
    term.print('-- ' + s[0], 'dim');
    term.print(s[1]);
    sql = s[1];
  }
  if (!api.live) {
    term.print('$ cloud-posture query "' + sql.replace(/(["\\$`])/g, '\\$1') + '"');
    term.print('static report: run the command above, or start `cloud-posture serve` for a live console.', 'dim');
    return;
  }
  const r = await fetch('/api/query', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sql }) });
  let j;
  try { j = await r.json(); } catch (e) { throw new Error('HTTP ' + r.status); }
  if (j.error) { term.print('error: ' + str(j.error), 'red'); return; }
  printRows(term, j.columns, j.rows);
  if (j.engine) term.print('engine: ' + str(j.engine), 'dim');
}
function vSQL(root, api, arg) {
  api.live = api.live != null ? api.live : (api.D && api.D.mode === 'live');
  const term = repl(root, api, 'sql> ', (cmd, t) => runSQL(t, cmd, api));
  term.print('nimbus sql: SQL over your cloud (zero-ETL views). Saved queries:');
  SAVED.forEach(([n, q], i) => {
    const l = rowLine(term.out, () => term.run('\\' + (i + 1)), 'nw', 'saved');
    seg(l, '  \\' + (i + 1) + '  ' + fit(n, 38));
    seg(l, q.slice(0, 60) + (q.length > 60 ? '…' : ''), 'dim');
  });
  term.print(api.live ? 'live: queries run against the posture database. Up/Down history, Ctrl-L clears.'
    : 'static report: queries are printed as cloud-posture commands. Up/Down history, Ctrl-L clears.', 'dim');
  const a = arg && typeof arg === 'object' ? arg : (arg ? { sql: String(arg) } : {});
  if (a.sql) {
    if (a.run) term.run(a.sql);
    else term.inp.value = a.sql;
  }
}

// ---------------------------------------------------------------- copilot
async function ask(term, q, api) {
  q = str(q).trim();
  if (!q) return;
  const D = api.D || {};
  const url = D.copilot_url;
  if (!url) {
    term.print('$ nimbus ask "' + q.replace(/(["\\$`])/g, '\\$1') + '"');
    term.print('not connected: run the command above in a terminal, or start `nimbus serve`.', 'dim');
    return;
  }
  const r = await fetch(String(url).replace(/\/$/, '') + '/api/copilot', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ question: q }) });
  let j;
  try { j = await r.json(); } catch (e) { throw new Error('HTTP ' + r.status); }
  if (j.error) term.print('error: ' + str(j.error), 'red');
  if (j.intent || j.mode) term.print('intent ' + str(j.intent || '-') + ' · mode ' + str(j.mode || '-'), 'dim');
  if (j.answer) String(j.answer).split('\n').forEach(s => term.print(s));
  if (j.sql) { term.print('sql:', 'b'); term.print('  ' + str(j.sql)); }
  if (Array.isArray(j.columns) && j.columns.length) printRows(term, j.columns, j.rows || []);
  else if (Array.isArray(j.rows) && j.rows.length) term.print(j.rows.length + ' rows', 'dim');
  if (!j.answer && !j.sql && !j.error && !(j.rows && j.rows.length)) term.print('(no answer)', 'dim');
}
function vCopilot(root, api, arg) {
  const D = api.D || {};
  const term = repl(root, api, 'ask> ', (cmd, t) => ask(t, cmd, api));
  term.print('nimbus copilot: ask in plain English, e.g. show me all public databases with no encryption');
  term.print(D.copilot_url ? 'connected to ' + str(D.copilot_url)
    : 'not connected: start `nimbus serve`, or run `nimbus ask "…"` in a terminal.', 'dim');
  const a = arg && typeof arg === 'object' ? arg : (arg ? { q: String(arg), run: true } : {});
  if (a.q) { if (a.run !== false) term.run(a.q); else term.inp.value = a.q; }
}

// ---------------------------------------------------------------- registry
const VIEWS = {
  overview: vOverview, paths: vPaths, risk: vRisk, findings: vFindings, finding: vFinding, issue: vIssue,
  compliance: vCompliance, cost: vCost, sql: vSQL, copilot: vCopilot, coverage: vCoverage, node: vNode,
};
// [name, title, live]: sections plus the pane views (finding, issue, node).
const SPECS = [
  ['overview', 'overview', true],
  ['paths', 'attack paths', true],
  ['risk', 'top risks', true],
  ['findings', 'findings', true],
  ['compliance', 'compliance', true],
  ['cost', 'cost', true],
  ['sql', 'sql', false],
  ['copilot', 'copilot', false],
  ['coverage', 'coverage', true],
  ['finding', 'finding', true],
  ['issue', 'issue', true],
  ['node', 'resource', true],
];
C.views = {};
SPECS.forEach(([name, title, live]) => {
  const render = mount(name, live);
  C.views[name] = render;
  const i = C.commands.findIndex(c => c && c.name === name);
  const cmd = { name, title, render };
  if (i >= 0) C.commands[i] = cmd; else C.commands.push(cmd);
});
C._clients = { fit, rfit, parseFilter, filterString, registry, liveLog };
})();
