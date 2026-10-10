/* cwm.js: layout, navigation, hash routing, drill-down pane, focus/urgency, keys and live mode
 * for the nimbus dashboard. It carries cwm(1)'s look (docs/design/cwm-dashboard-spec.md v2) but is
 * not a window manager. Views come from clients.js (window.CWM.commands). Data-derived strings are
 * only ever written with textContent. Public surface: window.CWM. */
(function () {
  'use strict';

  const C = window.CWM = Object.assign({ commands: [] }, window.CWM || {});
  if (!Array.isArray(C.commands)) C.commands = [];
  const doc = document;
  const html = doc.documentElement;

  let D = {};
  try {
    const el = doc.getElementById('data');
    D = JSON.parse((el && el.textContent) || '{}') || {};
  } catch (e) {
    D = {};
  }
  const LIVE = D.mode === 'live';
  const PROMPT = 'nimbus';
  const PROMPT_S = '»'; // » menu.c PROMPT_SCHAR
  const PROMPT_E = '«'; // « menu.c PROMPT_ECHAR

  // Sections in navigation order: [hash name, nav label]. Keys 1-9 follow this order.
  const SECTIONS = [
    ['overview', 'overview'],
    ['paths', 'attack paths'],
    ['risk', 'top risks'],
    ['findings', 'findings'],
    ['compliance', 'compliance'],
    ['cost', 'cost'],
    ['sql', 'sql'],
    ['copilot', 'copilot'],
    ['coverage', 'coverage'],
  ];
  const PANE = { finding: true, node: true, issue: true }; // drill-downs open in the right-hand pane
  const MULTI = { overview: true };              // views that lay out their own grid of panels
  const KEYS = [['/', 'filter'], ['1-9', 'section'], ['j k', 'move'], ['enter', 'open'], ['esc', 'close']];

  const S = {
    cur: null,        // {name, arg, root, closers}
    pane: null,       // {cmd, arg, el, title, body, closers}
    focusKey: '',     // data-key of the focused panel ('pane' for the pane)
    urgent: Object.create(null),
    hash: '',
    filter: '',
  };
  let app, nav, navInput, promptText, main;
  const items = {};

  function el(tag, cls, text) {
    const e = doc.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }
  function findCommand(name) {
    for (let i = 0; i < C.commands.length; i++) if (C.commands[i] && C.commands[i].name === name) return C.commands[i];
    return null;
  }
  function isSection(name) { return SECTIONS.some(function (s) { return s[0] === name; }); }
  function labelOf(name) { const s = SECTIONS.find(function (x) { return x[0] === name; }); return s ? s[1] : name; }
  function inEditable(t) {
    return !!(t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable));
  }

  /* ---- hash <-> arg ---- */
  function argToQuery(arg) {
    if (arg == null || arg === '') return '';
    const p = new URLSearchParams();
    if (typeof arg !== 'object') p.set('arg', String(arg));
    else {
      Object.keys(arg).forEach(function (k) {
        const v = arg[k];
        if (v == null || v === '' || v === false) return;
        if (Array.isArray(v)) { if (v.length) p.set(k, v.join(',')); return; }
        if (typeof v === 'object') return;
        p.set(k, String(v));
      });
    }
    const q = p.toString();
    return q ? '?' + q : '';
  }
  function parseHash(h) {
    h = String(h || '').replace(/^#/, '');
    const i = h.indexOf('?');
    let name = i >= 0 ? h.slice(0, i) : h;
    try { name = decodeURIComponent(name); } catch (e) { /* keep raw */ }
    const q = i >= 0 ? h.slice(i + 1) : '';
    let arg;
    if (q) {
      const p = new URLSearchParams(q);
      const o = {};
      p.forEach(function (v, k) { o[k] = v; });
      if (Object.keys(o).length === 1 && o.arg != null) arg = o.arg;
      else {
        if (o.run != null) o.run = o.run === 'true' || o.run === '1';
        if (o.ids != null) o.ids = o.ids.split(',').filter(Boolean);
        arg = Object.keys(o).length ? o : undefined;
      }
    }
    return { name: name, arg: arg };
  }
  function hashFor(name, arg) { return '#' + name + argToQuery(arg); }

  /* ---- panels and focus ---- */
  function makePanel(key, title, cls) {
    const p = el(cls === 'pane' ? 'aside' : 'section', 'panel' + (cls ? ' ' + cls : ''));
    p.dataset.key = key;
    const h = el('div', 'panel-h');
    const t = el('span', 't', title);
    h.appendChild(t);
    const b = el('div', 'panel-b view');
    p.append(h, b);
    return { el: p, head: h, title: t, body: b };
  }
  function allPanels() { return Array.prototype.slice.call(doc.querySelectorAll('.panel')); }
  function firstMainKey() {
    const p = main && main.querySelector('.panel');
    return p ? p.dataset.key : '';
  }
  function applyFocus() {
    const ps = allPanels();
    if (!ps.some(function (p) { return p.dataset.key === S.focusKey; })) S.focusKey = firstMainKey();
    delete S.urgent[S.focusKey];
    ps.forEach(function (p) {
      const k = p.dataset.key;
      p.classList.toggle('focus', k === S.focusKey);
      p.classList.toggle('urgent', k !== S.focusKey && !!S.urgent[k]);
    });
  }
  function focusPanel(key) {
    if (!key || key === S.focusKey) { if (key) { delete S.urgent[key]; applyFocus(); } return; }
    S.focusKey = key;
    applyFocus();
  }
  function focusedPanel() {
    return allPanels().find(function (p) { return p.dataset.key === S.focusKey; }) || null;
  }

  /* ---- views ---- */
  function apiFor(holder, name) {
    return {
      open: open,
      navigate: navigate,
      closePane: closePane,
      D: D,
      live: LIVE,
      panel: function (key, title, wide) {
        // multi-panel views (overview) add their own panels to their root
        const p = makePanel(key, title, wide ? 'wide' : '');
        holder.root.appendChild(p.el);
        return p.body;
      },
      setTitle: function (t) {
        const s = String(t == null ? '' : t);
        if (holder.title) holder.title.textContent = s;
      },
      setArg: function (arg) {
        if (holder !== S.cur) return;
        holder.arg = arg;
        const h = hashFor(name, arg);
        if (h !== location.hash) {
          try { history.replaceState(null, '', h); } catch (e) { /* file:// in some browsers */ }
          S.hash = location.hash;
        }
      },
      onClose: function (fn) { if (typeof fn === 'function') holder.closers.push(fn); },
      cwm: C,
    };
  }
  function runView(holder, name, arg) {
    const def = findCommand(name);
    if (!def || typeof def.render !== 'function') return;
    try {
      def.render(holder.root, apiFor(holder, name), arg);
    } catch (e) {
      holder.root.appendChild(el('div', 'ln red', name + ': ' + (e && e.message ? e.message : String(e))));
    }
  }
  function runClosers(h) {
    if (!h) return;
    h.closers.forEach(function (fn) { try { fn(); } catch (e) { /* ignore */ } });
    h.closers = [];
  }

  /* ---- navigation ---- */
  function navigate(name, arg, opts) {
    opts = opts || {};
    if (!isSection(name) || !findCommand(name)) { name = 'overview'; arg = undefined; }
    closePane();
    runClosers(S.cur);
    main.textContent = '';
    S.urgent = Object.create(null);
    const multi = !!MULTI[name];
    main.className = 'main ' + (multi ? 'multi' : 'single');
    const holder = { name: name, arg: arg, closers: [], root: null, title: null };
    if (multi) {
      holder.root = el('div', 'board'); // a fresh root per visit, so the view mounts (and registers) anew
      main.appendChild(holder.root);
    } else {
      const p = makePanel(name, labelOf(name));
      main.appendChild(p.el);
      holder.root = p.body;
      holder.title = p.title;
    }
    S.cur = holder;
    Object.keys(items).forEach(function (k) { items[k].classList.toggle('sel', k === name); });
    const h = hashFor(name, arg);
    if (!opts.fromHash && h !== location.hash) {
      if (opts.replace) { try { history.replaceState(null, '', h); } catch (e) { /* ignore */ } }
      else location.hash = h;
    }
    S.hash = location.hash;
    main.scrollTop = 0;
    runView(holder, name, arg);
    S.focusKey = firstMainKey();
    applyFocus();
  }
  function onHashChange() {
    if (location.hash === S.hash) return;
    const r = parseHash(location.hash);
    navigate(r.name, r.arg, { fromHash: true });
  }

  /* ---- right-hand pane ---- */
  function openPane(cmd, arg) {
    closePane(true);
    const p = makePanel('pane', cmd, 'pane');
    const close = el('span', 'close', 'close');
    close.setAttribute('role', 'button');
    close.addEventListener('click', function (e) { e.stopPropagation(); closePane(); });
    p.head.appendChild(close);
    const holder = { name: cmd, arg: arg, closers: [], root: p.body, title: p.title, el: p.el };
    S.pane = holder;
    app.classList.add('has-pane');
    app.appendChild(p.el);
    runView(holder, cmd, arg);
    S.focusKey = 'pane';
    applyFocus();
  }
  function closePane(keepLayout) {
    const h = S.pane;
    if (!h) return;
    runClosers(h);
    h.el.remove();
    S.pane = null;
    if (!keepLayout) app.classList.remove('has-pane');
    if (S.focusKey === 'pane') S.focusKey = '';
    if (!keepLayout) applyFocus();
  }

  // open(cmd, arg): sections navigate (pushing the hash); finding/node open the pane.
  function open(cmd, arg) {
    if (cmd && typeof cmd === 'object') { arg = cmd.arg; cmd = cmd.cmd; }
    cmd = String(cmd || '');
    if (PANE[cmd]) { openPane(cmd, arg); return; }
    if (isSection(cmd)) navigate(cmd, arg);
  }

  /* ---- reverse video (xterm -rv) ---- */
  function setRv(on) {
    C.rv = !!on;
    html.classList.toggle('cwm-rv', C.rv);
    try { localStorage.setItem('nimbus-xterm-rv', C.rv ? '1' : '0'); } catch (e) { /* ignore */ }
  }

  /* ---- navigation menu (a cwm menu: prompt row + one row per section) ---- */
  function drawPrompt() { promptText.textContent = PROMPT + PROMPT_S + S.filter + PROMPT_E; }
  function matches() {
    const q = S.filter.toLowerCase();
    return SECTIONS.filter(function (s) { return !q || s[1].toLowerCase().indexOf(q) >= 0 || s[0].indexOf(q) >= 0; });
  }
  function applyFilter() {
    drawPrompt();
    const m = matches();
    nav.classList.toggle('filtering', !!S.filter);
    SECTIONS.forEach(function (s) {
      const it = items[s[0]];
      it.classList.toggle('gone', m.indexOf(s) < 0);
      it.classList.toggle('hit', !!S.filter && m[0] === s);
    });
  }
  function clearFilter() {
    S.filter = '';
    navInput.value = '';
    applyFilter();
  }
  function buildNav() {
    nav = el('nav', 'nav');
    nav.setAttribute('aria-label', 'sections');
    const pr = el('div', 'r prompt');
    promptText = el('span', null, '');
    navInput = el('input');
    navInput.type = 'text';
    navInput.spellcheck = false;
    navInput.autocomplete = 'off';
    navInput.setAttribute('aria-label', 'filter sections');
    pr.append(promptText, navInput);
    nav.appendChild(pr);
    navInput.addEventListener('input', function () {
      S.filter = navInput.value.slice(0, 200);
      applyFilter();
    });
    navInput.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        e.stopPropagation();
        const m = matches()[0];
        clearFilter();
        navInput.blur();
        if (m) navigate(m[0]);
      } else if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
        clearFilter();
        navInput.blur();
      }
    });
    SECTIONS.forEach(function (s) {
      const it = el('div', 'r item', s[1]);
      it.dataset.section = s[0];
      it.setAttribute('role', 'link');
      it.addEventListener('click', function () { navigate(s[0]); });
      items[s[0]] = it;
      nav.appendChild(it);
    });
    nav.appendChild(el('div', 'r', ''));
    const rv = el('div', 'r item', 'reverse');
    rv.dataset.action = 'reverse';
    rv.setAttribute('role', 'button');
    rv.addEventListener('click', function () { setRv(!C.rv); });
    nav.appendChild(rv);
    nav.appendChild(el('div', 'r', ''));
    const keys = el('div', 'keys');
    keys.appendChild(el('div', 'r', 'keys'));
    KEYS.forEach(function (k) {
      const r = el('div', 'r');
      r.append(el('span', 'k', k[0]), el('span', null, k[1]));
      keys.appendChild(r);
    });
    nav.appendChild(keys);
    applyFilter();
  }

  /* ---- keyboard ---- */
  function listRows(p) {
    return Array.prototype.slice.call(p.querySelectorAll('.row')).filter(function (r) { return r.offsetParent !== null; });
  }
  function moveSel(dir) {
    const p = focusedPanel();
    if (!p) return;
    const rows = listRows(p);
    if (!rows.length) return;
    const cur = p.querySelector('.kbsel');
    let i = rows.indexOf(cur);
    if (cur) cur.classList.remove('kbsel');
    i = i < 0 ? (dir > 0 ? 0 : rows.length - 1) : Math.max(0, Math.min(rows.length - 1, i + dir));
    rows[i].classList.add('kbsel');
    rows[i].scrollIntoView({ block: 'nearest' });
  }
  function onKeyDown(e) {
    if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
    const t = e.target;
    if (inEditable(t)) {
      if (e.key === 'Escape') { t.blur(); e.preventDefault(); }
      return;
    }
    const k = e.key;
    if (k === '/') {
      e.preventDefault();
      navInput.focus();
    } else if (k >= '1' && k <= '9' && k.length === 1) {
      e.preventDefault();
      navigate(SECTIONS[k.charCodeAt(0) - 49][0]);
    } else if (k === 'j') {
      e.preventDefault();
      moveSel(1);
    } else if (k === 'k') {
      e.preventDefault();
      moveSel(-1);
    } else if (k === 'Enter') {
      const p = focusedPanel();
      const sel = p && p.querySelector('.kbsel');
      if (sel) { e.preventDefault(); sel.click(); }
    } else if (k === 'Escape') {
      if (S.pane) { e.preventDefault(); closePane(); }
      else {
        const p = focusedPanel();
        const sel = p && p.querySelector('.kbsel');
        if (sel) sel.classList.remove('kbsel');
      }
    }
  }
  function onPointerFocus(e) {
    const p = e.target && e.target.closest ? e.target.closest('.panel') : null;
    if (p) focusPanel(p.dataset.key);
  }

  /* ---- live mode (serve): WebSocket, refetch, re-render in place, urgency ---- */
  function markUrgent() {
    allPanels().forEach(function (p) { if (p.dataset.key !== S.focusKey) S.urgent[p.dataset.key] = true; });
    applyFocus();
  }
  function getJSON(url) {
    return fetch(url, { headers: { Accept: 'application/json' } }).then(function (r) {
      if (!r.ok) throw new Error(url + ': ' + r.status);
      return r.json();
    });
  }
  function hook(ev, fresh) {
    if (typeof C.onLive !== 'function') return;
    try { C.onLive(ev, fresh); } catch (e) { /* ignore */ }
    applyFocus(); // views may have rebuilt their panels
  }
  function handleLive(ev) {
    if (!ev || typeof ev !== 'object') return;
    if (ev.type === 'findings_updated') {
      // /api/issues is optional (older servers lack it): its failure must not drop the rest.
      Promise.all([getJSON('/api/summary'), getJSON('/api/findings?status=FAIL'),
        getJSON('/api/issues?state=all').catch(function () { return null; })]).then(function (r) {
        hook(ev, { summary: r[0], findings: Array.isArray(r[1]) ? r[1] : null, issues: Array.isArray(r[2]) ? r[2] : null });
        markUrgent();
      }).catch(function () { hook(ev, null); });
    } else if (ev.type === 'scan_started') {
      hook(ev);
    } else if (ev.type === 'monitor_event') {
      hook(ev);
      markUrgent();
    }
    // anything else (e.g. the server's `hello`) is ignored
  }
  function connectLive() {
    let backoff = 1000;
    function connect() {
      let ws;
      try {
        ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws');
      } catch (e) {
        retry();
        return;
      }
      ws.onopen = function () { backoff = 1000; };
      ws.onmessage = function (m) {
        let ev = null;
        try { ev = JSON.parse(m.data); } catch (e) { return; }
        handleLive(ev);
      };
      ws.onclose = retry;
    }
    function retry() {
      const wait = backoff;
      backoff = Math.min(backoff * 2, 30000);
      setTimeout(connect, wait);
    }
    connect();
  }

  /* ---- public API ---- */
  C.open = open;
  C.navigate = function (name, arg) { navigate(name, arg); };
  C.closePane = function () { closePane(); };
  C.setRv = setRv;
  C.applyFocus = function () { applyFocus(); }; // views call it after re-laying out their panels
  C.sections = SECTIONS.map(function (s) { return s[0]; });
  C.D = D;
  C.rv = false;

  /* ---- init ---- */
  function init() {
    let rv = false;
    try { rv = localStorage.getItem('nimbus-xterm-rv') === '1'; } catch (e) { /* ignore */ }
    C.rv = rv;
    html.classList.toggle('cwm-rv', rv);
    app = el('div', 'app');
    buildNav();
    main = el('main', 'main');
    app.append(nav, main);
    doc.body.insertBefore(app, doc.body.firstChild);
    doc.addEventListener('keydown', onKeyDown);
    doc.addEventListener('mousedown', onPointerFocus, true);
    doc.addEventListener('focusin', onPointerFocus, true);
    window.addEventListener('hashchange', onHashChange);
    const r = parseHash(location.hash);
    navigate(r.name || 'overview', r.arg, { replace: true });
    if (LIVE) connectLive();
  }
  init();
})();
