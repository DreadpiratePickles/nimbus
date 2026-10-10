// Playwright smoke test for the nimbus dashboard, v2 contract: cwm *look*, not a window manager
// (docs/design/cwm-dashboard-spec.md "v2", §v2.7).
// Usage: node smoke.mjs <path-to-index.html> [--shots <dir>]
// Prints PASS/FAIL per check; exits non-zero on any failure.
import { chromium } from 'playwright';
import assert from 'node:assert/strict';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { existsSync, mkdirSync, readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';

const args = process.argv.slice(2);
const report = args.find((a, i) => !a.startsWith('--') && args[i - 1] !== '--shots');
const shotsIdx = args.indexOf('--shots');
const shots = shotsIdx >= 0 ? args[shotsIdx + 1] : process.env.SHOTS_DIR || '';
if (!report || !existsSync(report)) {
  console.error('usage: node smoke.mjs <path-to-index.html> [--shots <dir>]');
  process.exit(2);
}
if (shots) mkdirSync(shots, { recursive: true });

const BLACK = 'rgb(0, 0, 0)', WHITE = 'rgb(255, 255, 255)';
const ACTIVE = 'rgb(204, 204, 204)', INACTIVE = 'rgb(102, 102, 102)', URGENT = 'rgb(252, 136, 20)';
// ANSI palette from cwm.css: black, white, red3, green3, blue2, gray50
const TEXT_OK = new Set([BLACK, WHITE, 'rgb(205, 0, 0)', 'rgb(0, 205, 0)', 'rgb(0, 0, 238)', 'rgb(127, 127, 127)']);
const BG_OK = new Set(['rgba(0, 0, 0, 0)', BLACK, WHITE]);
const BORDER_OK = new Set([BLACK, WHITE, ACTIVE, INACTIVE, URGENT]);
const SECTIONS = ['overview', 'attack paths', 'top risks', 'findings', 'compliance', 'cost', 'sql', 'copilot', 'coverage'];
const HASHES = ['overview', 'paths', 'risk', 'findings', 'compliance', 'cost', 'sql', 'copilot', 'coverage'];
const W = 1440, H = 900;
const reportURL = pathToFileURL(resolve(report)).href;

// The report's embedded payload (the JSON the page reads), for expected counts.
const SRC = readFileSync(report, 'utf8');
const DATA_OPEN = '<script id="data" type="application/json">';
const DATA = (() => { const i = SRC.indexOf(DATA_OPEN) + DATA_OPEN.length; return JSON.parse(SRC.slice(i, SRC.indexOf('</script>', i))); })();
const openIssue = (i) => i.state === 'open' || i.state === 'reopened';
// path Issues: one row per group (D.path_groups = Analysis.Grouped(), the `paths` CLI's rows)
const nIssues = (D) => (D.path_groups || []).length;
// variant(mut): a copy of the report whose payload was changed by mut(D); returns its file URL.
function variant(mut, name = 'variant') {
  const D = JSON.parse(JSON.stringify(DATA));
  mut(D);
  const enc = JSON.stringify(D).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
  const i = SRC.indexOf(DATA_OPEN) + DATA_OPEN.length;
  const html = SRC.slice(0, i) + enc + SRC.slice(SRC.indexOf('</script>', i));
  const dir = mkdtempSync(join(tmpdir(), 'nimbus-' + name + '-'));
  const f = join(dir, 'index.html');
  writeFileSync(f, html);
  return pathToFileURL(f).href;
}

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: W, height: H } });
const page = await ctx.newPage();
const errors = [];
const watch = (p, sink) => {
  p.on('pageerror', (e) => sink.push('pageerror: ' + e.message));
  p.on('console', (m) => { if (m.type() === 'error') sink.push('console.error: ' + m.text()); });
};
watch(page, errors);

let failed = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log('PASS ' + name);
  } catch (e) {
    failed++;
    console.log('FAIL ' + name + '\n     ' + String(e && e.message ? e.message : e).split('\n').join('\n     '));
  }
}
async function shot(p, name) {
  if (shots) await p.screenshot({ path: join(shots, name) });
}
const settle = (p = page) => p.waitForTimeout(60);

// ---- DOM probes (contract: nav.nav, .panel/.panel-h/.panel-b, aside.pane, .row, .kbsel) ----
const navInfo = (p = page) => p.evaluate(() => {
  const n = document.querySelector('nav.nav');
  if (!n) return null;
  const cs = getComputedStyle(n);
  const rowInfo = (x) => { const s = getComputedStyle(x); return { text: x.textContent, bg: s.backgroundColor, color: s.color, weight: s.fontWeight, size: s.fontSize, hidden: s.display === 'none' }; };
  const prompt = n.querySelector('.prompt');
  return {
    bg: cs.backgroundColor, border: `${cs.borderTopWidth} ${cs.borderTopStyle} ${cs.borderTopColor}`,
    weight: cs.fontWeight, size: cs.fontSize, family: cs.fontFamily, radius: cs.borderTopLeftRadius,
    prompt: prompt ? prompt.textContent : null,
    items: [...n.querySelectorAll('.item[data-section]')].map((x) => Object.assign(rowInfo(x), { section: x.dataset.section })),
    keys: (n.querySelector('.keys') || {}).textContent || '',
    reverse: !!n.querySelector('[data-action="reverse"]'),
  };
});
const panels = (p = page) => p.evaluate(() => [...document.querySelectorAll('.panel')].filter((e) => getComputedStyle(e).display !== 'none').map((e) => {
  const cs = getComputedStyle(e);
  const h = e.querySelector(':scope > .panel-h');
  const hs = h && getComputedStyle(h);
  return {
    key: e.dataset.key, pane: e.classList.contains('pane'),
    border: `${cs.borderTopWidth} ${cs.borderTopStyle} ${cs.borderTopColor}`, borderColor: cs.borderTopColor,
    bg: cs.backgroundColor, color: cs.color,
    head: h ? { text: h.textContent, weight: hs.fontWeight, size: hs.fontSize, family: hs.fontFamily, bg: hs.backgroundColor, color: hs.color } : null,
  };
}));
const hash = (p = page) => p.evaluate(() => decodeURIComponent(location.hash));
const selected = async (p = page) => ((await navInfo(p)).items.find((i) => i.bg === BLACK) || {}).section;
const paneOpen = (p = page) => p.evaluate(() => { const e = document.querySelector('aside.pane'); return !!e && getComputedStyle(e).display !== 'none'; });
const findingsRows = (p = page) => p.evaluate(() => [...document.querySelectorAll('main .panel .row[data-open="finding"]')].map((r) => r.textContent));
const issueRows = (p = page) => p.evaluate(() => [...document.querySelectorAll('main .panel .row[data-open="issue"]')].map((r) => r.textContent));
const textOf = (sel, p = page) => p.evaluate((s) => { const e = document.querySelector(s); return e ? e.textContent : null; }, sel);
const colorOf = (sel, p = page) => p.evaluate((s) => { const e = document.querySelector(s); return e ? getComputedStyle(e).color : null; }, sel);
const RED = 'rgb(205, 0, 0)', GRAY = 'rgb(127, 127, 127)';
async function go(h, p = page) {
  await p.evaluate((x) => { location.hash = x; }, h);
  await settle(p);
}

await page.goto(reportURL);
await page.waitForFunction(() => document.querySelector('nav.nav') && document.querySelector('main .panel'), null, { timeout: 5000 }).catch(() => {});

// 1. page + nav (cwm menu look)
await check('1 body black; nav is a cwm menu: white, 1px solid black, bold 14px sans-serif, prompt nimbus»«, nine rows, overview inverted, keys documented', async () => {
  assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), BLACK);
  const n = await navInfo();
  assert.ok(n, 'no nav.nav');
  assert.equal(n.bg, WHITE);
  assert.equal(n.border, '1px solid ' + BLACK);
  assert.equal(n.weight, '700');
  assert.equal(n.size, '14px');
  assert.match(n.family, /sans-serif/);
  assert.equal(n.radius, '0px');
  assert.equal(n.prompt, 'nimbus»«');
  assert.deepEqual(n.items.map((i) => i.text), SECTIONS);
  n.items.forEach((i) => { assert.equal(i.weight, '700', i.text + ' not bold'); assert.equal(i.size, '14px'); });
  const sel = n.items.filter((i) => i.bg === BLACK);
  assert.equal(sel.length, 1, 'exactly one inverted row');
  assert.equal(sel[0].section, 'overview');
  assert.equal(sel[0].color, WHITE);
  n.items.filter((i) => i.section !== 'overview').forEach((i) => { assert.equal(i.bg, WHITE); assert.equal(i.color, BLACK); });
  for (const k of ['/', '1-9', 'j', 'k', 'enter', 'esc']) assert.ok(n.keys.toLowerCase().includes(k), 'keys block lacks ' + k);
  assert.ok(n.reverse, 'no reverse row');
  assert.equal(await hash(), '#overview');
});

// 2. panels: white boxes, bold heading inside (no bar), border by focus
await check('2 overview is a grid of white panels; focused #CCCCCC, others #666666; heading bold 14px black with no bar; click moves focus', async () => {
  const ps = await panels();
  assert.ok(ps.length >= 5, 'overview should be a grid of panels, got ' + ps.length);
  ps.forEach((p) => {
    assert.equal(p.bg, WHITE, p.key + ' bg');
    assert.match(p.border, /^1px solid /, p.key + ' border');
    assert.ok(p.head, p.key + ' has no heading');
    assert.equal(p.head.weight, '700'); assert.equal(p.head.size, '14px');
    assert.match(p.head.family, /sans-serif/);
    assert.equal(p.head.bg, 'rgba(0, 0, 0, 0)', 'heading must not be a bar');
    assert.equal(p.head.color, BLACK);
  });
  assert.equal(ps.filter((p) => p.borderColor === ACTIVE).length, 1, 'one focused panel');
  assert.equal(ps.filter((p) => p.borderColor === INACTIVE).length, ps.length - 1);
  assert.equal(ps[0].borderColor, ACTIVE, 'first panel focused at load');
  await page.click(`main .panel[data-key="${ps[2].key}"] > .panel-h`);
  const after = await panels();
  assert.equal(after[2].borderColor, ACTIVE);
  assert.equal(after[0].borderColor, INACTIVE);
});
await shot(page, 'v2-initial.png');

// 3. style audit of the whole page
async function audit(p = page) {
  return p.evaluate(({ TEXT_OK, BG_OK, BORDER_OK }) => {
    const T = new Set(TEXT_OK), B = new Set(BG_OK), BD = new Set(BORDER_OK);
    const bad = [];
    const tag = (e) => e.tagName.toLowerCase() + (e.className && typeof e.className === 'string' ? '.' + e.className.split(' ').join('.') : '');
    for (const e of document.querySelectorAll('*')) {
      if (e.closest('head') || e.tagName === 'SCRIPT' || e.tagName === 'STYLE') continue;
      const s = getComputedStyle(e);
      if (s.display === 'none') continue;
      if (s.borderTopLeftRadius !== '0px' || s.borderBottomRightRadius !== '0px') bad.push('radius ' + tag(e) + ' ' + s.borderTopLeftRadius);
      if (s.boxShadow !== 'none') bad.push('shadow ' + tag(e));
      if (s.backgroundImage !== 'none') bad.push('bg-image ' + tag(e));
      if (s.animationName !== 'none') bad.push('animation ' + tag(e));
      if (s.transitionDuration.split(',').some((d) => parseFloat(d) > 0)) bad.push('transition ' + tag(e));
      if (s.textShadow !== 'none') bad.push('text-shadow ' + tag(e));
      if (!B.has(s.backgroundColor)) bad.push('bg ' + tag(e) + ' ' + s.backgroundColor);
      for (const side of ['Top', 'Right', 'Bottom', 'Left']) {
        if (parseFloat(s['border' + side + 'Width']) > 0 && s['border' + side + 'Style'] !== 'none' && !BD.has(s['border' + side + 'Color'])) bad.push('border ' + tag(e) + ' ' + s['border' + side + 'Color']);
      }
      const hasText = [...e.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
      if (hasText && !T.has(s.color)) bad.push('color ' + tag(e) + ' ' + s.color + ' "' + e.textContent.slice(0, 20) + '"');
    }
    const imgs = document.querySelectorAll('img, svg, picture, video, iframe').length;
    return { bad: [...new Set(bad)].slice(0, 15), imgs };
  }, { TEXT_OK: [...TEXT_OK], BG_OK: [...BG_OK], BORDER_OK: [...BORDER_OK] });
}
await check('3 whole page: no radius, shadow, background image, animation, img/svg; colours only from the palette', async () => {
  for (const h of HASHES) {
    await go('#' + h);
    const a = await audit();
    assert.deepEqual(a.bad, [], '#' + h + ': ' + a.bad.join('; '));
    assert.equal(a.imgs, 0, '#' + h + ': images/icons present');
  }
  await go('#overview');
});

// 4. no window manager left
await check('4 no WM: no client windows, root right/left click opens no menu, Alt+/ does nothing, context menu not hijacked', async () => {
  const before = await page.evaluate(() => document.querySelectorAll('*').length);
  await page.mouse.click(W - 4, H - 4, { button: 'right' });
  await page.mouse.click(W - 4, H - 4);
  await page.keyboard.press('Alt+Slash');
  await page.keyboard.press('Alt+Shift+Slash');
  await settle();
  const r = await page.evaluate(() => ({
    clients: document.querySelectorAll('.cwm-client, .cwm-menu, .cwm-geom').length,
    prevented: (() => { const ev = new MouseEvent('contextmenu', { bubbles: true, cancelable: true }); document.body.dispatchEvent(ev); return ev.defaultPrevented; })(),
    n: document.querySelectorAll('*').length,
  }));
  assert.equal(r.clients, 0);
  assert.equal(r.prevented, false, 'contextmenu was preventDefault()ed');
  assert.equal(r.n, before, 'DOM changed after root clicks / WM keys');
});

// 5. drill-through: overview number -> filtered findings with the same count
await check('5 overview counts Issues (open-issues number = open Issues in the payload, findings: N secondary) and opens #findings with the same Issue count; a severity number opens that severity', async () => {
  await go('#overview');
  const n = await page.evaluate(() => document.querySelector('main .ov-open').textContent.trim());
  const want = DATA.issues.filter(openIssue).length;
  assert.equal(Number(n.replace(/,/g, '')), want, 'overview headline must count open Issues, not findings');
  const risk = await textOf('main .panel[data-key="risk"]');
  assert.match(risk, /open Issues?/);
  // W7-POLISH r5 #13 / R4: the risk panel prints the CLI headline (store.Headline.Text) word for
  // word, and toxic combinations never sit in the critical parenthesis.
  const h = DATA.headline;
  if (h && typeof h.issues === 'number') {
    const pl = (n, one, many) => n.toLocaleString('en-US') + ' ' + (n === 1 ? one : many);
    const want = pl(h.issues, 'open Issue', 'open Issues') + ': ' + pl(h.path_issues, 'attack path Issue', 'attack path Issues') +
      ' (' + pl(h.path_variants, 'hop variant', 'hop variants') + ') + ' + pl(h.finding_issues, 'finding Issue', 'finding Issues') +
      '; ' + h.critical.toLocaleString('en-US') + ' critical (' + h.path_critical + ' path, ' + h.finding_critical + ' finding)';
    assert.ok(risk.includes(want), 'risk panel headline differs from the CLI headline:\n want ' + want + '\n got  ' + risk);
  }
  assert.doesNotMatch(risk, /critical \(\d+ toxic\)/, 'toxic count inside the critical parenthesis');
  assert.ok(risk.includes('findings: ' + DATA.findings.filter((f) => f.status === 'FAIL').length), 'no "findings: N" secondary line: ' + risk);
  await page.click('main .ov-open');
  await settle();
  assert.match(await hash(), /^#findings/);
  assert.equal(await selected(), 'findings');
  const count = await page.evaluate(() => document.querySelector('main .panel .count').textContent);
  assert.match(count, new RegExp('^' + want + ' issues shown'));
  assert.match(count, /findings: \d+/);
  assert.equal((await issueRows()).length, want, 'issue rows vs headline');
  await go('#overview');
  const sv = await page.evaluate(() => { const e = document.querySelector('main [data-open="findings"].sev-HIGH'); return e && e.textContent.trim(); });
  assert.ok(sv, 'no HIGH severity number in overview');
  assert.equal(Number(sv), DATA.issues.filter((i) => openIssue(i) && i.severity === 'HIGH').length, 'HIGH number must count Issues');
  await page.click('main [data-open="findings"].sev-HIGH');
  await settle();
  assert.match(await hash(), /^#findings\?.*severity=HIGH/);
  const rows = await issueRows();
  assert.equal(rows.length, Number(sv), 'rows vs number');
  rows.forEach((r) => assert.match(r, /^HIGH/));
});

// 6. hash routing, both directions
await check('6 #findings?severity=CRITICAL opens filtered (also on a fresh load); editing the filter updates the hash; back returns', async () => {
  await go('#findings?severity=CRITICAL');
  assert.equal(await selected(), 'findings');
  const v = await page.evaluate(() => document.querySelector('main input[aria-label="filter"]').value);
  assert.match(v, /sev=CRITICAL/);
  const rows = await issueRows();
  assert.ok(rows.length > 0, 'no CRITICAL rows');
  rows.forEach((r) => assert.match(r, /^CRITICAL/));
  const p2 = await ctx.newPage();
  const e2 = []; watch(p2, e2);
  await p2.goto(reportURL + '#findings?severity=CRITICAL');
  await p2.waitForSelector('main input[aria-label="filter"]');
  assert.equal(await selected(p2), 'findings');
  assert.equal((await issueRows(p2)).length, rows.length, 'fresh load rows');
  await p2.goto(reportURL + '#nonsense');
  await settle(p2);
  assert.equal(await selected(p2), 'overview', 'unknown hash falls back to overview');
  assert.deepEqual(e2, []);
  await p2.close();
  await page.fill('main input[aria-label="filter"]', 'sev=HIGH prov=aws');
  await settle();
  const h = await hash();
  assert.match(h, /severity=HIGH/); assert.match(h, /provider=aws/);
  await go('#compliance');
  await page.goBack(); await settle();
  assert.equal(await selected(), 'findings', 'back did not return to findings');
});

// 7. row -> right pane; Escape and close
await check('7 findings (Issue) row opens the right pane (#CCCCCC, main #666666, title heading, close action); Escape closes; close closes', async () => {
  await go('#findings?severity=CRITICAL');
  const first = (await issueRows())[0];
  await page.click('main .panel .row[data-open="issue"] >> nth=0');
  await settle();
  assert.ok(await paneOpen(), 'pane not open');
  const ps = await panels();
  const pane = ps.find((p) => p.pane), main = ps.find((p) => !p.pane);
  assert.equal(pane.borderColor, ACTIVE);
  assert.equal(main.borderColor, INACTIVE);
  assert.ok(pane.head.text.length > 3, 'pane heading empty');
  assert.match(pane.head.text, /close$/, 'pane heading lacks close action');
  assert.ok(first.includes(pane.head.text.replace(/close$/, '').trim().slice(0, 20)), 'pane title vs row: ' + pane.head.text);
  const box = await page.evaluate(() => { const r = document.querySelector('aside.pane').getBoundingClientRect(); return { x: r.x, w: r.width }; });
  assert.ok(box.x > W / 2, 'pane is not on the right');
  await shot(page, 'v2-findings-pane.png');
  await page.keyboard.press('Escape');
  await settle();
  assert.equal(await paneOpen(), false, 'Escape did not close the pane');
  assert.equal((await panels()).find((p) => !p.pane).borderColor, ACTIVE, 'focus did not return to main');
  await page.click('main .panel .row[data-open="issue"] >> nth=0');
  await settle();
  await page.click('aside.pane .close');
  await settle();
  assert.equal(await paneOpen(), false, 'close did not close the pane');
});

// 8. nav filter
await check('8 / focuses the nav filter; typing comp shows nimbus»comp« and only compliance; Enter jumps to #compliance', async () => {
  await go('#overview');
  await page.mouse.click(W - 4, H - 4);
  await page.keyboard.press('/');
  assert.equal(await page.evaluate(() => document.activeElement && document.activeElement.closest('nav.nav') !== null), true, 'filter not focused');
  await page.keyboard.type('comp');
  const n = await navInfo();
  assert.equal(n.prompt, 'nimbus»comp«');
  assert.deepEqual(n.items.filter((i) => !i.hidden).map((i) => i.text), ['compliance']);
  await page.keyboard.press('Enter');
  await settle();
  assert.equal(await hash(), '#compliance');
  assert.equal(await selected(), 'compliance');
  assert.equal((await navInfo()).prompt, 'nimbus»«', 'filter not cleared');
  assert.equal((await navInfo()).items.filter((i) => !i.hidden).length, 9);
});

// 9. digits, j/k, Enter
await check('9 1-9 jump to sections; j/k move an inverted selection in the focused list; Enter opens it in the pane', async () => {
  await page.mouse.click(W - 4, H - 4);
  for (let i = 0; i < 9; i++) {
    await page.keyboard.press(String(i + 1));
    await settle();
    assert.equal(await hash().then((h) => h.slice(1).split('?')[0]), HASHES[i], 'key ' + (i + 1));
  }
  await go('#findings?severity=HIGH');
  await page.click('main .panel > .panel-h');
  await page.keyboard.press('j');
  await page.keyboard.press('j');
  await page.keyboard.press('k');
  await page.keyboard.press('j');
  const s = await page.evaluate(() => {
    const k = [...document.querySelectorAll('main .kbsel')];
    const rows = [...document.querySelectorAll('main .panel .row[data-open="issue"]')];
    const cs = k[0] && getComputedStyle(k[0]);
    return { n: k.length, idx: rows.indexOf(k[0]), bg: cs && cs.backgroundColor, color: cs && cs.color, text: k[0] && k[0].textContent };
  });
  assert.equal(s.n, 1);
  assert.equal(s.idx, 1, 'j j k j should select the second row');
  assert.equal(s.bg, BLACK); assert.equal(s.color, WHITE);
  await page.keyboard.press('Enter');
  await settle();
  assert.ok(await paneOpen(), 'Enter did not open the pane');
  await page.keyboard.press('Escape');
  await settle();
});

// 10. Open query -> sql
await check('10 pane "Open query" opens sql and runs the query (static: prints the CLI command)', async () => {
  await go('#findings?severity=HIGH&view=findings');
  await page.click('main .panel .row[data-open="finding"] >> nth=0');
  await settle();
  await page.click('aside.pane .row[data-open="sql"]');
  await settle();
  assert.match(await hash(), /^#sql/);
  assert.equal(await paneOpen(), false, 'pane should close on section change');
  const t = await page.evaluate(() => document.querySelector('main .panel').textContent);
  assert.match(t, /cloud-posture query "SELECT canonical_id/);
});

// 11. attack paths graph
await check('11 attack paths: embedded Cytoscape graph renders; selecting a path updates the hash; a step opens the pane', async () => {
  await go('#paths');
  const g = await page.evaluate(() => { const r = document.querySelector('main .panel .view'); return { cy: !!(r && r._cy), nodes: r && r._cy ? r._cy.nodes().length : 0, canv: document.querySelectorAll('main canvas').length }; });
  assert.ok(g.cy && g.nodes > 1 && g.canv > 0, JSON.stringify(g));
  await page.click('main .row[data-open="path"] >> nth=0');
  await settle();
  assert.match(await hash(), /^#paths\?pathId=/);
  const step = await page.$('main .row[data-open="finding"]');
  assert.ok(step, 'no clickable step');
  await step.click();
  await settle();
  assert.ok(await paneOpen());
  await page.keyboard.press('Escape');
});

// 12. compliance control -> findings
await check('12 compliance: a failing control opens findings filtered to it', async () => {
  await go('#compliance');
  const n = await page.evaluate(() => { const r = document.querySelector('main .row[data-open="findings"]'); return r && r.textContent; });
  assert.ok(n, 'no clickable control');
  await page.click('main .row[data-open="findings"] >> nth=0');
  await settle();
  assert.match(await hash(), /^#findings\?.*control=/);
  assert.ok((await issueRows()).length > 0, 'no Issue rows for the control');
});

// 13. reverse video
await check('13 reverse row flips panels to black/white only (nav and page unchanged), persists across reload, toggles back', async () => {
  await go('#overview');
  await page.click('nav.nav [data-action="reverse"]');
  await settle();
  const r = await page.evaluate(() => {
    const p = getComputedStyle(document.querySelector('main .panel')), n = getComputedStyle(document.querySelector('nav.nav'));
    const h = getComputedStyle(document.querySelector('main .panel > .panel-h'));
    return { pbg: p.backgroundColor, pfg: p.color, hfg: h.color, nbg: n.backgroundColor, nfg: n.color, body: getComputedStyle(document.body).backgroundColor, ls: localStorage.getItem('nimbus-xterm-rv') };
  });
  assert.deepEqual(r, { pbg: BLACK, pfg: WHITE, hfg: WHITE, nbg: WHITE, nfg: BLACK, body: BLACK, ls: '1' });
  const a = await audit();
  assert.deepEqual(a.bad, [], a.bad.join('; '));
  await shot(page, 'v2-reverse.png');
  await page.reload();
  await page.waitForSelector('main .panel');
  assert.equal(await page.evaluate(() => getComputedStyle(document.querySelector('main .panel')).backgroundColor), BLACK, 'rv not persisted');
  await page.click('nav.nav [data-action="reverse"]');
  await settle();
  assert.equal(await page.evaluate(() => getComputedStyle(document.querySelector('main .panel')).backgroundColor), WHITE);
});

// 14. no leaks across section switches
await check('14 switching sections 10x (paths <-> overview) leaves window/document listeners and the live registry at baseline', async () => {
  const p = await ctx.newPage();
  const e = []; watch(p, e);
  await p.addInitScript(() => {
    const reg = new Map();
    const key = (t, type, opts) => (t === window ? 'w:' : 'd:') + type + ':' + !!(opts === true || (opts && opts.capture));
    const add = EventTarget.prototype.addEventListener, rem = EventTarget.prototype.removeEventListener;
    EventTarget.prototype.addEventListener = function (type, fn, opts) {
      if ((this === window || this === document) && fn) { const k = key(this, type, opts); if (!reg.has(k)) reg.set(k, new Set()); reg.get(k).add(fn); }
      return add.call(this, type, fn, opts);
    };
    EventTarget.prototype.removeEventListener = function (type, fn, opts) {
      if ((this === window || this === document) && fn) { const k = key(this, type, opts); if (reg.has(k)) reg.get(k).delete(fn); }
      return rem.call(this, type, fn, opts);
    };
    window.__listenerCount = () => { let n = 0; reg.forEach((v) => { n += v.size; }); return n; };
  });
  await p.goto(reportURL + '#overview');
  await p.waitForSelector('main .panel');
  const base = await p.evaluate(() => ({ l: window.__listenerCount(), r: window.CWM._clients.registry.length }));
  for (let i = 0; i < 10; i++) {
    await p.evaluate(() => { window.CWM.navigate('paths'); window.CWM.open('finding', 'x'); window.CWM.navigate('overview'); });
  }
  await p.waitForTimeout(60);
  const after = await p.evaluate(() => ({ l: window.__listenerCount(), r: window.CWM._clients.registry.length, cy: document.querySelectorAll('canvas').length }));
  assert.equal(after.r, base.r, 'registry grew ' + JSON.stringify({ base, after }));
  assert.equal(after.l, base.l, 'listeners leaked ' + JSON.stringify({ base, after }));
  assert.equal(after.cy, 0, 'cytoscape canvases left behind');
  assert.deepEqual(e, []);
  await p.close();
});

// 15. live mode
await check('15 live: hello ignored; findings_updated refetches without reload, re-renders, #FC8814 on unfocused panels until focused; filter keeps focus; reconnects', async () => {
  const html = readFileSync(report, 'utf8').replace('"mode":"static"', '"mode":"live"');
  assert.ok(html.includes('"mode":"live"'), 'could not switch the report to live mode');
  const lctx = await browser.newContext({ viewport: { width: W, height: H } });
  const lp = await lctx.newPage();
  const lerr = []; watch(lp, lerr);
  let fetched = 0;
  const sockets = [];
  await lp.route('http://nimbus.test/', (r) => r.fulfill({ contentType: 'text/html; charset=utf-8', body: html }));
  await lp.route('http://nimbus.test/api/**', (r) => { fetched++; r.fulfill({ contentType: 'application/json', body: r.request().url().includes('/api/findings') ? '[]' : '{"open":0}' }); });
  await lp.routeWebSocket('ws://nimbus.test/ws', (ws) => { sockets.push(ws); });
  await lp.goto('http://nimbus.test/');
  await lp.waitForSelector('main .panel');
  for (let i = 0; i < 40 && !sockets.length; i++) await lp.waitForTimeout(25);
  assert.equal(sockets.length, 1, 'no WebSocket to /ws');
  await lp.evaluate(() => { window.__noReload = 1; });
  sockets[0].send(JSON.stringify({ type: 'hello', time: new Date().toISOString() }));
  await lp.waitForTimeout(60);
  assert.equal(fetched, 0, 'hello caused a refetch');
  let ps = await panels(lp);
  assert.ok(ps.every((p) => p.borderColor !== URGENT), 'hello marked urgency');
  sockets[0].send(JSON.stringify({ type: 'findings_updated', time: new Date().toISOString() }));
  for (let i = 0; i < 40 && fetched < 3; i++) await lp.waitForTimeout(25);
  await lp.waitForTimeout(60);
  assert.equal(fetched, 3, 'expected /api/summary, /api/findings and /api/issues refetch');
  assert.equal(await lp.evaluate(() => window.__noReload), 1, 'page reloaded');
  ps = await panels(lp);
  const text = await lp.evaluate(() => document.querySelector('main').textContent);
  assert.match(text, /findings updated/);
  assert.doesNotMatch(text, /hello/);
  assert.equal(ps[0].borderColor, ACTIVE, 'focused panel must stay #CCCCCC');
  const urgent = ps.filter((p) => p.borderColor === URGENT);
  assert.equal(urgent.length, ps.length - 1, 'every unfocused panel should be urgent: ' + ps.map((p) => p.borderColor).join(','));
  await lp.click(`main .panel[data-key="${urgent[0].key}"] > .panel-h`);
  ps = await panels(lp);
  assert.equal(ps.find((p) => p.key === urgent[0].key).borderColor, ACTIVE, 'focusing did not clear urgency');
  // typing in the findings filter survives a live re-render
  await lp.evaluate(() => { location.hash = '#findings'; });
  await lp.waitForSelector('main input[aria-label="filter"]');
  await lp.evaluate(() => { const i = document.querySelector('main input[aria-label="filter"]'); i.value = ''; i.focus(); i.__mark = 1; });
  await lp.keyboard.type('sev=HI');
  const b2 = fetched;
  sockets[0].send(JSON.stringify({ type: 'findings_updated', time: new Date().toISOString() }));
  for (let i = 0; i < 40 && fetched < b2 + 3; i++) await lp.waitForTimeout(25);
  await lp.waitForTimeout(60);
  await lp.keyboard.type('GH');
  const f = await lp.evaluate(() => { const i = document.querySelector('main input[aria-label="filter"]'); return { v: i.value, focused: document.activeElement === i, same: i.__mark === 1 }; });
  assert.deepEqual(f, { v: 'sev=HIGH', focused: true, same: true });
  sockets[0].close();
  for (let i = 0; i < 100 && sockets.length < 2; i++) await lp.waitForTimeout(25);
  assert.equal(sockets.length, 2, 'socket did not reconnect after 1s backoff');
  assert.deepEqual(lerr, []);
  await lctx.close();
});

// 16. XSS
await check('16 XSS: </script><img onerror> in a finding title (and in the hash) renders as text; __pwned undefined, 0 img', async () => {
  const PAY = '</script><img src=x onerror=window.__pwned=1>';
  const src = readFileSync(report, 'utf8');
  const i = src.indexOf('"title":"');
  assert.ok(i > 0, 'no finding title in the report');
  // what Go's json.Marshal + jsonSafe would emit for the payload
  const enc = PAY.replace(/</g, '\\u003c').replace(/>/g, '\\u003e');
  let html = src.slice(0, i + 9) + enc + src.slice(i + 9);
  const k = html.indexOf('"kind":"single","title":"');
  assert.ok(k > 0, 'no Issue title in the report');
  html = html.slice(0, k + 25) + enc + html.slice(k + 25);
  const dir = mkdtempSync(join(tmpdir(), 'nimbus-xss-'));
  const f = join(dir, 'index.html');
  writeFileSync(f, html);
  const xp = await ctx.newPage();
  const xe = []; watch(xp, xe);
  await xp.goto(pathToFileURL(f).href + '#findings?status=all&q=' + encodeURIComponent('<img src=x onerror=window.__pwned=1>'));
  await xp.waitForSelector('main .panel');
  await xp.evaluate(() => { location.hash = '#findings?status=all'; });
  await xp.waitForTimeout(60);
  const id = await xp.evaluate((p) => { const D = JSON.parse(document.getElementById('data').textContent); const x = D.findings.find((y) => y.title.startsWith(p)); return x && x.id; }, PAY.slice(0, 20));
  assert.ok(id, 'payload finding not in data');
  await xp.evaluate((x) => window.CWM.open('finding', x), id);
  for (const h of ['#overview', '#risk', '#paths', '#compliance', '#coverage']) { await xp.evaluate((x) => { location.hash = x; }, h); await xp.waitForTimeout(40); }
  await xp.evaluate(() => { location.hash = '#findings?status=all'; });
  await xp.waitForTimeout(60);
  await xp.evaluate((x) => window.CWM.open('finding', x), id);
  await xp.waitForTimeout(60);
  const r = await xp.evaluate(() => ({ pwned: window.__pwned, imgs: document.querySelectorAll('img').length, text: document.querySelector('aside.pane').textContent }));
  assert.equal(r.pwned, undefined);
  assert.equal(r.imgs, 0);
  assert.ok(r.text.includes(PAY), 'payload not shown as text in the pane');
  const iid = await xp.evaluate((p) => { const D = JSON.parse(document.getElementById('data').textContent); const x = D.issues.find((y) => (y.title || '').startsWith(p)); return x && x.id; }, PAY.slice(0, 20));
  assert.ok(iid, 'payload issue not in data');
  await xp.evaluate((x) => window.CWM.open('issue', x), iid);
  await xp.waitForTimeout(60);
  const r2 = await xp.evaluate(() => ({ pwned: window.__pwned, imgs: document.querySelectorAll('img').length, text: (document.querySelector('aside.pane') || {}).textContent || '' }));
  assert.equal(r2.pwned, undefined);
  assert.equal(r2.imgs, 0);
  assert.ok(r2.text.includes(PAY), 'issue payload not shown as text in the pane');
  assert.deepEqual(xe, []);
  await xp.close();
});

// ---- Track I: the dashboard shows the new truth (Issues, coverage, trend, explain, paths, layout, live) ----

// 17. Issues first: toxic combinations and the Issue pane
await check('17 Issues: combination Issues carry a "toxic" tag and list their weaknesses; an Issue row opens a pane with sources, confidence and evidence findings that click through', async () => {
  const combos = DATA.issues.filter((i) => openIssue(i) && i.kind === 'combination');
  assert.ok(combos.length > 0, 'test data has no combination Issue');
  await go('#findings?deadends=1');
  const rows = await page.evaluate(() => [...document.querySelectorAll('main .panel .row[data-open="issue"]')].map((r) => ({ text: r.textContent, toxic: !!r.querySelector('.toxic'), toxicColor: r.querySelector('.toxic') && getComputedStyle(r.querySelector('.toxic')).color, weak: (r.querySelector('.weak') || {}).textContent || '' })));
  const tox = rows.filter((r) => r.toxic);
  assert.equal(tox.length, combos.length, 'toxic rows vs combination Issues');
  tox.forEach((r) => {
    assert.match(r.text, /toxic/);
    assert.equal(r.toxicColor, RED, 'toxic tag is red3 text');
    assert.match(r.weak, /\S+ \+ \S+/, 'combination row must list its weaknesses: ' + r.weak);
  });
  assert.equal(rows.filter((r) => !r.toxic && /toxic/.test(r.text)).length, 0, 'single Issues must not be tagged toxic');
  await page.click('main .panel .row[data-open="issue"]:has(.toxic) >> nth=0');
  await settle();
  assert.ok(await paneOpen(), 'Issue pane not open');
  const title = (await textOf('aside.pane .panel-h .t')).trim();
  const is = combos.find((c) => c.title === title);
  assert.ok(is, 'pane title is not a combination Issue title: ' + title);
  const pane = await textOf('aside.pane .panel-b');
  assert.match(pane, /toxic/);
  assert.match(pane, /sources\s+\S/);
  assert.ok(pane.includes(is.confidence.toFixed(2)), 'confidence ' + is.confidence + ' missing');
  assert.ok(pane.includes('Evidence (' + is.finding_ids.length + ' finding'), 'evidence heading missing');
  const ev = await page.evaluate(() => [...document.querySelectorAll('aside.pane .row[data-ev]')].map((r) => r.getAttribute('data-ev')));
  assert.deepEqual(ev.slice().sort(), is.finding_ids.slice().sort(), 'evidence rows vs finding_ids');
  await page.click('aside.pane .row[data-ev] >> nth=0');
  await settle();
  const f = DATA.findings.find((x) => x.id === ev[0]);
  assert.equal((await textOf('aside.pane .panel-h .t')).trim(), f.title, 'evidence row did not open its finding');
  await page.keyboard.press('Escape');
  await settle();
  // raw findings stay one click away
  await go('#findings?view=findings');
  assert.ok((await findingsRows()).length > 0, 'view=findings shows raw finding rows');
  assert.equal((await issueRows()).length, 0);
});

// 18. Coverage honesty
await check('18 coverage: per provider/account ok/denied/skipped/error/timeout counts with reasons, denied and timeout in red3; overview links to it; empty coverage falls back to tool runs', async () => {
  await go('#overview');
  const ov = await textOf('main .panel[data-key="coverage"]');
  assert.ok(ov && /denied/.test(ov) && /timeout/.test(ov), 'overview coverage panel lacks status counts: ' + ov);
  await page.click('main .panel[data-key="coverage"] [data-open="coverage"] >> nth=0');
  await settle();
  assert.equal(await hash(), '#coverage');
  const t = await textOf('main .panel');
  for (const h of ['PROVIDER', 'ACCOUNT', 'OK', 'DENIED', 'SKIPPED', 'ERROR', 'TIMEOUT']) assert.ok(t.includes(h), 'coverage header lacks ' + h);
  assert.equal(await page.evaluate(() => document.querySelectorAll('main [data-cov]').length), new Set(DATA.coverage.map((c) => (c.provider || '-') + '/' + c.account)).size, 'one row per provider/account');
  // a payload with denied/timeout/skipped/error entries
  const url = variant((D) => {
    const sid = D.coverage[0] ? D.coverage[0].scan_id : 'x';
    D.coverage.push(
      { scan_id: sid, provider: 'aws', account: '111111111111', api: 'iam:GetAccountAuthorizationDetails', status: 'denied', reason: 'AccessDenied: not authorized to perform iam:GetAccountAuthorizationDetails', at: '2026-10-09T00:00:00Z' },
      { scan_id: sid, provider: 'aws', account: '111111111111', api: 'ec2:DescribeInstances eu-west-1', status: 'timeout', reason: 'context deadline exceeded after 7s', at: '2026-10-09T00:00:00Z' },
      { scan_id: sid, provider: 'aws', account: '111111111111', api: 's3:ListBuckets', status: 'ok', at: '2026-10-09T00:00:00Z' },
      { scan_id: sid, provider: 'gcp', account: 'proj-a', api: 'collector:gcp', status: 'skipped', reason: 'not_installed', at: '2026-10-09T00:00:00Z' },
      { scan_id: sid, provider: 'azure', account: 'sub-1', api: 'Microsoft.Network/networkSecurityGroups', status: 'error', reason: 'HTTP 500 from ARM', at: '2026-10-09T00:00:00Z' });
  }, 'cov');
  const p = await ctx.newPage();
  const e = []; watch(p, e);
  await p.goto(url + '#coverage');
  await p.waitForSelector('main .panel');
  await shot(p, 'v3-coverage.png');
  const r = await p.evaluate(() => {
    const row = document.querySelector('main [data-cov="aws/111111111111"]');
    const c = (cls) => { const x = row && row.querySelector('.c-' + cls); return x ? { n: x.textContent.trim(), color: getComputedStyle(x).color } : null; };
    const reasons = [...document.querySelectorAll('main [data-reason]')].map((x) => ({ st: x.getAttribute('data-reason'), text: x.textContent, color: getComputedStyle(x.querySelector('.why') || x).color }));
    return { ok: c('ok'), denied: c('denied'), timeout: c('timeout'), reasons };
  });
  assert.deepEqual(r.ok && r.ok.n, '1');
  assert.deepEqual(r.denied, { n: '1', color: RED });
  assert.deepEqual(r.timeout, { n: '1', color: RED });
  const den = r.reasons.find((x) => x.st === 'denied');
  assert.ok(den && den.text.includes('AccessDenied: not authorized') && den.text.includes('iam:GetAccountAuthorizationDetails'), 'denied reason not listed');
  assert.equal(den.color, RED);
  assert.equal(r.reasons.find((x) => x.st === 'timeout').color, RED);
  assert.ok(r.reasons.find((x) => x.st === 'skipped' && x.text.includes('not_installed')), 'skipped reason not listed');
  assert.ok(r.reasons.find((x) => x.st === 'error' && x.text.includes('HTTP 500')), 'error reason not listed');
  await p.goto(url + '#overview');
  await p.waitForSelector('main .panel[data-key="coverage"]');
  assert.equal(await colorOf('main .panel[data-key="coverage"] .c-denied', p), RED, 'overview denied count not red3');
  // fallback: no coverage table -> the old tool-run table
  await p.goto(variant((D) => { D.coverage = []; }, 'nocov') + '#coverage');
  await p.waitForSelector('main .panel');
  const ft = await textOf('main .panel', p);
  assert.ok(ft.includes('TOOL') && ft.includes('STATUS'), 'fallback to scan.tools missing');
  assert.deepEqual(e, []);
  await p.close();
});

// 18b. the real report's coverage view (for the screenshot set)
await go('#coverage');
await shot(page, 'v3-coverage-report.png');

// 19. Trend
await check('19 trend: a monochrome block-character sparkline per severity from the scans history; per-scan Issue lifecycle sparklines (new / resolved / reopened / verified / regressed) and the verified share from governance.scan_trend; "totals only" without them', async () => {
  await go('#overview');
  const probe = (p) => p.evaluate(() => {
    const e = document.querySelector('main .panel[data-key="trend"]');
    if (!e) return null;
    const sp = (sel) => [...e.querySelectorAll(sel)].map((s) => ({ t: s.textContent, color: getComputedStyle(s).color, label: s.getAttribute('data-sev') || s.getAttribute('data-trend') }));
    return { text: e.textContent, sev: sp('.spark[data-sev]'), life: sp('.spark[data-trend]') };
  });
  const tr = await probe(page);
  assert.ok(tr, 'no trend panel on the overview');
  assert.deepEqual(tr.sev.map((s) => s.label), ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
  const n = Math.min(DATA.scans.length, 24);
  tr.sev.forEach((s) => {
    assert.match(s.t, /^[▁▂▃▄▅▆▇█]+$/, 'sparkline chars: ' + s.t);
    assert.equal([...s.t].length, n, 'one cell per scan');
    assert.equal(s.color, BLACK, 'sparkline must be monochrome');
  });
  assert.match(tr.text, /crit/);
  // The real report: the store recorded the scan's Issue trend (governance.scan_trend).
  const rows = ((DATA.governance || {}).scan_trend || []).filter((r) => r.issue_trend);
  assert.ok(rows.length > 0, 'the payload carries no per-scan Issue trend (governance.scan_trend)');
  assert.deepEqual(tr.life.map((s) => s.label), ['new', 'resolved', 'reopened', 'verified_fixed', 'regressed', 'verified_share']);
  tr.life.forEach((s) => {
    assert.match(s.t, /^[▁▂▃▄▅▆▇█]+$/, 'lifecycle sparkline chars: ' + s.t);
    assert.equal([...s.t].length, Math.min(rows.length, 24), 'one cell per scan with counts');
    assert.equal(s.color, BLACK, 'lifecycle sparkline must be monochrome');
  });
  const last = rows[0].issue_trend;
  assert.ok(tr.text.includes(last.new + ' new / ' + last.resolved + ' resolved'), 'latest counts missing: ' + tr.text);
  assert.match(tr.text, /% of closures verified/);
  // A three-scan history: the sparklines follow it, the verified share is plotted.
  const tri = (nw, rs, ro, vf, rg, share) => ({ issue_trend: { new: nw, resolved: rs, reopened: ro, verified_fixed: vf, regressed: rg, open: 5, verified_share: share } });
  let url = variant((D) => {
    D.governance = Object.assign({}, D.governance || {}, { scan_trend: [tri(1, 4, 2, 3, 1, 0.75), tri(0, 2, 0, 1, 0, 0.5), tri(7, 0, 0, 0, 0, 0)] });
  }, 'trend');
  let p = await ctx.newPage();
  await p.goto(url + '#overview');
  await p.waitForSelector('main .panel[data-key="trend"]');
  const t3 = await probe(p);
  const life = Object.fromEntries(t3.life.map((s) => [s.label, s.t]));
  assert.equal(life.new, '█▁▂', 'new per scan (7, 0, 1 oldest → newest): ' + life.new);
  assert.equal([...life.verified_share].length, 3);
  assert.ok(new Set([...life.verified_share]).size > 1, 'verified share must vary: ' + life.verified_share);
  assert.match(t3.text, /1 new \/ 4 resolved \/ 2 reopened \/ 3 verified fixed \/ 1 regressed since last scan · 75% of closures verified/);
  await p.close();
  // No lifecycle counts anywhere: the panel says the history is totals only.
  url = variant((D) => {
    if (D.governance) D.governance.scan_trend = [];
    D.scans = D.scans.map((x) => { const y = Object.assign({}, x); delete y.issue_trend; return y; });
  }, 'trend-none');
  p = await ctx.newPage();
  await p.goto(url + '#overview');
  await p.waitForSelector('main .panel[data-key="trend"]');
  assert.match(await textOf('main .panel[data-key="trend"]', p), /totals only/);
  await p.close();
});

// 20. Explain
await check('20 explain: the finding pane and the Issue pane show base, each factor as "name ×mult — reason", not-scored factors under "missing", top paths, and "score version" in the footer', async () => {
  const top = DATA.risk.find((r) => r.explanation && (r.explanation.factors || []).some((f) => f.status === 'not scored'));
  assert.ok(top, 'no explained risk entry with a not-scored factor');
  const x = top.explanation;
  await go('#findings');
  await page.evaluate((id) => window.CWM.open('finding', id), top.finding.id);
  await settle();
  const t = await page.evaluate(() => [...document.querySelectorAll('aside.pane .panel-b .ln')].map((l) => l.textContent));
  const all = t.join('\n');
  assert.ok(all.includes('base ' + x.base.toFixed(1) + ' — ' + x.base_reason), 'base line missing');
  const scored = x.factors.filter((f) => f.status !== 'not scored');
  scored.forEach((f) => {
    const re = new RegExp(f.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s+×' + f.multiplier.toFixed(2) + ' — ');
    assert.ok(t.some((l) => re.test(l) && l.includes(f.reason.slice(0, 20))), 'factor line missing: ' + f.name);
  });
  const mi = t.findIndex((l) => l.trim() === 'missing');
  assert.ok(mi > 0, 'no "missing" heading');
  x.factors.filter((f) => f.status === 'not scored').forEach((f) => {
    assert.ok(t.slice(mi).some((l) => l.includes(f.name)), 'not-scored factor not under missing: ' + f.name);
    assert.ok(!t.slice(0, mi).some((l) => new RegExp('^\\s*' + f.name + '\\s+×').test(l)), 'not-scored factor listed as a factor: ' + f.name);
  });
  if ((x.top_paths || []).length) {
    assert.ok(t.some((l) => l.trim() === 'top paths'), 'no top paths heading');
    assert.ok(await page.$('aside.pane .row[data-open="paths"][data-top]'), 'top path not clickable');
  }
  const last = t.filter((l) => l.trim()).pop();
  assert.equal(last.trim(), 'score version ' + x.version, 'pane footer: ' + last);
  await shot(page, 'v3-finding-explain.png');
  const iss = DATA.issues.find((i) => (i.finding_ids || []).includes(top.finding.id));
  await page.evaluate((id) => window.CWM.open('issue', id), iss.id);
  await settle();
  const it = await textOf('aside.pane .panel-b');
  assert.ok(it.includes('base ' + x.base.toFixed(1)), 'Issue pane lacks the explanation');
  assert.match(it, /score version \S+$/);
  await page.keyboard.press('Escape');
});

// 21. Paths
await check('21 paths: per-hop because under each step; dead ends: N with [show dead ends] filtering Issues; a choke point shows only its path_ids and "closes N paths"; min fix set shows exact/verified; incomplete not counted; suppressed (trusted) and weak_link rendered', async () => {
  const A = DATA.analysis;
  await go('#paths');
  await page.click('main .row[data-open="path"] >> nth=0');
  await settle();
  const sel = DATA.paths.slice().sort((a, b) => b.score - a.score)[0];
  const det = await page.evaluate(() => [...document.querySelectorAll('main .ln.because')].map((l) => ({ text: l.textContent, color: getComputedStyle(l).color })));
  const withBecause = sel.steps.filter((s) => s.because);
  assert.ok(withBecause.length > 0, 'test data path has no because');
  assert.equal(det.length, withBecause.length, 'one because line per hop');
  det.forEach((d, i) => assert.ok(d.text.includes(withBecause[i].because.slice(0, 30)), 'because text ' + i));
  const head = await textOf('main .panel .paths-head');
  assert.ok(head.startsWith(nIssues(DATA) + ' attack path Issue'), head);
  assert.ok(head.includes('dead ends: ' + A.dead_ends.count), 'dead ends line: ' + head);
  assert.ok(await page.$('main .panel .act[data-toggle="deadends"]'), 'no [show dead ends] toggle');
  assert.equal((await textOf('main .panel .act[data-toggle="deadends"]')).trim(), '[show dead ends]');
  await page.click('main .panel .act[data-toggle="deadends"]');
  await settle();
  assert.equal((await textOf('main .panel .act[data-toggle="deadends"]')).trim(), '[hide dead ends]');
  assert.match(await hash(), /deadends=1/);
  assert.equal(await page.evaluate(() => document.querySelectorAll('main .row[data-deadend]').length), A.dead_ends.count, 'dead-end list');
  // min fix set flags
  const mfs = await textOf('main .panel .mfs-head');
  assert.match(mfs, new RegExp((A.min_fix_exact ? 'exact' : 'greedy') + '.*' + (A.min_fix_verified ? 'verified' : 'unverified')));
  // choke point drill-in
  const cp = A.choke_points.slice().sort((a, b) => (b.path_ids || []).length - (a.path_ids || []).length)[0];
  await page.click(`main .row[data-choke="${cp.node_id}"]`);
  await settle();
  assert.match(await hash(), /choke=/);
  const vis = await page.evaluate(() => [...document.querySelectorAll('main .row[data-open="path"]')].filter((r) => r.offsetParent !== null).map((r) => r.getAttribute('data-path')));
  // one row per path Issue: the groups with at least one hop variant through the choke point
  const wantVis = DATA.path_groups.filter((g) => g.path_ids.some((id) => cp.path_ids.includes(id))).map((g) => g.best_id);
  assert.deepEqual(vis.slice().sort(), wantVis.slice().sort(), 'choke point must show only the Issues of its path_ids');
  assert.ok((await textOf('main .panel')).includes('closes ' + cp.closes_n + ' path'), 'no "closes N paths" line');
  await shot(page, 'v3-paths-choke.png');
  // Issue list: dead ends hidden by default, toggle shows them
  const rcj = A.reaches_crown_jewel || {};
  const open = DATA.issues.filter(openIssue);
  await go('#findings');
  assert.equal((await issueRows()).length, open.filter((i) => rcj[i.resource_id] !== false).length, 'dead-end Issues must be hidden by default');
  assert.ok((await textOf('main .panel .count')).length > 0);
  await page.click('main .panel .act[data-toggle="deadends"]');
  await settle();
  assert.equal((await issueRows()).length, open.length, '[show dead ends] must show every Issue');
  // incomplete / suppressed / weak_link
  const url = variant((D) => {
    D.analysis.incomplete = [Object.assign({}, D.paths[0], { id: 'inc-1', name: 'incomplete prefix' })];
    D.analysis.suppressed = [{ node_id: 'sg-trusted', name: 'office-ssh', exposure: 'trusted', exposure_cidrs: ['203.0.113.0/24'], reason: 'every source inside trusted_cidrs', finding_ids: [] }];
    D.paths.find((x) => x.id === D.path_groups[1].best_id).weak_link = true;
  }, 'paths');
  const p = await ctx.newPage();
  const e = []; watch(p, e);
  await p.goto(url + '#paths');
  await p.waitForSelector('main .paths-head');
  const r = await p.evaluate((wid) => {
    const h = document.querySelector('main .paths-head');
    const inc = h.querySelector('.incomplete');
    const wl = document.querySelector(`main .row[data-path="${wid}"]`);
    const sup = [...document.querySelectorAll('main .ln')].find((l) => l.textContent.trim() === 'suppressed (trusted)');
    return { head: h.textContent, inc: inc && { t: inc.textContent, c: getComputedStyle(inc).color }, wl: wl && { cls: wl.className, c: getComputedStyle(wl.querySelector('.pname')).color }, sup: !!sup, body: document.querySelector('main .panel').textContent };
  }, DATA.path_groups[1].best_id);
  assert.ok(r.head.startsWith(nIssues(DATA) + ' attack path Issue'), 'incomplete paths must not be counted: ' + r.head);
  assert.deepEqual(r.inc, { t: '1 incomplete', c: GRAY });
  assert.ok(r.sup, 'no "suppressed (trusted)" heading');
  assert.ok(r.body.includes('office-ssh') && r.body.includes('203.0.113.0/24'), 'suppressed entry not listed');
  assert.ok(r.wl && r.wl.c === GRAY, 'weak_link path not grey: ' + JSON.stringify(r.wl));
  assert.deepEqual(e, []);
  await p.close();
});

// 22. Re-layout on resize
await check('22 re-layout: opening the pane, closing it and resizing the window re-truncate the findings table to the panel width', async () => {
  const widths = () => page.evaluate(() => {
    const body = document.querySelector('main .panel .panel-b');
    const hd = body.querySelector('.thead');
    const rg = document.createRange(); rg.selectNodeContents(hd);
    return { head: rg.getBoundingClientRect().width, panel: body.clientWidth };
  });
  await go('#findings?deadends=1');
  const w0 = await widths();
  assert.ok(w0.head <= w0.panel, 'header wider than panel at load ' + JSON.stringify(w0));
  await page.click('main .panel .row[data-open="issue"] >> nth=0');
  await page.waitForTimeout(250);
  const w1 = await widths();
  assert.ok(w1.head <= w1.panel, 'pane open: findings header ' + w1.head + 'px > panel ' + w1.panel + 'px');
  await shot(page, 'v3-findings-issue-pane.png');
  await page.keyboard.press('Escape');
  await page.waitForTimeout(250);
  const w2 = await widths();
  assert.ok(w2.head <= w2.panel && w2.head > w1.head, 'pane closed: header did not widen again ' + JSON.stringify({ w1, w2 }));
  await page.setViewportSize({ width: 1100, height: H });
  await page.waitForTimeout(250);
  const w3 = await widths();
  assert.ok(w3.head <= w3.panel, 'window resize: header ' + w3.head + ' > panel ' + w3.panel);
  await page.setViewportSize({ width: W, height: H });
  await page.waitForTimeout(250);
});

// 23. Live summary with Issue counts
await check('23 live: /api/summary Issue counts (unit "issues" or an issues object) drive the overview; the legacy shape keeps working', async () => {
  const html = SRC.replace('"mode":"static"', '"mode":"live"');
  for (const shape of ['top', 'nested', 'legacy']) {
    const lctx = await browser.newContext({ viewport: { width: W, height: H } });
    const lp = await lctx.newPage();
    const lerr = []; watch(lp, lerr);
    const sockets = [];
    const counts = { total: 9, open: 7, resolved: 2, combinations: 1, by_severity: { CRITICAL: 3, HIGH: 4 }, by_provider: { aws: 7 }, by_account: {} };
    const sum = shape === 'top' ? Object.assign({ unit: 'issues', findings: { open: 11, total: 20 } }, counts)
      : shape === 'nested' ? { open: 11, total: 20, issues: counts } : { open: 11, total: 20, by_severity: { HIGH: 11 } };
    await lp.route('http://nimbus.test/', (r) => r.fulfill({ contentType: 'text/html; charset=utf-8', body: html }));
    await lp.route('http://nimbus.test/api/**', (r) => {
      const u = r.request().url();
      r.fulfill({ contentType: 'application/json', body: u.includes('/api/summary') ? JSON.stringify(sum) : u.includes('/api/findings') ? JSON.stringify(DATA.findings.filter((f) => f.status === 'FAIL')) : u.includes('/api/issues') ? JSON.stringify(DATA.issues) : '{}' });
    });
    await lp.routeWebSocket('ws://nimbus.test/ws', (ws) => { sockets.push(ws); });
    await lp.goto('http://nimbus.test/');
    await lp.waitForSelector('main .ov-open');
    for (let i = 0; i < 40 && !sockets.length; i++) await lp.waitForTimeout(25);
    sockets[0].send(JSON.stringify({ type: 'findings_updated' }));
    await lp.waitForFunction(() => /findings updated/.test(document.querySelector('main').textContent), null, { timeout: 3000 });
    const n = await lp.evaluate(() => ({ open: document.querySelector('main .ov-open').textContent.trim(), crit: (document.querySelector('main .panel[data-key="risk"] [data-open="findings"].sev-CRITICAL') || {}).textContent }));
    if (shape === 'legacy') assert.equal(Number(n.open), DATA.issues.filter(openIssue).length, 'legacy summary: counts come from the Issue list');
    else { assert.equal(n.open, '7', shape + ': open from summary'); assert.equal(n.crit, '3', shape + ': CRITICAL from summary'); }
    assert.deepEqual(lerr, []);
    await lctx.close();
  }
});

// 24. Issue page (integration pass 3, delta #4): owner/SLA/due, suppression and ticket lines,
// linked Issues, the fix with its five remediation phases and the timeline, from issue_pages.
await check('24 Issue page: the Issue pane shows owner/SLA/due, suppression and ticket, linked Issues (clickable), the fix template with prerequisite/snapshot/fix/verify/rollback, and the timeline from issue_pages', async () => {
  const pages = DATA.issue_pages || {};
  const ids = Object.keys(pages);
  assert.ok(ids.length > 0, 'payload has no issue_pages');
  const id = ids.find((k) => (pages[k].fixes || []).length && (pages[k].linked_issues || []).length) || ids.find((k) => (pages[k].fixes || []).length) || ids[0];
  const pg = pages[id];
  await page.evaluate((x) => window.CWM.open('issue', x), id);
  await settle();
  const it = await textOf('aside.pane .panel-b');
  assert.match(it, /owner/, 'no owner line');
  assert.match(it, /SLA\s*\d+ days, due /, 'no SLA/due line');
  assert.match(it, /suppressed/, 'no suppression line');
  assert.match(it, /ticket/, 'no ticket line');
  if ((pg.fixes || []).length) {
    assert.ok(it.includes('template ' + pg.fixes[0].template), 'fix template not shown');
    const phases = await page.evaluate(() => [...document.querySelectorAll('aside.pane [data-phase]')].map((e) => e.getAttribute('data-phase')));
    ['prerequisite', 'snapshot', 'fix', 'verify', 'rollback'].forEach((ph) => assert.ok(phases.includes(ph), 'phase missing: ' + ph));
  }
  if ((pg.linked_issues || []).length) {
    const li = pg.linked_issues[0].id;
    assert.ok(await page.$('aside.pane .row[data-linked="' + li + '"]'), 'linked Issue row missing');
  }
  if ((pg.timeline || []).length) assert.ok(await page.$('aside.pane [data-tl]'), 'timeline missing');
  assert.match(it, /Timeline/);
  await shot(page, 'v4-issue-page.png');
  await page.keyboard.press('Escape');
  await settle();
});

// 25. Governance (integration pass 4): the owners panel shows overdue / on-time / MTTR and open /
// overdue by owner from D.governance; an overdue Issue row carries the red OVERDUE badge and the
// overview's overdue number drills through to exactly the overdue Issues.
await check('25 owners panel: overdue, on-time rate, MTTR and open/overdue by owner from the governance payload; overdue Issue rows carry a red OVERDUE badge', async () => {
  const G = DATA.governance;
  assert.ok(G && Array.isArray(G.owners), 'payload has no governance metrics');
  assert.ok(DATA.issues.some((i) => i.owner_source), 'Issues carry no governance owner_source');
  assert.ok(DATA.issues.filter(openIssue).some((i) => i.due_at), 'open Issues carry no due_at');
  await go('#overview');
  const panelText = (p) => p.evaluate(() => { const e = document.querySelector('.panel[data-key="owners"] .panel-b'); return e ? e.textContent : ''; });
  const t = await panelText(page);
  assert.match(t, /overdue \d+/, 'no overdue number');
  assert.match(t, /on-time/, 'no on-time rate');
  assert.match(t, /MTTR/, 'no MTTR');
  assert.match(t, /open \/ overdue by owner/, 'no owner table');
  assert.doesNotMatch(t, /\[governance placeholder\]|todo/i);
  const owners = await page.evaluate(() => [...document.querySelectorAll('.panel[data-key="owners"] [data-owner]')].map((e) => e.getAttribute('data-owner')));
  assert.deepEqual(owners, G.owners.slice(0, 6).map((o) => o.owner), 'owner rows vs payload');
  // Variant: one open Issue is overdue.
  const target = DATA.issues.find((i) => openIssue(i) && i.kind === 'single');
  const url = variant((D) => {
    const x = D.issues.find((i) => i.id === target.id);
    x.overdue = true; x.due_at = '2026-01-02T00:00:00Z'; x.owner = 'k8s-team@example.com';
    D.governance.open_past_due = 1;
    D.governance.owners = [{ owner: 'k8s-team@example.com', open: 1, overdue: 1 }].concat(D.governance.owners);
  }, 'overdue');
  const p2 = await ctx.newPage();
  const e2 = []; watch(p2, e2);
  await p2.goto(url + '#overview');
  await p2.waitForSelector('.panel[data-key="owners"]');
  assert.match(await panelText(p2), /overdue 1/);
  await p2.click('.panel[data-key="owners"] [data-open="findings"].red');
  await p2.waitForTimeout(80);
  const rows = await p2.evaluate(() => [...document.querySelectorAll('main .panel .row[data-open="issue"]')].map((r) => ({ id: r.getAttribute('data-issue'), badge: !!r.querySelector('.overdue'), color: r.querySelector('.overdue') && getComputedStyle(r.querySelector('.overdue')).color })));
  assert.equal(rows.length, 1, 'overdue drill-through must show exactly the overdue Issue');
  assert.equal(rows[0].id, target.id);
  assert.ok(rows[0].badge, 'no OVERDUE badge on the row');
  assert.equal(rows[0].color, 'rgb(205, 0, 0)', 'OVERDUE badge must be red3');
  await p2.close();
  assert.deepEqual(e2, []);
});

// 26. Paths: one row per path Issue (r2 shortfall #7, Wiz focused path view)
await check('26 paths: one row per path Issue with a "+N" variant badge where variants > 1; header count equals rows; the graph draws only the selected Issue\'s path (nodes == its hops); [show all paths] draws the fan; +N lists the variants', async () => {
  const G = DATA.path_groups;
  assert.ok(Array.isArray(G) && G.length > 0, 'payload has no path_groups');
  assert.equal(G.reduce((a, g) => a + g.path_ids.length, 0), DATA.paths.length, 'path_groups must cover every path once');
  await go('#paths');
  const rows = await page.evaluate(() => [...document.querySelectorAll('main .row[data-open="path"]')].map((r) => ({
    group: r.getAttribute('data-group'), path: r.getAttribute('data-path'),
    badge: r.querySelector('[data-variants]') ? Number(r.querySelector('[data-variants]').getAttribute('data-variants')) : 0,
    badgeText: r.querySelector('[data-variants]') ? r.querySelector('[data-variants]').textContent.trim() : '' })));
  assert.equal(rows.length, G.length, 'one row per path Issue');
  assert.deepEqual(rows.map((r) => r.group), G.map((g) => g.issue_id), 'rows in Issue order');
  rows.forEach((r, i) => {
    assert.equal(r.path, G[i].best_id, 'row ' + i + ' shows the best variant');
    assert.equal(r.badge, G[i].variants, 'row ' + i + ' variant badge');
    if (G[i].variants > 0) assert.equal(r.badgeText, '+' + G[i].variants);
  });
  const head = await textOf('main .panel .paths-head');
  assert.ok(head.startsWith(rows.length + ' attack path Issue'), 'header count must equal rows: ' + head);
  // hop count of a path in the focused graph: internet (unless a credential entry) + each hop resource once
  const nodesOf = (p) => { const st = p.steps || []; const s = new Set(st.map((x) => x.resource)); return s.size + (st[0] && st[0].relation === 'entry' ? 0 : 1); };
  const byId = Object.fromEntries(DATA.paths.map((p) => [p.id, p]));
  const cyNodes = () => page.evaluate(() => { const r = document.querySelector('main .panel .view'); return r && r._cy ? r._cy.nodes().map((n) => n.id()) : null; });
  // default: the first Issue is selected and only its path is drawn
  const first = byId[G[0].best_id];
  let ids = await cyNodes();
  assert.ok(ids, 'no graph');
  assert.equal(ids.length, nodesOf(first), 'default graph must draw only the first Issue\'s path: ' + JSON.stringify(ids));
  assert.ok(first.steps.every((s) => ids.includes(s.resource)), 'graph lacks a hop of the selected path');
  assert.ok(await page.$(`main .row.sel[data-group="${G[0].issue_id}"]`), 'first row not selected by default');
  await shot(page, 'v4-paths-default.png');
  // select another Issue: the graph is redrawn with that path's nodes only
  const k = Math.min(G.length - 1, 2);
  await page.click(`main .row[data-group="${G[k].issue_id}"]`);
  await settle();
  const pk = byId[G[k].best_id];
  ids = await cyNodes();
  assert.equal(ids.length, nodesOf(pk), 'selected Issue graph node count');
  assert.ok(pk.steps.every((s) => ids.includes(s.resource)), 'graph lacks a hop of the selected Issue');
  await shot(page, 'v4-paths-focused.png');
  // a "+N" badge lists the hop variants; selecting one draws that variant
  const gv = G.find((g) => g.variants > 0);
  if (gv) {
    await page.click(`main .row[data-group="${gv.issue_id}"] [data-variants]`);
    await settle();
    const vrows = await page.evaluate(() => [...document.querySelectorAll('main .row[data-open="path-variant"]')].filter((r) => r.offsetParent !== null).map((r) => r.getAttribute('data-path')));
    assert.deepEqual(vrows, gv.path_ids.slice(1), '+N must list the other hop variants');
    await page.click(`main .row[data-open="path-variant"][data-path="${gv.path_ids[1]}"]`);
    await settle();
    ids = await cyNodes();
    assert.equal(ids.length, nodesOf(byId[gv.path_ids[1]]), 'variant graph node count');
    assert.match(await hash(), new RegExp('pathId=' + gv.path_ids[1]));
    await shot(page, 'v4-paths-variants.png');
  }
  // explicit toggle: the full fan
  assert.equal((await textOf('main .panel .act[data-toggle="fan"]')).trim(), '[show all paths]');
  await page.click('main .panel .act[data-toggle="fan"]');
  await settle();
  const fanN = (await cyNodes()).length;
  const inPaths = new Set(DATA.paths.flatMap((p) => (p.steps || []).map((s) => s.resource)));
  assert.ok(fanN >= Math.min(inPaths.size, 2), 'fan must draw every path: ' + fanN);
  assert.match(await hash(), /graph=all/);
  assert.equal((await textOf('main .panel .act[data-toggle="fan"]')).trim(), '[selected path only]');
  await shot(page, 'v4-paths-fan.png');
  await page.click('main .panel .act[data-toggle="fan"]');
  await settle();
  // the overview counts path Issues, not hop variants
  await go('#overview');
  assert.equal((await textOf('.ov-paths')).trim(), String(G.length), 'overview path count must be path Issues');
});

await check('27 graph query (r5 #8): paths> --from/--to/--through runs over the report paths, filters the Issue rows, draws only the matched segments, prints the whole-graph CLI command; --save keeps it in the saved list across a reload; a bad selector is a red error', async () => {
  const typeOf = Object.fromEntries(((DATA.graph && DATA.graph.nodes) || []).map((n) => [n.id, n.type]));
  const nodesOfP = (p) => { const st = p.steps || []; const out = []; if (!(st[0] && st[0].relation === 'entry')) out.push('internet'); st.forEach((x) => { if (x.resource && !out.includes(x.resource)) out.push(x.resource); }); return out; };
  // a target type that some internet-rooted path reaches
  const withNet = DATA.paths.filter((p) => nodesOfP(p)[0] === 'internet' && typeOf[nodesOfP(p).slice(-1)[0]]);
  assert.ok(withNet.length > 0, 'no internet-rooted path with a typed target');
  const T = typeOf[nodesOfP(withNet[0]).slice(-1)[0]];
  const segOf = (p) => { const ids = nodesOfP(p); for (let i = 0; i < ids.length; i++) { if (ids[i] !== 'internet') continue; for (let k = i + 1; k < ids.length && k - i <= 6; k++) if (typeOf[ids[k]] === T) return ids.slice(i, k + 1); } return null; };
  const matched = DATA.paths.filter((p) => segOf(p));
  const wantGroups = DATA.path_groups.filter((g) => g.path_ids.some((id) => matched.find((p) => p.id === id))).length;
  const wantNodes = new Set(matched.flatMap((p) => segOf(p))).size;
  await page.evaluate(() => { try { localStorage.removeItem('nimbus.pathQueries'); } catch (e) {} });
  await go('#paths');
  await page.fill('main .pq-box input', '--from internet --to type:' + T + ' --save smoke-q');
  await page.press('main .pq-box input', 'Enter');
  await settle();
  const visible = await page.evaluate(() => [...document.querySelectorAll('main .row[data-open="path"]')].filter((r) => !r.classList.contains('gone')).length);
  assert.equal(visible, wantGroups, 'query must leave only the Issues with a matching path');
  const res = await textOf('main .pq-result');
  assert.match(res, /^query: \d+ paths? \(\d+ Issues?\) from internet to type:/);
  assert.ok(res.includes('cloud-posture paths --from internet --to type:' + T + ' --max-hops 6'), 'no whole-graph CLI command: ' + res);
  const cyN = await page.evaluate(() => { const r = document.querySelector('main .panel .view'); return r && r._cy ? r._cy.nodes().length : -1; });
  assert.equal(cyN, wantNodes, 'graph must draw only the matched segments');
  assert.match(await hash(), /q=/);
  assert.ok((await textOf('main .pq-saved')).includes('[smoke-q]'), 'saved list lacks the query');
  await page.reload();
  await settle(); await settle();
  await go('#overview'); await go('#paths');
  assert.ok((await textOf('main .pq-saved')).includes('[smoke-q]'), 'saved query lost on reload');
  await page.click('main .pq-saved [data-saved="smoke-q"]');
  await settle();
  assert.equal(await page.evaluate(() => [...document.querySelectorAll('main .row[data-open="path"]')].filter((r) => !r.classList.contains('gone')).length), wantGroups, 'saved query re-run');
  await page.fill('main .pq-box input', '--from internet --to type:no_such_type');
  await page.press('main .pq-box input', 'Enter');
  await settle();
  assert.match(await textOf('main .pq-result'), /error: --to: selector "type:no_such_type" matches no node/);
  assert.equal(await colorOf('main .pq-result span'), RED);
  await page.click('main .pq-result .act, main .graph-bar .act[data-toggle="pq-clear"]').catch(() => {});
  await page.fill('main .pq-box input', '');
  await page.press('main .pq-box input', 'Enter');
  await settle();
  assert.equal(await page.evaluate(() => [...document.querySelectorAll('main .row[data-open="path"]')].filter((r) => !r.classList.contains('gone')).length), DATA.path_groups.length, 'an empty query clears the filter');
  await page.evaluate(() => { try { localStorage.removeItem('nimbus.pathQueries'); } catch (e) {} });
  await shot(page, 'v7-paths-query.png');
});

await check('28 potential escalation (item 13): a finding Issue page that carries potential_escalations lists them (rule, title, target link, because, credit) as inferred and not a path Issue; a page without them shows no block', async () => {
  const pages = DATA.issue_pages || {};
  const id = Object.keys(pages).find((k) => (pages[k].issue || {}).kind !== 'path' && !(pages[k].potential_escalations || []).length);
  assert.ok(id, 'no finding Issue page in the payload');
  const tgt = ((DATA.graph && DATA.graph.nodes) || []).find((n) => n.id !== 'internet') || { id: 'arn:x', name: 'x' };
  const url = variant((D) => { D.issue_pages[id].potential_escalations = [{ rule_id: 'aws-iam-privesc-put-role-policy', title: 'Inline Policy Injection for Self-Escalation (IAM-005)', anchor: 'a', target: tgt.id, confidence: 'inferred', because: ['may iam:PutRolePolicy on itself'], credit: { source: 'Prowler', licence: 'Apache-2.0', upstream_id: 'IAM-005' } }]; }, 'potential');
  const p2 = await ctx.newPage();
  const errs = [];
  watch(p2, errs);
  await p2.goto(url);
  await p2.waitForFunction(() => document.querySelector('main .panel'), null, { timeout: 5000 });
  await p2.evaluate((x) => window.CWM.open('issue', x), id);
  await settle(p2);
  const it = await textOf('aside.pane .panel-b', p2);
  assert.match(it, /Potential escalation \(1, inferred: .* not a path Issue\)/);
  assert.ok(it.includes('aws-iam-privesc-put-role-policy') && it.includes('credit: Prowler IAM-005 (Apache-2.0)'), it);
  assert.ok(await p2.$('aside.pane [data-potential="aws-iam-privesc-put-role-policy"]'), 'no potential row');
  await p2.close();
  assert.deepEqual(errs, []);
  await page.evaluate((x) => window.CWM.open('issue', x), id);
  await settle();
  assert.doesNotMatch(await textOf('aside.pane .panel-b'), /Potential escalation/);
  await page.keyboard.press('Escape');
  await settle();
});

// screenshots: overview (v3)
await go('#overview');
await shot(page, 'v3-overview.png');

await check('page produced no errors at any step', async () => { assert.deepEqual(errors, []); });

await browser.close();
console.log(failed ? `${failed} check(s) FAILED` : 'all checks passed');
process.exit(failed ? 1 : 0);
