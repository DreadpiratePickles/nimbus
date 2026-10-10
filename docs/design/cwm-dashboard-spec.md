# nimbus dashboard — cwm look specification (v2; v1 below is superseded in part)

_v1 intro, written 2026-10-09 (superseded by v2): the dashboard was rebuilt to look and behave exactly like a stock OpenBSD desktop running **cwm** (Calm Window Manager) with **xterm** clients. Every cwm value below comes from `docs/research/cwm-reference.md`, which was extracted from the xenocara `app/cwm` source with file:line citations. Do not "improve" the look: fidelity is the requirement. Where the browser cannot do what X11 does, this spec says what to do instead._

## v2 (2026-10-09): cwm look, not a window manager

_Product-owner correction (verbatim): "The main agent is reading 'look exactly like cwm' as turning the whole dashboard into a fake window manager, no i mean with the general look of cwm." v2 **supersedes §1–5 and §7** below (root window, client windows, menus, geometry overlay, keyboard mapping, `~/.cwmrc`). **§6's view contents and §9's testing discipline still apply**, with the changes listed here. §0 (delivery, no CDN, `textContent` only, `Data` unchanged) and §8 (files) still apply. The dashboard is a conventional, discoverable security dashboard that uses cwm's visual language._

### v2.1 Visual language (values from `docs/research/cwm-reference.md` §1–3)
- Page background `#000000` (X root). Nothing else is drawn on it.
- Every panel is a white `#FFFFFF` box with a `1px solid` border: `#CCCCCC` (activeborder) for the focused panel, `#666666` (inactiveborder) for all others, `#FC8814` (urgencyborder) for a panel that received live data while unfocused, until it is focused.
- No title bars, no rounded corners, no shadows, no gradients or background images, no icons or images, no animations or transitions, no emoji.
- Headings and navigation use cwm's menu font `bold 14px sans-serif` (`sans-serif:pixelsize=14:bold`), 17px rows (ascent + descent), black on white. The selected navigation row is inverted exactly like a cwm menu row: black bar, white text.
- Body text is 14px sans-serif regular. Identifiers, commands, SQL, code and the column-aligned tables printed by the views are 13px monospace (columns are aligned in character cells, so they must be fixed-width).
- Colour appears only as text colour, only from the ANSI palette in `cwm.css`: red3 `#CD0000` (CRITICAL bold, HIGH, FAIL), green3 `#00CD00` (PASS, ok), blue2 `#0000EE` (LOW), gray50 `#7F7F7F` (muted, INFO, n/a). MEDIUM is bold foreground.
- Reverse video (`xterm -rv`): a `reverse` row in the navigation toggles it; panels become `#000000` with `#FFFFFF` text; the navigation box and the page are unchanged. Persisted in `localStorage['nimbus-xterm-rv']`.

### v2.2 Layout
- Left: a fixed navigation column rendered as a cwm menu: white box, `1px solid #000000` border, no padding, rows of 17px. Row 0 is the prompt `nimbus»«` (no spaces, no caret; typed text appears between the guillemets). It is a type-to-filter box: typing filters the section rows (case-insensitive substring), the first match is shown inverted, Enter jumps to it, Escape clears. Then one bold row per section, in this order: `overview`, `attack paths`, `top risks`, `findings`, `compliance`, `cost`, `sql`, `copilot`, `coverage`. The current section's row is inverted. Below the sections: a `reverse` row and a `keys` block documenting the keys (v2.4).
- Main area: the current section's panels in a responsive grid of bordered white boxes; each box starts with a bold black heading line inside the box (no bar, no background). The overview is a grid of panels (risk, attack paths, issues by severity × provider, coverage, compliance, owners and savings); other sections are one full-height panel.
- Right-hand pane: drill-downs (finding detail, resource detail) open in a third column, another bordered box, `#CCCCCC` while focused, with a heading line holding the title and a plain-text `close` action. Escape closes it. Navigating to another section closes it.
- Routing: each section has a hash `#overview`, `#paths`, `#risk`, `#findings`, `#compliance`, `#cost`, `#sql`, `#copilot`, `#coverage`. Section switches push the hash (back/forward work); a view's filter is reflected in the hash query and replaced in place, e.g. `#findings?severity=CRITICAL`, `#compliance?framework=cis-aws`, `#paths?pathId=…`. Loading a URL with a hash opens that section with that filter. Unknown hashes fall back to `#overview`.
- Narrow screens (< 900px): the navigation column stacks above the main area and the pane stacks below it.

### v2.3 Removed (the window manager)
No root-click menus, no window, application, exec, ssh, group, label or wm menus, no window moving/resizing/raising/lowering, no groups, no tiling, no hide/cycle/sticky/fullscreen/maximize, no lock/quit/restart, no geometry overlay, no `~/.cwmrc`, no `xterm` shell view. `cwmrc`, `xterm` and `ssh` are deleted; `finding` and `node` are the right-hand pane.

### v2.4 Keyboard
Keys are ignored while typing in an input (except Escape, which leaves the input). `/` focuses the navigation filter; `1`–`9` jump to the nine sections; `j` / `k` move the selection (an inverted row, like a cwm menu row) in the focused panel's list; Enter opens the selected row; Escape closes the pane (or clears the navigation filter when it is focused). The `keys` block at the bottom of the navigation lists exactly these.

### v2.5 Content and behaviour kept from §6
- Views stay in `clients.js` and keep their terminal-style tables and `textContent`-only rendering; they render into panels instead of windows. `api = { open, D, live, setTitle, setArg, onClose }`: `open(section, arg)` navigates (updating the hash), `open('finding'|'node', id)` opens the pane, `setArg(arg)` records the view's current filter in the hash.
- Every drill-through stays: every number in the overview opens the matching filtered list; rows open the pane; `Open query` opens `sql` and runs the query; attack-path steps open the finding; compliance controls open the filtered findings.
- Live mode (`serve`): connect `/ws`; ignore `hello`; on `findings_updated` refetch `/api/summary` and `/api/findings?status=FAIL` and re-render in place (no reload; a focused input keeps focus and keystrokes), print `<time> findings updated` in the overview, and mark every unfocused panel urgent (`#FC8814`) until it is focused; `scan_started` / `monitor_event` print a line, the latter also marks urgency; reconnect with backoff 1s → 30s.
- The attack-path graph stays embedded Cytoscape with the same monochrome styling (follows `--ansi-1`/`--ansi-8` and reverse video).

### v2.6 Files
- `cwm.css` — the visual language (tokens, nav, panels, pane, view text styles). `clients.js` no longer injects CSS.
- `cwm.js` — layout, navigation, hash routing, pane, focus/urgency, keyboard and live engine. Public surface `window.CWM = { commands, views, open, navigate, closePane, rv, setRv, D }`. All WM code is deleted.
- `clients.js` — the views. `render.go` / `dashboard.html` unchanged apart from the template field name for the engine script; the `</script`, `</style`, `<!--` guards and the no-CDN tests stay.

### v2.7 Tests (replace §9's cwm checks; same discipline: write first, watch fail, implement)
Go: rendered page has the data block, Cytoscape, no external `src`, the v2 tokens (`#CCCCCC`, `#666666`, `#FC8814`, `bold 14px sans-serif`, `»`, `«`), and `cwm.js` contains none of the WM vocabulary (`menu-window`, `window-htile`, `xlock`, `'application'`, `'exec'`, `'ssh'`), and `clients.js` registers no `xterm` / `cwmrc` view.
Playwright (`tools/ui-smoke/smoke.mjs`, 1440×900): black body; nav box white, `1px solid` black, bold 14px, prompt `nimbus»«`, the nine rows in order, selected row inverted; panel borders `#CCCCCC`/`#666666` by focus; no element in the page with `border-radius` ≠ 0, `box-shadow` ≠ none, a background image, an animation, an `img` or `svg`; text colours only from the palette; hash routing (`#findings?severity=CRITICAL` opens filtered, also on a fresh load; filter edits update the hash); drill-through from an overview number to findings with the same count; row → right pane (`#CCCCCC`, main `#666666`); Escape and `close` close it; `/` focuses the filter; `comp` + Enter jumps to compliance; `1`–`9` and `j`/`k`/Enter; `Open query` runs in sql; reverse video flips panels only and persists; no WM left (no client windows, no root menus); listeners do not leak across section switches; live mode with a mocked `/ws`; XSS payload `</script><img src=x onerror=window.__pwned=1>` in a finding title of a copy of the report leaves `window.__pwned` undefined and 0 `img` elements; no page errors anywhere.

---

_v1 (superseded by v2 above for §1–5 and §7; §0, §6 view contents, §8 and §9 discipline still apply):_

## 0. Scope and non-negotiables

- Same delivery as today: one self-contained HTML file rendered by `internal/dashboard/render.go` from the embedded template, used both for `cloud-posture dashboard --out` (static) and `cloud-posture serve` (live). The inline JSON payload (`<script id="data" type="application/json">{{ .JSON }}</script>`) and the `Data` struct **do not change**.
- No CDN, no external requests. Cytoscape 3.30.2 is embedded from `internal/dashboard/cytoscape.min.js` (SRI-verified copy).
- All cloud-controlled strings are rendered with `textContent` only. Never `innerHTML` with data.
- Existing Go tests stay green; new tests are added first (see §9).
- The product content (findings, attack paths, risk, compliance, cost, SQL, copilot, coverage) keeps every feature the old dashboard had, plus the drill-through behaviours listed in §6.

## 1. The screen (X root window)

- `<body>` is the X root: `background:#000000`, `margin:0`, `overflow:hidden`, `width:100vw;height:100vh`, cursor `default` (`left_ptr`). cwm never sets a root background; black is X's default and the choice here.
- Nothing is drawn on the root: no bar, no icons, no hints, no logo. The only things that ever exist on the root are client windows, one menu, and the move/resize geometry overlay.
- The screen "area" for placement/tiling is the viewport minus `gap` (default `0 0 0 0`).

## 2. Client windows (xterm)

Every product view is a **client window** that looks like a stock xterm.

### 2.1 Decoration (cwm)
- Border: `1px solid` (cwm `borderwidth 1`). Colours: active `#CCCCCC`, inactive `#666666`, urgent `#FC8814` (overrides everything), group-flash blue `#0000FF`, ungroup-flash red `#FF0000`.
- **Nothing else.** No title bar, no buttons, no shadow, no radius, no resize handles drawn, no outline on focus.
- Fullscreen (`CM-f`): border width 0, window covers the whole viewport, ignores gap. Maximize (`CM-m`): fills the area but keeps the 1px border. `CM-equal` / `CMS-equal` = vertical / horizontal maximize. Each is a toggle that restores the saved geometry.

### 2.2 Client look (xterm defaults)
- Background `#FFFFFF`, foreground `#000000` (stock xterm). Font: `13px/15px "Menlo", "DejaVu Sans Mono", "Liberation Mono", monospace` (xterm's `fixed` 6x13 bitmap is 13px tall; use the nearest monospace). Cell size is measured at runtime from a hidden `M` span and used for all cols×rows math.
- Geometry is in **character cells**: default new window = 80×24 cells + no padding (xterm has an internal border of 2px; use `padding:2px`).
- Text colours allowed inside clients are xterm's 16 ANSI defaults only: black `#000000`, red3 `#CD0000`, green3 `#00CD00`, yellow3 `#CDCD00`, blue2 `#0000EE`, magenta3 `#CD00CD`, cyan3 `#00CDCD`, gray90 `#E5E5E5`, and bright: gray50 `#7F7F7F`, red `#FF0000`, green `#00FF00`, yellow `#FFFF00`, `#5C5CFF`, magenta `#FF00FF`, cyan `#00FFFF`, white `#FFFFFF`. Severity mapping: CRITICAL = bold red3, HIGH = red3, MEDIUM = yellow3 on black cell? **No**: yellow on white is unreadable, so MEDIUM = bold black, LOW = blue2, INFO = gray50, PASS = green3. Links/actions are rendered as xterm would show them: plain text, underlined on hover only.
- Reverse video: the application menu includes `xterm -rv` ("reverse"), which flips all clients to `#000000` bg / `#FFFFFF` fg (persisted in `localStorage['nimbus-xterm-rv']`). The cwm chrome (borders, menu) never changes.
- Content scrolls inside the client (`overflow:auto`, thin default scrollbars are acceptable; xterm has none, so hide them with `scrollbar-width:none` and keep wheel scrolling).

### 2.3 Window model (cwm semantics)
- Fields: `id`, `name` (WM_CLASS res_name: `xterm`), `class` (`XTerm`), `title` (WM_NAME, e.g. `nimbus — findings`), `label` (user label, default empty), `group` (0–9, **default 0 = nogroup**; `sticky` option is off), `hidden`, `active`, `urgent`, `sticky` (window-stick flag), `x,y,w,h` in px (w,h always a whole number of cells), saved geometry for maximize/fullscreen, `ptr` (last pointer position inside the window), `titleHistory` (last 5 titles).
- Stacking: DOM order = stacking order. `raise` appends to the end; `lower` prepends.
- MRU list `clientq`: focused window moves to head (`client_mtf`), except while `cycling` (modifier held).

### 2.4 Focus
- **Focus follows the mouse without raising.** `mouseenter` on a client sets it active (border `#CCCCCC`), previous active goes `#666666`. Clicking inside a client does **not** raise or focus it (focus already followed the pointer). Keyboard events go to the active client's content if it has a focused input, otherwise to the WM.
- The only focus indicator is the border colour.

### 2.5 Placement of a new window
- Centred on the current pointer position, clamped to the area: `x = max(max(ptrx, area.x) - w/2, area.x)`, same for y, then `x = max(min(x, area.x+area.w - w - 2bw), area.x)`. If no pointer position is known yet (page load), use the centre of the viewport. If the window is larger than the area, it is placed at the area origin and shrunk to the area.
- After mapping, cwm warps the pointer into the window centre; a browser cannot warp, so instead the new window becomes active immediately (same observable result: it has focus).
- New windows are raised.

### 2.6 Move / resize
- Mouse move `M-1` (Alt + left button drag anywhere on the client): raises, cursor `move` (`fleur`), live move, no clamp. Geometry overlay (§4) shows `%+5d%+5d` → e.g. ` +120  +45`.
- Mouse resize `M-2` (Alt + middle drag) and, because many laptops have no middle button, also `M-3`-less alternative is **not** added; instead accept `Alt+Shift+left drag` as the browser substitute for `M-2` and document it in `~/.cwmrc` as `bind-mouse MS-1 window-resize`. Resize grows from the bottom-right corner only, snapped to cell increments, cursor `nwse-resize` (`bottom_right_corner`). Overlay shows `%4d x %-4d` in **cells**, e.g. `  80 x 24  `.
- `M-3` (Alt + right) lowers. `CMS-3` hides. `CM-1` toggles group membership and flashes the border blue (added) or red (removed) until the modifier is released.
- Keyboard: `M-h/j/k/l` move 1px, `MS-h/j/k/l` move 10px; `CM-h/j/k/l` resize by 1 cell, `CMS-h/j/k/l` by 10 cells (left/up shrink width/height; right/down grow). Keyboard move clamps so the window stays within 1px of the screen edge.
- Snapping is off (`snapdist 0`).

### 2.7 Hide / show / cycle / close
- `M-Return` hides the active window (unmaps; no icon, no taskbar; it is found again via the window menu with the `&` flag or group toggles). `CM-x` closes it. `M-Up` raises, `M-Down` lowers.
- `M-Tab` / `MS-Tab`: cycle MRU forward/backward with **no on-screen switcher**: each press raises the next window and makes it active; MRU order is frozen while Alt is held and updated on `keyup` of Alt. `M-grave` / `MS-grave`: cycle within the same class (all are XTerm, so same as above).
- `CM-s`: toggle sticky (skipped by group hide/show).
- `CM-n`: label menu (`label»<current>«`); Return sets the label.

### 2.8 Groups
- 10 groups, 0 = nogroup, names: nogroup, one, two, three, four, five, six, seven, eight, nine. Group 1 is active at start. New windows get **no group**.
- `CM-1..9` group-toggle-N: if every member is hidden or sticky, show the group; else hide it. `CM-0` / `CM-a` toggle all. `M-Right` / `M-Left` group-cycle / rcycle (skip empty groups; hide the others). `CM-g` toggles the active window's membership in the active group (flash blue/red).
- `window-htile` / `window-vtile` are unbound in cwm by default. The shipped `~/.cwmrc` (§7) binds them to `CM-t` and `CMS-t` and says so. Semantics: current window to the top (htile) / left (vtile) with 50% of the area; other **windows in its group** share the rest equally; the last one takes the leftover pixels; all raised; hidden windows ignored.

## 3. Menus (cwm `menu.c`)

One menu element, created on demand, removed on close.

- Box: `background:#FFFFFF`, `border:1px solid #000000` (menufg), text `#000000`, `font: bold 14px sans-serif` (`sans-serif:pixelsize=14:bold`), `line-height` = ascent+descent (use `17px`), **no padding at all**, text starts at x=0. Width = widest row's text width; height = `(1 + rows) × 17px`. No shadow, no radius.
- Position: top-left at the pointer position when opened (keyboard-opened menus too). Clamp: if it overflows right/bottom, shift left/up; never hide the left/top edge; crop if it still doesn't fit.
- Row 0 is the prompt: `<prompt>»<typed>«` with **no spaces** and **no caret**, e.g. `exec»«`, `window»fin«`. Prompt strings: `window`, `application`, `group`, `wm`, `exec`, `ssh`, `label`.
- Result rows below. **The first result row is always highlighted** (full-width black bar, white text). Down / `C-s` / `M-j` rotates the first row to the tail; Up / `C-r` / `M-k` rotates the last row to the head. Hovering a row highlights it too (black bar, white text) and un-highlights the previously hovered row; the row-1 highlight is not cleared by hover (yes, two rows can be highlighted; that is cwm).
- Cursor while a menu is open: `help` (`question_arrow`); switches to default on first hover of a row.
- Opened by a mouse button → **list mode**: all entries shown immediately. Opened by a key → only the prompt until something is typed; `C-a` toggles list-all. Backspacing to empty keeps the previous results on screen.
- Keys: Return/KP_Enter select the top row; BackSpace/`C-h` erase one char; `C-u` clears; Escape/`C-[` aborts; Tab completes to the common case-insensitive prefix of the results; any printable key appends.
- Mouse: selection happens on **mouseup** over a result row (press-drag-release works from the root). Release over the prompt row or outside closes without selection.
- No match: only the prompt row. Return with no results returns the typed text: `exec` runs it as a command (unknown → ignored silently, like a failed spawn); `window`/`group`/`application`/`wm` discard it.
- Entry text is capped at 200 bytes.

### 3.1 Menu contents
- **window** (`M-slash`, left button on root): rows `(%d) %c[%s] %s` = `(group) flag[label] title`, flag `!` active, `&` hidden, ` ` otherwise; MRU order; case-insensitive substring match ranked label → title history → class, active window ranked down one tier, hidden ranked up one. Selecting shows + raises + activates.
- **group** (middle button on root): rows `%d: %s` or `%d: [%s]` when fully hidden; empty groups excluded; selecting shows a fully hidden group, otherwise hides it. Middle button in a browser: `button === 1`; also accept `Shift+right` on the root as the laptop substitute and document it.
- **application** (`C-slash`, right button on root): rows are the `command` names from `~/.cwmrc` (§7) in config order; `term` and `lock` are skipped exactly as cwm does. Case-insensitive substring match.
- **exec** (`M-question`): entries = every executable on the dashboard's PATH = the command names from §7 plus `xterm`, `cwmrc`, `top`, `clear`-style helpers listed in §7; case-insensitive **prefix** or glob match; ASCII-sorted; duplicates dropped. Return runs the top result.
- **ssh** (`M-period`): the known_hosts list = the scanned **accounts** (`D.accounts`, formatted `provider/account`). Selecting opens an xterm titled `[ssh] <account>` whose content is the findings view filtered to that account.
- **wm** (`CM-w`): single row `cwm [cwm]`; selecting re-execs: closes every window and reopens the initial layout.
- **label** (`CM-n`): pre-filled with the current label.

## 4. Geometry overlay
A child element at the client's top-left `(0,0)` inside the border, `background:#FFFFFF`, `color:#000000`, `font: bold 14px sans-serif`, height 17px, width = text width, no padding, no border. Visible only during mouse move (`%+5d%+5d`) or resize (`%4d x %-4d`, in cells).

## 5. Keyboard mapping in the browser
- `M` = Alt/Option (`event.altKey`). Never Cmd. `C` = Control (`event.ctrlKey`), `S` = Shift. Match on `event.code` (`KeyH`, `Slash`, `Period`, `Backquote`, `Equal`, `Enter`, `Delete`, `Backspace`, `Tab`, `Digit0-9`, `ArrowUp/Down/Left/Right`) because macOS Option produces dead/accented characters. `M-question` is `Alt+Shift+Slash`.
- `CM-Delete` (lock): macOS keyboards send `Backspace`; accept both. "Lock" blanks the screen with a black overlay and the text `xlock` style prompt (`Password: ` is not needed; any key unlocks). Keep it trivial.
- `CMS-q` quit and `CMS-r` restart: quit closes all windows and leaves the black root; restart = reopen the initial layout.
- All handled combos call `preventDefault()`. Combos the browser owns (Cmd-anything) are not touched. When a text input inside a client is focused, only Alt/Ctrl combos reach the WM; plain typing goes to the input.
- Alt key `keyup` ends `cycling` and clears group-flash colours.

## 6. Clients (the product views)
Each view is a function `render(root, api)` registered in `clients.js` under a command name. The WM API (`cwm.js`) exposes exactly:

```js
window.CWM = {
  open({ cmd, title, cols = 80, rows = 24, render }),  // returns client id; placement per §2.5
  close(id), hide(id), show(id), raise(id), setTitle(id, title), urgent(id, on),
  exec(cmd, arg),            // run a command name as the exec menu would
  commands,                  // ordered array of {name, title, cols, rows, render} from clients.js
  accounts,                  // for the ssh menu
  cells,                     // {w,h} px per cell
  rv,                        // reverse-video state
};
```
`clients.js` registers views by pushing into `CWM.commands` **before** `cwm.js` runs its init (script order in the template: data → cytoscape → clients.js → cwm.js → init). `render` receives the client's content element and `api = { open, close, exec, D, live }` and builds DOM with `textContent`.

Views (command name → title → default size → content). All text is laid out as fixed-width columns like a terminal program would print; interactive rows are `<div class="row">` elements that react to click.

| cmd | title | cols×rows | content |
|---|---|---|---|
| `overview` | `nimbus — overview` | 100×32 | header line `nimbus <generated_at> · <mode>`; then 7 blocks printed like `top(1)` sections: risk (top risk score, open findings, by severity with **new-since-last-scan** when `scan` exists), attack paths (count, top 5 by score, top 5 choke points), issues by severity × provider (text bars using `#` characters, provider rows), coverage (accounts, tools, status, last-scan age, errors), compliance (framework → score%, failing/passing), owners (open criticals by owner from `risk[].owner`, overdue SLA count), savings (`cost.total_monthly_savings`). **Every number is clickable** and opens the matching view pre-filtered (`findings` with severity/provider, `paths`, `compliance <fw>`, `coverage`). |
| `paths` | `nimbus — attack paths` | 120×36 | left column (40 cols): path list `score  name  (steps)` sorted by score, click selects; right: Cytoscape graph (white bg, black edges, node shapes as before: ellipse entry, diamond target, ring = choke point; node labels in the mono font; selected path highlighted in red3, others dimmed gray50). Below: `Recommendations — these break paths`, `Additional — these lower risk only`, `Cheapest fix set (N fixes, X% of path risk)`, each line `breaks N/M  removes X  <fix>  cloud-posture fix --id …`. Clicking a step opens `finding <id>`. |
| `risk` | `nimbus — top risks` | 120×30 | table `score band finding resource owner due paths reasons` with reasons as chips in text `[internet-exposed ×1.6]`. Click → `finding <id>`. |
| `findings` | `nimbus — findings` | 120×36 | filter line rendered as an xterm prompt: `filter> sev=… prov=… acct=… src=… status=FAIL q=…` editable via an input styled as terminal text; table `SEV  finding  resource  provider/account  source  compliance`. Supports filter args from `open` (severity, provider, account, status, q). Count line `N shown of M` and a warning line when capped at 500. Click → `finding <id>`. |
| `finding` | `nimbus — <title>` | 100×36 | detail view, `less`-style: title, severity · status, canonical id, resource, type, provider/account, region, source/check, file:line, first/last seen, weaknesses, risk/description, remediation, fix commands, related attack paths (click → `paths` with that path selected), compliance mappings, risk score and reasons, `Open query` line that opens `sql` with the resource query and runs it. |
| `compliance` | `nimbus — compliance` | 120×36 | framework selector as a row list `framework  score%  failing passing n/a` (click selects); below, the control grid printed as columns `STATUS  id  title` with `FAIL` red3, `PASS` green3, `n/a` gray50; click a control → `findings` filtered to its finding ids. |
| `cost` | `nimbus — cost` | 100×30 | `cost.text` if present, else tables for zombies / rightsizing / security_cost_wins / roi from the cost map; total savings line. |
| `sql` | `nimbus — sql` | 120×30 | an xterm REPL: prompt `sql> `, input, saved queries listed as `\\1 … \\6` shortcuts; static mode prints the CLI hint; live mode POSTs `/api/query` and prints a fixed-width result table with `N rows`. `Ctrl-L` clears. |
| `copilot` | `nimbus — copilot` | 100×30 | REPL `ask> `; without `copilot_url` prints the `nimbus ask "…"` hint; with it POSTs `<copilot_url>/api/copilot` and prints `answer`, then `sql`, then the rows table (fix the old bug that dropped rows). |
| `coverage` | `nimbus — coverage` | 100×24 | tools × accounts × status × findings × detail; `failed`/`skipped` in red3/gray50; this is the coverage-honesty panel. |
| `node` | `nimbus — <resource>` | 100×30 | resource drawer: type/class/provider/account/region/criticality/owner/sensitive/weaknesses, findings on it, paths through it, `Open query` runs the query. |
| `cwmrc` | `~/.cwmrc` | 80×40 | prints the virtual config from §7 verbatim. |
| `xterm` | `xterm` | 80×24 | the nimbus shell: prompt `$ `, commands `help`, `ls` (list views), any view name (opens it), `findings --severity CRITICAL`, `sql <query>`, `ask <q>`, `clear`, `exit` (closes the window). Unknown command prints `ksh: <cmd>: not found`. |

Initial layout on load: `overview` opened and active. In live mode, `findings_updated` **does not reload the page**; it refetches `/api/summary` and `/api/findings?status=FAIL` and re-renders open views, prints a line `<time> findings updated` in the overview, and sets the **urgency border** on windows that are not active until they are focused. `scan_started` prints `scan running…`; `monitor_event` prints `change detected: <title>` and marks urgency. The socket reconnects with exponential backoff (1s→30s).

## 7. The virtual `~/.cwmrc`
Shown by the `cwmrc` command and used to generate the application/exec menus. Exactly:

```
# nimbus dashboard — cwm configuration
# default cwm bindings are in effect; this file only adds commands and two tile bindings
command overview    nimbus-overview
command paths       nimbus-paths
command risk        nimbus-risk
command findings    nimbus-findings
command compliance  nimbus-compliance
command cost        nimbus-cost
command sql         nimbus-sql
command copilot     nimbus-copilot
command coverage    nimbus-coverage
command cwmrc       less ~/.cwmrc
command reverse     xterm -rv
command term        xterm
command lock        xlock
bind-key CM-t   window-htile
bind-key CMS-t  window-vtile
bind-mouse MS-1 window-resize
bind-mouse S-3  menu-group
```
(`term` and `lock` are listed but skipped in the application menu, as cwm does.)

## 8. Files
- `internal/dashboard/dashboard.html` — template shell only: `<!doctype html>`, `<meta charset>`, `<meta viewport>`, `<title>nimbus</title>`, `<style>{{ .CSS }}</style>`, `<body>`, `<script id="data" type="application/json">{{ .JSON }}</script>`, `<script>{{ .Cytoscape }}</script>`, `<script>{{ .Clients }}</script>`, `<script>{{ .WM }}</script>`.
- `internal/dashboard/cwm.css`, `internal/dashboard/cwm.js`, `internal/dashboard/clients.js`, `internal/dashboard/cytoscape.min.js` — all `//go:embed`ded by `render.go` and injected as `template.CSS` / `template.JS`. `render.go` must refuse (return an error in `init`/first render, covered by a test) if any embedded script contains `</script` case-insensitively.
- `tools/ui-smoke/` — Node + Playwright smoke test (`package.json`, `smoke.mjs`) run with `make ui-test` against a rendered report; see §9.

## 9. Tests (write first, watch them fail, then implement)
Go (`internal/dashboard/render_test.go`):
1. Rendered output contains `<script id="data" type="application/json">`, contains `cytoscape`, does not contain `</script><img`, and contains **no `https://`/`http://` URL inside a `src=` attribute** (no CDN).
2. Rendered output contains the strings `#CCCCCC`, `#666666`, `#FC8814`, `sans-serif`, `»`, `«`, `(%d) %c[%s] %s`-equivalent row builder marker `"(" + ` is not testable; instead assert the literal prompt strings `window`, `application`, `exec`, `group`, `ssh`, `label`, `wm` appear in the WM script.
3. Each embedded asset is non-empty and free of `</script` (case-insensitive).
4. `cloud-posture dashboard --out` still ≥ 50,000 bytes (existing `cli_test.go`).

Playwright (`tools/ui-smoke/smoke.mjs`, 1440×900, against `cloud-posture-report/index.html` rendered from `testdata`):
1. `body` computed background is `rgb(0, 0, 0)`; exactly one client window exists at load; its border is `1px solid rgb(204, 204, 204)`; it has no element with text matching a title bar; its title is `nimbus — overview`.
2. Right-click on the root at (1200,700) opens a menu whose first row text is `application»«`, background `rgb(255, 255, 255)`, border `1px solid rgb(0, 0, 0)`, font-weight 700, font-size 14px, left edge at x=1200; rows include `overview`…`coverage` and **not** `term`/`lock`; the first result row has background `rgb(0, 0, 0)` and colour `rgb(255, 255, 255)`. Mouseup on `findings` opens a second window titled `nimbus — findings`, which is now active (`#CCCCCC`) while overview is `#666666`.
3. `Alt+Shift+Slash` opens `exec»«` with no result rows; typing `co` shows `compliance`, `copilot`, `cost`, `coverage` in ASCII order with `compliance` highlighted; `Enter` opens compliance.
4. `Alt+Slash` opens `window»«`; `Ctrl+a` lists all windows with rows matching `/^\(\d\) [ !&]\[.*\] nimbus — /`, and the active window's row has the `!` flag.
5. `Alt+Enter` hides the active window; `Alt+Slash`, `Ctrl+a` shows it with the `&` flag; selecting it shows it again.
6. `Ctrl+Alt+KeyX` closes the active window. `Ctrl+Alt+KeyM` maximizes (window rect equals viewport minus 2px border). `Ctrl+Alt+KeyF` goes fullscreen with border width 0.
7. `Alt+KeyL` moves the active window right by exactly 1px; `Alt+Shift+KeyL` by 10px; `Ctrl+Alt+KeyL` widens by exactly one cell width.
8. Alt+left-drag moves the window and shows an overlay matching `/^[+-]\s*\d+[+-]\s*\d+$/` ignoring spaces; Alt+Shift+left-drag resizes and shows `/^\s*\d+ x \d+\s*$/`.
9. `Ctrl+Alt+Digit1` with a window in group 1 hides it; again shows it.
10. Clicking the open-findings number in overview opens `findings`; clicking a findings row opens a `nimbus — <title>` window; no page errors in the console at any step.

## 10. Out of scope for v1
Virtual desktops beyond groups, Xinerama, pointer warping, config file parsing, real xterm emulation, light/dark "themes" (there is only xterm and `xterm -rv`).
