# cwm (Calm Window Manager) — Reference for a Faithful Web Replica

## Provenance

- **Source:** OpenBSD xenocara, `app/cwm/`, branch `master` on the GitHub mirror (`raw.githubusercontent.com/openbsd/xenocara/master/app/cwm/<file>`).
- **Latest commit touching `app/cwm`:** `a89db76877a0cc256f9eac1c5d1e9251aa2caebc` (2026-01-05).
- **File revisions read** (from their `$OpenBSD$` tags):

  | File | Revision |
  |---|---|
  | conf.c | 1.257 (2025/08/20) |
  | calmwm.h | 1.380 (2025/08/20) |
  | kbfunc.c | 1.176 (2025/08/20) |
  | cwmrc.5 | 1.79 (2025/08/20) |
  | xevents.c | 1.151 (2026/01/05) |
  | menu.c | 1.110 (2022/10/15) |
  | client.c | 1.267 (2023/03/22) |
  | group.c | 1.138 (2022/01/27) |
  | screen.c | 1.98 (2022/01/27) |
  | search.c | 1.70 (2020/02/27) |
  | xutil.c | 1.113 (2020/04/25) |
  | calmwm.c | 1.115 (2022/02/26) |
  | parse.y | 1.75 (2021/12/24) |
  | cwm.1 | 1.66 (2023/07/20) |

- **`mousefunc.c` does not exist on master.** The fetch returns HTTP 404, and the mouse move/resize handlers now live in `kbfunc.c` as `kbfunc_client_move_mb` and `kbfunc_client_resize_mb`. I also read `xevents.c` and `parse.y` because they hold the focus, event and config-parsing logic.
- **Citations** are written as `file:line`, using line numbers from the revisions above.
- **Labels:** everything marked **[SOURCED]** was read directly from code or man pages. Everything marked **[INFERENCE]** is my reasoning and is not stated in the source.

---

## 1. Default colors [SOURCED]

`conf.c:60-70` (`color_binds[]`, in the order of `enum color` at `calmwm.h:85-96`):

| cwmrc keyword | enum | Default | Hex equivalent |
|---|---|---|---|
| `color activeborder` | CWM_COLOR_BORDER_ACTIVE | `"#CCCCCC"` | #CCCCCC |
| `color inactiveborder` | CWM_COLOR_BORDER_INACTIVE | `"#666666"` | #666666 |
| `color urgencyborder` | CWM_COLOR_BORDER_URGENCY | `"#FC8814"` | #FC8814 |
| `color groupborder` | CWM_COLOR_BORDER_GROUP | `"blue"` | X11 `blue` = #0000FF |
| `color ungroupborder` | CWM_COLOR_BORDER_UNGROUP | `"red"` | X11 `red` = #FF0000 |
| `color menufg` | CWM_COLOR_MENU_FG | `"black"` | #000000 |
| `color menubg` | CWM_COLOR_MENU_BG | `"white"` | #FFFFFF |
| `color font` | CWM_COLOR_MENU_FONT | `"black"` | #000000 |
| `color selfont` | CWM_COLOR_MENU_FONT_SEL | `""` (empty, so it is computed) | #FFFFFF by default (see below) |

(The X11 rgb.txt values for `blue`, `red`, `black` and `white` are standard X11 knowledge. They are not in the cwm tree.)

**How the selected-font color is computed when `selfont` is empty** (`conf.c:497-506`, `xutil.c:138-145`):

```
sel = (menubg XOR menufg) XOR font      // per channel, alpha forced to 0xffff
```

With the defaults this is (white ^ black) ^ black = **white**. So the default selected menu row has **white text on a black bar**.

**Correction to the brief:** the menu is **not** "black bg, white text". The default menu is a **white background with black text**. Only the selected row is inverted.

If a configured color name fails to allocate, cwm warns and falls back to the built-in default for that slot (`conf.c:507-512`).

Border pixels are drawn as `pixel | (0xffu << 24)` so that they stay opaque on ARGB visuals (`client.c:599`).

## 2. Font and text rendering [SOURCED]

- **Default font:** `c->font = xstrdup("sans-serif:pixelsize=14:bold");` (`conf.c:318`). This is a fontconfig/Xft pattern.
- **Loading:** cwm first tries `XftFontOpenXlfd(...)`, then `XftFontOpenName(...)`. If both fail it exits fatally (`errx`) (`conf.c:490-495`).
- **Drawing calls:** all text goes through `XftDrawStringUtf8`, and widths are measured with `XftTextExtentsUtf8` (`menu.c:355-356,400-403,412-415`).
- **Line height:** `xftfont->ascent + xftfont->descent` (`menu.c:358,367,406,436`). There is no extra leading.
- **Horizontal position:** text is drawn at **x = 0**, so there is no left padding. The baseline is at `row_y + ascent` (`menu.c:402,414,442`).
- **Exceptions:**
  - The geometry overlay (the "prop" window) uses `xftfont->height` for its height and draws the baseline at `ascent + 1` (`screen.c:300-304`).
  - The cwmrc keyword is `fontname` (`cwmrc.5:171-175`).

**[INFERENCE] Font metrics.** I could not read the actual metrics from source. On a stock OpenBSD install, fontconfig `sans-serif` usually resolves to DejaVu Sans. In DejaVu Sans Bold at 14px, ascent is about 13–14px and descent about 4px, which gives a menu row about 17–18px tall. Measure this on a real system to be pixel-exact.

## 3. Borders and decorations [SOURCED]

### Width

- **Default:** `c->bwidth = 1;` (`conf.c:290`). The cwmrc keyword is `borderwidth` (`cwmrc.5:127`).
- **Set to 0** for:
  - ignored windows (`client.c:96-97`)
  - windows whose Motif hints disable the border (`client.c:855-859`)
  - fullscreen windows (`client.c:332`)

### Color selection

`client_draw_border()`, `client.c:574-600`:

```
if ACTIVE:
    if flag GROUP   -> groupborder   (blue)
    if flag UNGROUP -> ungroupborder (red)
    else            -> activeborder  (#CCCCCC)
else                -> inactiveborder (#666666)
if URGENCY          -> urgencyborder (#FC8814)   // overrides everything
```

Then `XSetWindowBorderWidth(win, bwidth)` and `XSetWindowBorder(win, pixel)` are called.

### What the border is

The border is the **native X11 window border of the client window itself**. cwm does **not reparent** windows: there is no frame window and `XCreateWindow` is never called for clients. As a result:

- **There are no title bars, buttons, icons, frames, shadows or rounded corners.** The only per-window decoration is the 1px solid border.
- The only other windows cwm ever creates are:
  - the menu window (`menu.c:117`)
  - the move/resize geometry overlay (`screen.c:271`)
- cwm never draws a root background or wallpaper. No background-setting call exists in the tree.

### When the group colors appear

- **When set:** blue or red is applied when `window-group` (CM-g, or CM-click with button 1) toggles membership (`group.c:167-181`).
- **When cleared:**
  - when a modifier key is released (`xevents.c:373-376`; the modifier list is at `xevents.c:71-75`: Control_L/R, Alt_L/R, Meta_L/R, Super_L/R, ISO_Level3_Shift)
  - when a button is released on the window (`xevents.c:287-291`)
- The man page describes this as "A blue border will be shown briefly on windows added to the current group, and a red border will be shown on those just removed" (`cwm.1:241-242`).

### Urgency

- Set from the `XUrgencyHint` in `WM_HINTS`, but only if the window is not active (`client.c:567-572,644-645`).
- Cleared when the window becomes active (`client.c:264`).

## 4. Menus (menu.c) [SOURCED]

### Window construction

- The menu is created with `XCreateSimpleWindow(root, 0,0,1,1, Conf.bwidth, border=menufg, background=menubg)` (`menu.c:117-120`).
- With defaults that is a **1px black border, white background, black text**.
- cwm then calls `XMapRaised`, grabs the pointer with the **`XC_question_arrow` cursor**, takes input focus, and grabs the keyboard (`menu.c:125-140`).

### Position

- The top-left corner of the menu is placed **at the pointer position** captured when the menu opens (`menu.c:97,105-106`).
- On every redraw it is clamped into the screen area of the region (Xinerama/RandR head) containing the pointer, with gap applied (`menu.c:371-390`):
  - `area.w += area.x - bwidth*2; area.h += area.y - bwidth*2;` turns those values into right and bottom limits.
  - If the menu overflows on the right or bottom, it is shifted left or up.
  - The left and top edges are never hidden (comment at `menu.c:378`). If needed, width or height are cropped instead.
- If clamping moved the menu, the **pointer is warped** to the menu's new top-left (`menu.c:392-393`).
- On exit, the pointer is restored to its original position if it is still exactly at the menu corner (`menu.c:180-183`).

### Size

- **Width** is the maximum `xOff` text extent of the prompt line and all printed entries. Each entry is measured on at most `MENU_MAXENTRY` = 200 bytes (`calmwm.h:275`, `menu.c:357,363-366`).
- **Height** is `(1 + number of entries) × (ascent + descent)`.
- There is **no padding** on any side. Text touches the left inner edge.

### Prompt line (row 0)

`menu.c:37-38,353-354`:

```c
#define PROMPT_SCHAR "\xc2\xbb"   /* » U+00BB */
#define PROMPT_ECHAR "\xc2\xab"   /* « U+00AB */
snprintf(dispstr, ..., "%s%s%s%s", promptstr, PROMPT_SCHAR, searchstr, PROMPT_ECHAR);
```

- The prompt line reads `<prompt>»<typed text>«`, **with no spaces**.
- When the input is empty it shows, for example, `exec»«`.
- Typed text appears between the guillemets. There is no caret or cursor glyph.
- The prompt line is drawn in the `font` color and is never highlighted.

**Prompt strings, as passed to `menu_filter`:**

| Menu | Prompt | Source |
|---|---|---|
| menu-window / menu-window-hidden | `window` | `kbfunc.c:550` |
| menu-cmd | `application` | `kbfunc.c:582` |
| menu-group | `group` | `kbfunc.c:610` |
| menu-exec-wm | `wm` | `kbfunc.c:636` |
| menu-exec | `exec` | `kbfunc.c:700` |
| menu-ssh | `ssh` | `kbfunc.c:762` |
| window-menu-label | `label` (pre-filled with the current label) | `kbfunc.c:789` |
| Tab file completion inside exec | the current search string itself becomes the prompt | `menu.c:203` |

### Result rows

- Results are drawn under the prompt, one per row, in the `font` color, at x = 0 (`menu.c:405-417`).
- Rows that would start past the bottom of the screen area are not drawn (`menu.c:408-410`).
- **Selection highlight** (`menu.c:418-419,422-444`): after every redraw, **row 1 (the first result) is highlighted**. The row gets a full-width rectangle of `menufg` (black) with the text redrawn in `selfont` (white). This is inverse video.

**Keyboard navigation rotates the list.** Up and Down do **not** move the highlight. Instead (`menu.c:244-259`):

- **Down** moves the first result to the tail of the list.
- **Up** moves the last result to the head.

Because of this, the highlighted item is always the top row and the list visibly scrolls or rotates.

**Mouse hover** (`menu.c:446-462`):

- The row under the pointer is highlighted.
- The previously hovered row is un-highlighted (redrawn with a `menubg` rectangle and `font` text).
- On the first hover over a row, the grab cursor switches from `question_arrow` to `left_ptr`.

**[INFERENCE]** Because the hover code never clears the row-1 highlight that `menu_draw` applied, two rows can appear highlighted at once: row 1 and the hovered row.

### List versus filter mode

**Menus opened by a mouse button** (`cargs->xev == CWM_XEV_BTN` sets `CWM_MENU_LIST`, `kbfunc.c:540-541,571-572,600-601`):

- The menu shows **all entries immediately** (`menu.c:342-351`).

**Menus opened by a key:**

- The menu shows **only the prompt line** until you type something.
- **C-a** toggles "list all" (`menu.c:304-306,557-559`).
- Matching runs only when the search string is non-empty (`menu.c:322-324`).

**[INFERENCE]** After you backspace to an empty string, the previous results stay on screen. The result queue is not cleared in that path.

### No match

- If nothing matches, only the prompt line is drawn.
- On **Return** with no results, a dummy item holding the typed text is returned (`menu.c:260-272`):
  - **exec, ssh and label** (`CWM_MENU_DUMMY`) use that typed text.
    - exec spawns the typed text verbatim (`kbfunc.c:700-705`).
    - ssh runs ssh to the typed host.
  - **window, group, application and wm** discard the dummy (`menu.c:170-174`), so nothing happens.

### Mouse selection

- The selection happens on **ButtonRelease** over a result row (`menu.c:160-164,464-481`).
- Releasing over the prompt row or outside the menu returns a dummy item, which is discarded for non-dummy menus.

**[INFERENCE]** This means root menus are used press-drag-release. A quick click on the root opens the menu, and the release over the prompt row closes it again without a selection.

### Key handling inside a menu (`menu.c:503-589`; also `cwm.1:181-199`)

| Key | Action |
|---|---|
| Return, KP_Enter | Select the top (highlighted) result |
| Down, C-s, M-j | Next (rotates the list) |
| Up, C-r, M-k | Previous (rotates the list) |
| BackSpace, C-h | Erase one UTF-8 character |
| C-u | Clear the input |
| C-a | Toggle "list all" |
| Escape, C-[ | Abort |
| Tab | Complete to the common case-insensitive prefix of all results. In the exec menu, if the input already starts with the top result, it opens a file-path completion sub-menu whose prompt is the current input (`menu.c:277-303,191-217`). |
| Anything else | `XLookupString` text is appended to the input |

### Limits

- **Input and entry length:** `MENU_MAXENTRY` = 200 bytes (`calmwm.h:275`).
- **Number of entries:** no fixed cap. The visible count is limited only by screen height.

## 5. Default key bindings [SOURCED]

### Modifier letters

From `conf.c:202-211`:

| Letter | Modifier |
|---|---|
| `S` | Shift |
| `C` | Control |
| `M` | Mod1 (Meta/Alt) |
| `4` | Mod4 (Super/"windows" key) |
| `5` | Mod5 (AltGr) |

- A binding name is written as `<mods>-<keysym>`, and modifiers may come in any order before the dash (`conf.c:529-545`).
- CapsLock and NumLock (Mod2) are ignored when matching (`conf.c:199-201`; `IGNOREMODMASK` at `calmwm.h:50`).

### Full default table

`key_binds[]`, `conf.c:212-270`:

| Key | Function | | Key | Function |
|---|---|---|---|---|
| CM-Return | terminal | | CM-g | window-group |
| CM-Delete | lock | | CM-f | window-fullscreen |
| M-question | menu-exec | | CM-m | window-maximize |
| CM-w | menu-exec-wm | | CM-s | window-stick |
| M-period | menu-ssh | | CM-equal | window-vmaximize |
| M-Return | window-hide | | CMS-equal | window-hmaximize |
| M-Down | window-lower | | CMS-f | window-freeze |
| M-Up | window-raise | | CMS-r | restart |
| M-slash | menu-window | | CMS-q | quit |
| C-slash | menu-cmd | | M-h | window-move-left |
| M-Tab | window-cycle | | M-j | window-move-down |
| MS-Tab | window-rcycle | | M-k | window-move-up |
| M-grave | window-cycle-inclass | | M-l | window-move-right |
| MS-grave | window-rcycle-inclass | | MS-h | window-move-left-big |
| CM-n | window-menu-label | | MS-j | window-move-down-big |
| CM-x | window-close | | MS-k | window-move-up-big |
| CM-a | group-toggle-all | | MS-l | window-move-right-big |
| CM-0 | group-toggle-all | | CM-h | window-resize-left |
| CM-1 … CM-9 | group-toggle-1 … 9 | | CM-j | window-resize-down |
| M-Right | group-cycle | | CM-k | window-resize-up |
| M-Left | group-rcycle | | CM-l | window-resize-right |
| | | | CMS-h | window-resize-left-big |
| | | | CMS-j | window-resize-down-big |
| | | | CMS-k | window-resize-up-big |
| | | | CMS-l | window-resize-right-big |

### Functions with no default binding

These exist in `name_to_func[]` (`conf.c:71-198`) but are bound to nothing by default:

- `window-htile`, `window-vtile`
- `window-snap-{center,up,down,left,right,up-right,up-left,down-right,down-left}`
- `group-only-1..9`, `group-close-1..9`, `group-last`
- `window-movetogroup-1..9`
- `window-cycle-ingroup`, `window-rcycle-ingroup`
- `menu-window-hidden`
- `window-delete` (an alias of `window-close`)
- `pointer-move-*`
- `window-move`, `window-resize` (these are bound only to mouse buttons)

### Binding contexts

- **Per-window (`FUNC_CC`):** these act on the window under the pointer (`e->subwindow`), falling back to the current active window (`xevents.c:332-337`).
- **Per-screen (`FUNC_SC`):** these act on the screen.
- **Unknown function names** are treated as a shell command line to execute (`conf.c:581-584`).

### Move and resize amounts

- `moveamount` default: `c->mamount = 1;` (`conf.c:291`). The man page says "The default is 1." (`cwmrc.5:197-200`).
- "Big" variants multiply by `CWM_FACTOR 10` (`kbfunc.c:57-60`). By default:
  - small move = **1px**
  - big move = **10px**
- **Keyboard resize** (`kbfunc.c:208-235`) is in **size-hint increments**:
  - If the client sets `PResizeInc`, which xterm does (character cells), one step is `1 × incw/inch` and a big step is `10 × incw/inch`. For xterm that is 1 or 10 character cells.
  - Otherwise `amt = moveamount`, which gives 1px or 10px.
  - The result is clamped to the minimum size.
  - Keyboard resize always grows or shrinks the **right and bottom** edges. "resize-left" and "resize-up" shrink the width and height.
- **Pointer moves** (`pointer-move-*`) use the same amounts (`kbfunc.c:78-89`).

## 6. Default mouse bindings [SOURCED]

`mouse_binds[]`, `conf.c:271-280`:

| Binding | Function | Context |
|---|---|---|
| `1` (left, no modifiers, on root) | menu-window | screen |
| `2` (middle, on root) | menu-group | screen |
| `3` (right, on root) | menu-cmd ("application" menu) | screen |
| `M-1` | window-move | window |
| `CM-1` | window-group (toggle membership, flashes blue/red) | window |
| `M-2` | window-resize | window |
| `M-3` | window-lower | window |
| `CMS-3` | window-hide | window |

**Where clicks are delivered:**

- Per-window button bindings are grabbed only on the **active** client window (`conf.c:692-710`, called from `client.c:266`).
- Screen bindings fire from button presses on the root window (`screen.c:72-73` sets `ButtonPressMask` on root).
- An **unmodified click inside a client window is not intercepted at all**. It does not raise the window, and it does not set focus. See section 12.

**Mouse move** (`kbfunc.c:148-206`):

- Raises the window, grabs the pointer with the **`XC_fleur`** cursor, and moves the window live, at most 60 updates per second.
- Snaps to area edges within `snapdist`.
- Shows a geometry overlay with the text `"%+5d%+5d"` giving x and y (for example `" +120 +45"`).

**Mouse resize** (`kbfunc.c:237-289`):

- Raises the window and **warps the pointer to the bottom-right corner** of the window.
- Grabs the pointer with the **`XC_bottom_right_corner`** cursor.
- Resizes from the bottom-right only, applying size hints (increments, minimum and maximum size, aspect ratio; `client.c:798-843`).
- The overlay shows `"%4d x %-4d"` in **size-hint units**. For xterm that is columns × rows, for example `"  80 x 24  "`.

**Geometry overlay window** (`screen.c:268-307`):

- A child window of the client, positioned at **(0,0) inside the client** (its top-left corner).
- Border width 0. Background is `menubg` (white) and text is `font` (black).
- Width is the text's `xOff` and height is `xftfont->height`. There is no padding.

## 7. Command / application menu [SOURCED]

- **Defaults:** `conf_cmd_add(c, "lock", "xlock"); conf_cmd_add(c, "term", "xterm");` (`conf.c:314-315`). The wm menu also contains `cwm → cwm` (`conf.c:316`).
- **What the application menu lists:** `kbfunc_menu_cmd` **skips the entries named `lock` and `term`** (`kbfunc.c:575-580`).
  - So with the default config the application menu (right-click on root, or C-slash) is **empty**. It shows only the prompt line `application»«`.
  - Only `command name path` lines from `.cwmrc` populate it.
- **Entry format:** each row is the command `name` only (`"%s"`, `search.c:258-264`).
- **Matching:** case-insensitive substring match on the name, in config order (`search.c:130-142`).
- **Running:** the selected command runs via `u_spawn(cmd->path)` (`kbfunc.c:585`).
- **`terminal` (CM-Return)** spawns every cmdq entry named `term`, which is `xterm` by default (`kbfunc.c:805-814`).
- **`lock` (CM-Delete)** spawns `xlock` (`kbfunc.c:816-825`).

## 8. Window menu, exec menu, ssh menu, search [SOURCED]

### Window menu (`menu-window`: M-slash, or button 1 on root)

- **Which windows:** the source list is `sc->clientq`. That is all windows for `menu-window`, or only hidden ones for `menu-window-hidden` (`kbfunc.c:543-548`).
- **Order:** `clientq` is kept in **most-recently-focused order**. `client_mtf` moves the focused window to the head (`client.c:259-261,741-748`). So an unfiltered list is MRU-first.
- **Row format** (`search.c:242-256`):

  ```c
  snprintf(mi->print, ..., "(%d) %c[%s] %s",
      cc->gc ? cc->gc->num : 0, flag, cc->label ? cc->label : "", cc->name);
  ```

  `flag` is:
  - `'!'` if the window is active (focused)
  - `'&'` if it is hidden
  - otherwise `' '` (a space)

  Example rows:
  - `(0) ![] xterm`
  - `(1)  [] top`
  - `(3) &[mail] mutt`

  Group 0 means "no group". The label brackets are always shown, even when empty.
- **Selecting a window** shows it (unhides and `XMapRaised`) and warps the pointer into it (`kbfunc.c:550-557`). Focus then follows the pointer.

### Search and match algorithm for windows

`search_match_client`, `search.c:69-128`:

- `match_substr(search, str, 0)` is a **case-insensitive substring** match. It tries `strncasecmp` at every offset (`search.c:42-67`).
- **Tiers:**
  - 0: matches the **label**
  - 1: matches any of the window's **title history** (searched from the current title back to older ones)
  - 2: matches the **WM_CLASS res_class**
- **Rank adjustments:**
  - The active window is ranked **down** one tier, if possible.
  - Hidden windows are ranked **up** one tier.
- Results are grouped by tier (0, then 1, then 2), keeping `clientq` (MRU) order within each tier.
- **Title history** keeps `nameqlen = 5` titles (`conf.c:296`, `client.c:661-691`; `cwm.1:215`).

### Exec menu (`menu-exec`: M-question, which is Alt+Shift+/ on US layouts)

**Collecting entries** (`kbfunc.c:647-710`):

- Splits `$PATH` (or `_PATH_DEFPATH`) on `:`, up to 256 directories.
- Lists every regular file or symlink in each directory that passes `access(X_OK)`, using the base name only.
- Duplicates are **not** removed.

**Matching** (`search_match_exec`, `search.c:183-206`):

- An entry matches if the input is a **case-insensitive prefix** (`match_substr(..., 1)`, so zeroidx means prefix only) **or** if the input as an `fnmatch(3)` glob matches the entry.
- Results are **sorted with strcmp (ASCII order)** by insertion sort. Entries that compare equal are dropped (`r <= 0` breaks, `r < 0` inserts).
- If nothing matches, it falls back to a filesystem glob of `<input>*` filtered to executables. This lets you type a path such as `/usr/local/bin/fo`.

**Running:** Return runs the top result, or the raw typed text if there are no results (dummy), via `u_spawn`.

**Rows:** each row prints the plain text (`search_print_text`).

### ssh menu (`menu-ssh`: M-period)

**Reading hosts** (`kbfunc.c:712-776`):

- Reads `~/.ssh/known_hosts` (`conf.c:330`).
- Skips hashed lines that start with `|1|`.
- Takes each line's text up to the first `,` or space as the host.
- Matching is a case-insensitive substring match, in file order (`search.c:215-225`).

**Running:** it spawns

```c
"%s -T '[ssh] %s' -e ssh %s"   // term path, host, host
```

That is, `xterm -T '[ssh] host' -e ssh host`. The typed text is used if there is no match.

### Group menu (`menu-group`: button 2 on root)

- **Which groups:** groups that hold **only sticky windows** are excluded. That includes **empty groups**, because `group_holds_only_sticky` returns 1 for a group with no clients (`kbfunc.c:603-608`, `group.c:183-196`).
- **Row format** (`search.c:266-274`):
  - `"%d: %s"`, for example `1: one`
  - `"%d: [%s]"` when every window in the group is hidden, for example `2: [two]`
- **Group names:** nogroup, one, two, three, four, five, six, seven, eight, nine (`conf.c:39-53`).
- **Matching:** substring match against `"%d %s"` (`search.c:144-159`).
- **Selecting** a group shows it if it is fully hidden, and otherwise hides it (`kbfunc.c:612-614`).

### Label menu (`window-menu-label`: CM-n)

- Prompt `label`, pre-filled with the current label (`kbfunc.c:778-797`).
- Return sets the label. Escape keeps the old one.

### wm menu (`menu-exec-wm`: CM-w)

- Rows are `"%s [%s]"`, i.e. name and path (`search.c:282-289`). The default row is `cwm [cwm]`.
- Selecting a row re-execs that window manager.

## 9. Groups [SOURCED]

### Group model

- There are **10 groups, numbered 0–9** (`conf.c:39-53,518-527`). Group 0 is named "nogroup".
- **Group 1 is the initially active group** (`group.c:136-137`).
- `group_assign(gc)` with group number 0 sets `cc->gc = NULL` (`group.c:40-49`). A window with no group is never hidden or shown by group operations.

### Sticky

There are two related "sticky" concepts.

1. **`sticky` cwmrc option (sticky group mode).**
   - **Default off:** `c->stickygroups = 0` (`conf.c:289`).
   - When it is off, new windows get **no group** (`client.c:139-142`). The man page says "The default behavior for new windows is to not assign any group" (`cwmrc.5:204-209`).
   - When it is on, new windows join the currently active group.
   - Before that, a new window may already be placed by `_NET_WM_DESKTOP` restore or by autogroup (`client.c:130-143`).

2. **`window-stick` (CM-s).**
   - Toggles the per-window `CLIENT_STICKY` flag (`client.c:301-306`).
   - Sticky windows are skipped by `group_hide` and `group_show` (`group.c:62,77`).
   - The man page says "Stick current window to all groups (same as assigning to nogroup)" (`cwmrc.5:314-315`).

### Group operations

| Operation | Behaviour | Source |
|---|---|---|
| **group-toggle-N** (CM-1..9) | If every window in group N is hidden or sticky, show the group. Otherwise hide it. | `group.c:229-242` |
| **group-only-N** (unbound) | Remember the current active group as `group_last`. Show group N and hide all other groups. | `group.c:213-227` |
| **group-toggle-all** (CM-a / CM-0) | Alternately hide and show every group, using the `sc->hideall` toggle. | `group.c:244-256` |
| **group-cycle / group-rcycle** (M-Right / M-Left) | Walk forward or backward through the groups. The first group that is not only-sticky (empty groups count as only-sticky and are skipped) becomes the shown group. Every other non-empty group passed along the way is hidden, and the old group is hidden. If the new group was fully hidden it is shown (`group_show` restacks and sets it active); otherwise it is just made active. If no candidate exists, nothing happens. | `group.c:275-304` |
| **window-group** (CM-g / CM-M1) | Toggles the window's membership in the **active** group. Membership is set if the window is not in it and cleared if it is. The border flashes blue or red. | `group.c:167-181` |
| **window-movetogroup-N** | Moves the window to group N, and hides it if group N is currently fully hidden. | `group.c:150-165` |
| **group_show** | Maps hidden non-sticky members, restores their saved stacking order, and makes the group active. | `group.c:68-83,85-123` |

### Hide and unhide

- **`client_hide`** (`client.c:544-555`): `XUnmapWindow`, sets `CLIENT_HIDDEN`, sets `WM_STATE` to IconicState, and clears active if the window was active.
- **`client_show`** (`client.c:557-565`): `XMapRaised`, clears hidden, sets NormalState, and redraws the border.
- There is **no icon or taskbar representation**. Hidden windows can only be found via the window menu (`&` flag), the group menu, or group toggles.

## 10. Tiling, snap, maximize, fullscreen [SOURCED]

### Screen areas

- `screen_area(sc, x, y, apply_gap)` returns the RandR region containing the point. With `apply_gap`, the gap is subtracted (`screen.c:157-173,234-243`).
- Every geometry operation uses the region containing the **window's center**.

### window-htile (`client.c:913-980`; unbound by default; `htile` defaults to 50, `conf.c:292`)

1. **Count `n` candidates.** A candidate is a window with the same `gc` as the master (NULL equals NULL), that is not hidden, not ignored, not the master, and whose **top-left corner** lies within the area (inclusive bounds). If `n == 0`, return.
2. **Abort** if the master is vertically maximized, or if `master.h + 2*bw >= area.h`.
3. **Place the master.** Clear its hmaximized flag, then:

   ```
   x = area.x
   y = area.y
   w = area.w - 2*bw
   h = ((area.h - 2*bw) * htile) / 100     // only if htile > 0; otherwise height is kept
   ```

   Resize it and warp the pointer into it.
4. **Lay out the other windows.** Compute:

   ```
   mh = master.h + 2*bw
   w  = area.w / n          // integer division
   h  = area.h - mh
   ```

   Then for each candidate, in `clientq` (MRU) order, with x starting at `area.x`:

   ```
   bw  = Conf.bwidth
   geom = (x, area.y + mh, w - 2*bw, h - 2*bw)
   ```

   The **last** candidate's width is stretched to `area.x + area.w - x - 2*bw`. Then `x += w`.

   The result is a row of equal-width windows under the master.

### window-vtile (`client.c:982-1049`; `vtile` defaults to 50, `conf.c:293`)

This is the transpose of htile:

- **Master:** `x = area.x`, `y = area.y`, `w = ((area.w - 2*bw) * vtile) / 100`, `h = area.h - 2*bw`.
- **Others:** a column at `x = area.x + mw` with width `area.w - mw - 2*bw` and height `area.h/n - 2*bw`. The last candidate's height is stretched to the bottom.
- **Aborts** if the master is horizontally maximized, or if `master.w + 2*bw >= area.w`.

Tiling is one-shot. There is no persistent layout: windows remain floating afterwards.

### window-maximize (CM-m) (`client.c:342-381`)

- **Toggle on:** saves the geometry, then sets `geom = (area.x, area.y, area.w - 2bw, area.h - 2bw)` with **gap honoured**. The border stays.
- **Toggle off:** restores the saved geometry.

### vmaximize / hmaximize (CM-equal / CMS-equal) (`client.c:383-447`)

- vmaximize changes only y and h; hmaximize changes only x and w.
- Both use the same formula as maximize, honour the gap, and keep the border.

### window-fullscreen (CM-f) (`client.c:308-340`)

- Sets **border width = 0** and geometry = the full region **without gap**.
- Also sets FREEZE, so the window cannot be moved or resized while fullscreen.
- Toggling off restores the border and geometry.

### window-snap-* (unbound) (`kbfunc.c:291-333`)

| Direction | Effect |
|---|---|
| up | `y = area.y` |
| left | `x = area.x` |
| right | `x = area.x + area.w - w - 2bw` |
| down | `y = area.y + area.h - h - 2bw` |
| center | `x = area.x + (area.w - w - bw)/2`, same pattern for y. Note this uses `bw`, **not** `2bw` (it is in the source). |

The size never changes.

### Edge snapping while moving

`client_snapcalc` (`client.c:886-911`):

- If either edge of the window (counting the border) is within `snapdist` px of the matching area edge, the window jumps to that edge. If both edges qualify, the closer one wins.
- **`snapdist` defaults to 0** (`conf.c:294`; `cwmrc.5:201-203`). Snapping is effectively off, because only an exact 0px distance qualifies.

### window-freeze (CMS-f)

Toggles `CLIENT_FREEZE`. A frozen window ignores move, resize, maximize and fullscreen-on (`client.c:270-278`, plus the checks throughout).

### Gap

- `gap top bottom left right`. Unset by default: `Conf` is a zero-initialised global (`calmwm.c:44`), `conf_init` never sets `gap`, and `conf_screen` copies `Conf.gap` into the screen (`conf.c:487`). So the default is **0 0 0 0**.
- The gap applies to maximize, tile, snap, menu clamping and placement. It does **not** apply to fullscreen (`cwmrc.5:176-185,316-323`).

## 11. Placement and geometry defaults [SOURCED]

### New window placement

`client_placement`, `client.c:693-739`. This runs only for windows that were not already viewable when they were mapped.

- **If the client set `USPosition` or `PPosition`:** its requested position is used, with only an off-screen sanity clamp.
- **Otherwise the window is centred on the pointer, clamped to the area** (gap applied):

  ```
  x = max(max(ptrx, area.x) - w/2, area.x)
  y = max(max(ptry, area.y) - h/2, area.y)
  x = max(min(x, area.x + area.w - w - 2bw), area.x)
  y = max(min(y, area.y + area.h - h - 2bw), area.y)
  ```

  If the window is wider or taller than the area, it is placed at `area.x` or `area.y` and its w/h is set to `area.x + area.w` / `area.y + area.h`.
- **Immediately after mapping**, cwm warps the pointer into the new window at its centre (`ptr = w/2, h/2`; `client.c:100-101`, `xevents.c:95-96`). The new window therefore receives focus via EnterNotify.

### Default configuration values

| Setting | Default | Source |
|---|---|---|
| `borderwidth` | 1 | `conf.c:290` |
| `moveamount` | 1 | `conf.c:291` |
| `htile` | 50 | `conf.c:292` |
| `vtile` | 50 | `conf.c:293` |
| `snapdist` | 0 | `conf.c:294` |
| `sticky` | no | `conf.c:289` |
| `gap` | 0 0 0 0 | zero-initialised global |
| title history length | 5 | `conf.c:296` |
| `fontname` | `sans-serif:pixelsize=14:bold` | `conf.c:318` |
| config file | `~/.cwmrc` | `conf.c:329` |
| known_hosts | `~/.ssh/known_hosts` | `conf.c:330` |
| `_NET_WM_NAME` of the WM | `"CWM"` | `conf.c:319`, `xutil.c:212` |

### Off-screen limits

- **Keyboard move** (`kbfunc.c:122-131`): a window may be pushed almost entirely off-screen. It is clamped so that it stays within about `bwidth` px of each screen edge. For example, x is limited to the range `[-(w + bw - 1), view.w - bw - 1]`.
- **Mouse move:** has no clamp.
- **On screen change:** `screen_assert_clients_within` moves windows that are fully off-screen back to `(gap.left, gap.top)` (`screen.c:245-266`).

## 12. Other visible behaviour [SOURCED unless marked]

### Cursors

`conf.c:54-59`:

| Use | Cursor |
|---|---|
| Root / normal | `XC_left_ptr` (also set on root, `screen.c:71`) |
| Move | `XC_fleur` |
| Resize | `XC_bottom_right_corner` |
| Menu open | `XC_question_arrow`, switching to `XC_left_ptr` once the pointer hovers a menu entry |

### Focus model

- **Focus follows the mouse (sloppy).** An EnterNotify on a client calls `client_set_active` (`xevents.c:225-237`).
- **Focus does not raise the window.**
- **Clicking a window does not raise or focus it.** There is no click-to-focus handler; only bound modifier+button combinations are grabbed.
- **Things that do raise a window:** M-Up, window-cycle, mouse move or resize, and showing a window (`XMapRaised`).
- **M-Down / M-3** lowers the window to the bottom.
- **The only focus indicator** is the border color changing from #666666 to #CCCCCC.

### Pointer warping

cwm moves the pointer itself in these situations:

- when cycling
- when selecting a window from the menu
- when a new window maps
- after maximize, fullscreen, snap, tile or keyboard move/resize, it is clamped back inside the window (`client_ptr_inbound`, `client.c:505-521`)
- for menu clamping

Each window remembers its own last pointer position (`client_ptr_save`).

### window-cycle (M-Tab) visual behaviour

`kbfunc.c:408-472`:

- **There is no on-screen switcher, list or overlay.**
- Each press:
  - steps to the next or previous client in `clientq` (MRU order), skipping hidden, ignored, skip-taskbar and skip-pager windows
  - raises the MRU-first window and then the new window
  - warps the pointer to the new window's saved pointer position (or its centre), so focus follows
- While the modifier is held, `sc->cycling = 1` freezes the MRU order. On release of Control, Alt, Meta, Super or ISO_Level3, the chosen window is moved to the front (`xevents.c:369-372`). This gives Alt-Tab-like MRU semantics.
- **window-cycle-inclass (M-grave):** limited to windows of the same WM_CLASS.
- **window-cycle-ingroup:** limited to windows in the same group.

### Urgency

The window gets an orange #FC8814 border until it is focused.

### Screen edges

There is no edge-flipping and there are no virtual desktops beyond groups. Snapping is off by default (snapdist 0).

### Title bar text

cwm displays window titles **nowhere** except in the window menu.

---

## Faithful web translation notes [INFERENCE — not from source]

This section contains design recommendations derived from the facts above.

### CSS tokens

```css
:root {
  --cwm-border-w: 1px;               /* borderwidth 1 */
  --cwm-active: #CCCCCC;             /* activeborder */
  --cwm-inactive: #666666;           /* inactiveborder */
  --cwm-urgent: #FC8814;             /* urgencyborder */
  --cwm-group: #0000FF;              /* "blue" */
  --cwm-ungroup: #FF0000;            /* "red" */
  --cwm-menu-fg: #000000;            /* menufg: menu border + selection bar */
  --cwm-menu-bg: #FFFFFF;            /* menubg */
  --cwm-menu-font: #000000;          /* font */
  --cwm-menu-selfont: #FFFFFF;       /* computed bg^fg^font */
  --cwm-font: bold 14px "DejaVu Sans", sans-serif;  /* pixelsize=14:bold */
}
```

### Client windows

- Use `box-sizing: content-box; border: 1px solid var(--cwm-inactive);` and switch the color to `--cwm-active` on focus.
- Give them `border-radius: 0` and **no** shadow, title bar or padding.
- **xterm look:**
  - cwm does not control this; it comes from xterm defaults.
  - xterm's own default is black text on a white background with the `fixed` bitmap font (6x13).
  - Many users configure reverse video instead.
  - None of this comes from cwm source. Verify it against your target screenshot.
- **Do not use a CSS `outline` for the border.** In X, the border sits outside the client geometry: the window position (x, y) is the outer border's top-left, and its outer size is `w + 2bw` by `h + 2bw`. CSS `content-box` with `left/top` = (x, y) reproduces this exactly.

### Menu

- Style: `position: fixed`, `left/top` = pointer, `border: 1px solid #000`, `background: #fff`, `color: #000`, `padding: 0`, `white-space: pre`, `line-height` = ascent + descent (about 17px; measure it), `width: max-content`.
- **Prompt row:** render `${prompt}»${input}«`, for example `window»«`.
- **Selected row:** the first result row gets `background: #000; color: #fff`.
- **Keyboard navigation:** rotate the array instead of moving an index.
- **Clamping:** clamp the menu into the viewport. When it moves, the real cwm also warps the pointer. Browsers cannot warp the pointer, so skip that part.
- **Cursor:** use `cursor: help` (the closest match to `question_arrow`) while the menu is open, switching to `default` over entries.
- **Root clicks:** open the menu on `mousedown` on the root and select on `mouseup` over a row. This reproduces press-drag-release.
- **Opened by key:** show the prompt only. **Opened by mouse:** show all entries.

### Geometry overlay during drag

- An element absolutely positioned at the client's top-left inside its border, white background, black bold 14px text, no padding.
- Text: `sprintf("%+5d%+5d", x, y)` while moving, and `"%4d x %-4d"` in cols × rows while resizing.

### Cursors during drag

`move` (fleur) and `se-resize` (bottom_right_corner).

### Focus model

- Set focus on `mouseenter` of a window (sloppy focus; leaving to the root does not unfocus).
- Do **not** raise the window on click.
- Raise only on the explicit actions listed in section 12.

### Key handling

Implement this with a `keydown` listener in the capture phase on `window`, using `event.code` (layout-independent physical key) plus modifier flags.

**Modifier mapping:**

- `M` = `event.altKey`
- `C` = `event.ctrlKey`
- `S` = `event.shiftKey`
- `4` = `event.metaKey`

**macOS: Option produces dead or composed characters.** Option+key yields accented characters in `event.key` (for example Option+h → "˙"). So match on `event.code` (`KeyH`, `Slash`, `Period`, `Backquote`, `Equal`, `Digit1`, `Enter`, `Tab`, `ArrowUp`, …), never on `event.key`, whenever altKey is set.

**Browser- and OS-reserved combinations:**

| Combination | Problem | Workaround |
|---|---|---|
| M-Tab / MS-Tab | Option+Tab is free on macOS, but on Windows/Linux Alt+Tab is taken by the OS and never reaches the page. | Offer a configurable fallback binding (e.g. M-grave or a Ctrl-based chord) on those platforms. |
| Cmd-anything | Cmd+W, Cmd+Q, Cmd+T, Cmd+N, Cmd+Tab and Cmd+H cannot be intercepted (the browser or OS acts first). | Do not map cwm's `M` to Cmd. Use Option/Alt as Meta, which matches X convention (Mod1 = Alt). |
| CM-x (Ctrl+Alt+x) and similar | Mostly free in browsers on macOS. | On Windows, Ctrl+Alt equals AltGr on many layouts, so `event.getModifierState('AltGraph')` may be true. |
| CM-Delete | On a Mac keyboard, "Delete" is Backspace (`event.code === 'Backspace'`). Forward delete is `Delete` (fn+Backspace). | Map cwm's `Delete` keysym to both. |
| C-slash, M-question, M-period | Free in most browsers. | M-question is Alt+Shift+Slash on US layouts. cwm's keysym logic adds Shift automatically for shifted symbols (`conf.c:682-684`, `xevents.c:311-326`), so match `code==='Slash' && altKey && shiftKey`. |
| CMS-r, CMS-q | Ctrl+Alt+Shift+R/Q are free. | Never map them to Cmd+Shift+Q (macOS log out). |
| M-Left / M-Right | Option+Arrow is word navigation in text fields, and browser Alt+Left/Right is history back/forward on Windows/Linux. | Must `preventDefault()`. |
| Ctrl+Arrows on macOS | Taken by Mission Control/Spaces. | No impact on the defaults, because cwm does not use C-arrows. |
| Fullscreen | Browser fullscreen needs the Fullscreen API on a user gesture. | cwm's CM-f fullscreen is a window-geometry change (border 0, fill the area). Do not call `requestFullscreen` for it. |

General rules:

- Call `preventDefault()` and `stopPropagation()` for every matched binding.
- When focus is inside an embedded terminal (for example xterm.js), intercept cwm bindings **before** the terminal sees them, as X does with a passive grab. Let all other keys through.

**Menu keys:**

- Return, Esc, C-[, Up/Down, C-s/C-r, M-j/M-k, Backspace/C-h, C-u, C-a, Tab (common-prefix completion).
- C-a and C-u collide with nothing in a menu, because the menu has keyboard focus.

**Modifier release:** track `keyup` of Alt, Control, Meta and Shift-less modifiers to end window-cycling (commit MRU) and to clear the blue/red group flash. These match the modifier keys cwm itself watches (`xevents.c:71-75`).

### Things browsers cannot reproduce exactly

- pointer warping
- `XC_question_arrow` / `fleur` cursor bitmaps (use the CSS equivalents above)
- exact Xft/FreeType glyph rasterisation and metrics

---

## Items not verifiable from source (flagged)

- **Exact pixel ascent and descent** for `sans-serif:pixelsize=14:bold`. These depend on the system's fontconfig resolution, which is not in the cwm tree.
- **Root window background.** cwm never sets it. What appears is the X server or xenodm default, or whatever the user sets (for example `xsetroot`).
- **xterm appearance** (font, colors, scrollbar). This is xterm's own configuration, not cwm's.
- **Whether a default `xterm` sets `PPosition`.** This decides between pointer-centred placement and honouring the requested position. It is not determinable from cwm source.
