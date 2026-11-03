// cwm-style keys: 1–9 jump to a group (section), "/" opens the search prompt,
// ↑/↓ move the reverse-video selection through the menu, Enter follows it, Esc closes.
(function () {
  var input = document.getElementById('mkdocs-search-query');
  var menu = document.getElementById('mkdocs-search-results');
  var sel = -1;

  function typing(t) {
    return t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable);
  }
  function items() { return menu ? Array.prototype.slice.call(menu.querySelectorAll('article')) : []; }
  function select(i) {
    var list = items();
    list.forEach(function (a) { a.classList.remove('sel'); a.removeAttribute('aria-selected'); });
    if (!list.length) { sel = -1; return; }
    sel = (i + list.length) % list.length;
    list[sel].classList.add('sel');
    list[sel].setAttribute('aria-selected', 'true');
    list[sel].scrollIntoView({ block: 'nearest' });
  }
  function open(on) {
    if (!menu) return;
    menu.classList.toggle('open', !!on && menu.childElementCount > 0 && input.value.length > 0);
  }
  function close() { open(false); sel = -1; if (input) input.blur(); }

  if (menu && input) {
    new MutationObserver(function () { sel = -1; open(document.activeElement === input || location.pathname.slice(-11) === 'search.html'); if (items().length) select(0); })
      .observe(menu, { childList: true });
    input.addEventListener('focus', function () { open(true); });
    input.addEventListener('blur', function () { setTimeout(function () { if (document.activeElement !== input) open(false); }, 150); });
    menu.addEventListener('mousedown', function (e) {
      var a = e.target.closest('article');
      if (!a) return;
      var link = a.querySelector('a');
      if (link) { e.preventDefault(); location.href = link.href; }
    });
    input.form.addEventListener('submit', function (e) {
      var list = items();
      if (sel >= 0 && list[sel]) { e.preventDefault(); location.href = list[sel].querySelector('a').href; }
    });
    input.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowDown') { e.preventDefault(); select(sel + 1); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); select(sel - 1); }
      else if (e.key === 'Escape') { e.preventDefault(); input.value = ''; close(); }
    });
  }

  document.addEventListener('keydown', function (e) {
    if (e.metaKey || e.ctrlKey || e.altKey || typing(e.target)) return;
    if (e.key === '/' && input) { e.preventDefault(); input.focus(); input.select(); return; }
    if (e.key === 'Escape') { close(); return; }
    if (/^[1-9]$/.test(e.key)) {
      var g = document.querySelector('.groups a[data-group="' + e.key + '"]');
      if (g) { e.preventDefault(); location.href = g.href; }
    }
  });
})();
