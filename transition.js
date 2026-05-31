// ── Lunex Page Transition (slide left/right) ─────────────
(function () {
  var ORDER = ['login.html', 'dashboard.html', 'chat.html', 'dm.html', 'admin.html'];

  function pageName() {
    return window.location.pathname.split('/').pop() || 'login.html';
  }

  function pageIndex(name) {
    var n = name.split('/').pop();
    var idx = ORDER.indexOf(n);
    return idx === -1 ? 0 : idx;
  }

  // Get or create overlay
  var overlay = document.getElementById('page-transition');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'page-transition';
    document.body.appendChild(overlay);
  }

  // Force overlay styles (overrides any CSS)
  overlay.style.position   = 'fixed';
  overlay.style.inset      = '0';
  overlay.style.background = '#000';
  overlay.style.zIndex     = '99999';
  overlay.style.pointerEvents = 'none';
  overlay.style.opacity    = '0';
  overlay.style.transform  = 'translateX(0)';
  overlay.style.transition = 'opacity .32s cubic-bezier(.4,0,.2,1), transform .32s cubic-bezier(.4,0,.2,1)';

  // ── ENTER animation (new page slides in) ─────────────────
  var dir = sessionStorage.getItem('lunex_nav_dir') || 'forward';
  sessionStorage.removeItem('lunex_nav_dir');

  // Position overlay off-screen on the incoming side, then slide it away
  // forward: new page comes from right → overlay was on right, slides left off
  // back:    new page comes from left  → overlay was on left, slides right off
  overlay.style.opacity = '1';
  overlay.style.transform = dir === 'forward' ? 'translateX(100%)' : 'translateX(-100%)';

  // Double rAF ensures the browser paints the start position before animating
  requestAnimationFrame(function () {
    requestAnimationFrame(function () {
      overlay.style.transform = 'translateX(0)';
      overlay.style.opacity   = '0';
    });
  });

  // ── EXIT animation (current page slides out) ──────────────
  var currentPage = pageName();

  document.addEventListener('click', function (e) {
    var a = e.target.closest('a[href]');
    if (!a) return;
    var href = a.getAttribute('href');
    if (!href || href.startsWith('#') || href.startsWith('javascript') || href.startsWith('http')) return;
    if (a.target === '_blank') return;

    e.preventDefault();

    var fromIdx = pageIndex(currentPage);
    var toIdx   = pageIndex(href);
    var forward = toIdx >= fromIdx;

    sessionStorage.setItem('lunex_nav_dir', forward ? 'forward' : 'back');

    // Overlay slides in from center (opacity 0→1) while page slides out
    // forward: overlay comes from right  → translateX(100%) → translateX(0)
    // back:    overlay comes from left   → translateX(-100%) → translateX(0)
    overlay.style.transition = 'none';
    overlay.style.opacity    = '0';
    overlay.style.transform  = forward ? 'translateX(100%)' : 'translateX(-100%)';

    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        overlay.style.transition = 'opacity .32s cubic-bezier(.4,0,.2,1), transform .32s cubic-bezier(.4,0,.2,1)';
        overlay.style.transform  = 'translateX(0)';
        overlay.style.opacity    = '1';
        setTimeout(function () {
          window.location.href = href;
        }, 340);
      });
    });
  });
})();
