"""Shared operator-console design system (v0.38 UI rev-2).

One source of truth for the Apple-grade look across every console. Served at
``GET /v1/console/app.css`` (styles) and ``GET /v1/console/app.js``
(micro-interactions). Linked from each console template.

Kept as Python strings (not .css/.js files) so they are always packaged with
the wheel (package_data ships *.html, not *.css/.js) and need no new build step.
"""

CONSOLE_CSS = """
/* ── Recupero console design system v2 (Apple-grade) ── */
:root {
  --bg: #f5f5f7; --bg2: #eef1f6; --surface: #ffffff; --surface-2: #fbfbfd; --surface-3: #f2f2f7;
  --ink: #1d1d1f; --ink-soft: #6e6e73; --ink-faint: #86868b;
  --hair: rgba(0,0,0,.09); --hair-strong: rgba(0,0,0,.13);
  --accent: #0071e3; --accent-press: #0058b0; --accent-soft: rgba(0,113,227,.10);
  --crit: #d70015; --crit-soft: rgba(215,0,21,.07);
  --warn: #b9770e; --warn-soft: rgba(185,119,14,.10);
  --ok: #1d8a4e; --ok-soft: rgba(29,138,78,.10);
  --r-sm: 9px; --r: 14px; --r-lg: 20px;
  --ease: cubic-bezier(.32,.72,0,1);
  --font: -apple-system, BlinkMacSystemFont, "SF Pro Display", "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  --shadow-sm: 0 1px 2px rgba(0,0,0,.04), 0 1px 3px rgba(0,0,0,.05);
  --shadow-md: 0 8px 28px rgba(0,0,0,.08), 0 2px 6px rgba(0,0,0,.05);
  --shadow-lg: 0 20px 48px rgba(0,0,0,.13), 0 6px 14px rgba(0,0,0,.07);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #000; --bg2: #0c0c0e; --surface: #1c1c1e; --surface-2: #161618; --surface-3: #232325;
    --ink: #f5f5f7; --ink-soft: #aeaeb2; --ink-faint: #8e8e93;
    --hair: rgba(255,255,255,.10); --hair-strong: rgba(255,255,255,.16);
    --accent: #0a84ff; --accent-press: #409cff; --accent-soft: rgba(10,132,255,.16);
    --crit: #ff453a; --crit-soft: rgba(255,69,58,.13);
    --warn: #ffd60a; --warn-soft: rgba(255,214,10,.14);
    --ok: #30d158; --ok-soft: rgba(48,209,88,.13);
    --shadow-sm: 0 1px 3px rgba(0,0,0,.5);
    --shadow-md: 0 10px 30px rgba(0,0,0,.55);
    --shadow-lg: 0 22px 56px rgba(0,0,0,.7);
  }
}
* { box-sizing: border-box; }
html { -webkit-font-smoothing: antialiased; text-rendering: optimizeLegibility; }
body {
  font-family: var(--font); margin: 0; padding: 0 clamp(1rem, 4vw, 2.2rem) 3.5rem;
  color: var(--ink); letter-spacing: -0.011em; min-height: 100vh;
  background:
    radial-gradient(1000px 520px at 88% -10%, var(--accent-soft), transparent 60%),
    linear-gradient(180deg, var(--bg2), var(--bg) 360px);
  background-attachment: fixed;
}

/* ── Scrollbars ── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--hair-strong); border-radius: 99px; }
::-webkit-scrollbar-thumb:hover { background: var(--ink-faint); }
* { scrollbar-width: thin; scrollbar-color: var(--hair-strong) transparent; }

/* ── Typography ── */
h1 { font-size: clamp(1.5rem, 3vw, 1.9rem); font-weight: 700; letter-spacing: -0.025em; margin: 1.6rem 0 .25rem; }
h2 { font-size: 1.15rem; font-weight: 640; letter-spacing: -0.02em; margin: 1.4rem 0 .5rem; }
.sub { color: var(--ink-soft); font-size: .85rem; line-height: 1.5; margin: 0 0 1.2rem; max-width: 76ch; }
a { color: var(--accent); text-decoration: none; } a:hover { text-decoration: underline; }

/* ── Control bar ── */
.bar { display: flex; flex-wrap: wrap; gap: .6rem; align-items: center; margin: 0 0 1.3rem; }
input[type=password], input[type=text], input[type=number], select, textarea {
  padding: .55rem .8rem; border: 1px solid var(--hair-strong); border-radius: var(--r-sm);
  font-size: .85rem; background: var(--surface); color: var(--ink); font-family: var(--font);
  transition: border-color .18s var(--ease), box-shadow .18s var(--ease);
}
textarea { resize: vertical; line-height: 1.5; }
input[type=password], input#key { font-family: var(--mono); }
input:focus, select:focus, textarea:focus {
  outline: none; border-color: var(--accent); box-shadow: 0 0 0 4px var(--accent-soft);
}
select {
  -webkit-appearance: none; appearance: none; cursor: pointer;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%236e6e73' stroke-width='1.5' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
  background-repeat: no-repeat; background-position: right .7rem center; padding-right: 2.2rem;
}

/* ── Button ── */
button {
  padding: .55rem 1.1rem; border: 0;
  background: var(--accent); color: #fff; border-radius: var(--r-sm);
  cursor: pointer; font-size: .84rem; font-weight: 580; letter-spacing: -0.01em;
  font-family: var(--font);
  transition: background .16s var(--ease), transform .12s var(--ease), box-shadow .16s var(--ease);
  box-shadow: var(--shadow-sm), inset 0 1px 0 rgba(255,255,255,.18);
}
button:hover { background: var(--accent-press); box-shadow: var(--shadow-md); }
button:active { transform: scale(.96); box-shadow: var(--shadow-sm); }
button.secondary {
  background: var(--surface); color: var(--accent);
  border: 1px solid var(--hair-strong); box-shadow: var(--shadow-sm);
}
button.secondary:hover { background: var(--surface-2); }
button.ghost { background: transparent; color: var(--accent); border: 0; box-shadow: none; padding: .4rem .7rem; }
button.ghost:hover { background: var(--accent-soft); box-shadow: none; }
button:disabled { opacity: .5; cursor: default; transform: none; box-shadow: none; }

/* ── Status text ── */
#msg { font-size: .8rem; color: var(--ink-soft); margin-left: .4rem; transition: color .2s; }
.err { color: var(--crit) !important; }
.ok  { color: var(--ok)  !important; }

/* ── Summary line ── */
.summary { font-size: .85rem; margin-bottom: 1.1rem; color: var(--ink-soft); }
.summary .crit { color: var(--crit); font-weight: 700; }
.summary .hi   { color: var(--warn); font-weight: 700; }

/* ── Cards ── */
.cards {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(168px, 1fr));
  gap: .8rem; margin: 1.2rem 0;
}
.card {
  position: relative; overflow: hidden;
  background: var(--surface); border: 1px solid var(--hair); border-radius: var(--r);
  padding: 1rem 1.15rem; box-shadow: var(--shadow-sm);
  transition: transform .25s var(--ease), box-shadow .25s var(--ease), border-color .25s var(--ease);
}
.card::before {
  content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 3px;
  background: var(--accent); border-radius: 0 2px 2px 0;
  transform: scaleY(0); transition: transform .25s var(--ease);
}
.card:hover { transform: translateY(-2px); box-shadow: var(--shadow-md); border-color: transparent; }
.card:hover::before { transform: scaleY(1); }
.card.alert::before { background: var(--crit); transform: scaleY(1); }
.card.ok::before    { background: var(--ok);   transform: scaleY(1); }
.card .v {
  font-size: 1.7rem; font-weight: 700; letter-spacing: -0.03em;
  font-variant-numeric: tabular-nums; line-height: 1;
}
.card .l {
  font-size: .68rem; text-transform: uppercase; letter-spacing: .06em;
  color: var(--ink-faint); margin-top: .5rem; font-weight: 600;
}

/* ── Panel ── */
.panel {
  background: var(--surface); border: 1px solid var(--hair);
  border-radius: var(--r); padding: 1rem 1.15rem; box-shadow: var(--shadow-sm);
}

/* ── Tables ── */
table {
  width: 100%; border-collapse: separate; border-spacing: 0;
  background: var(--surface); font-size: .82rem;
  border: 1px solid var(--hair); border-radius: var(--r);
  overflow: hidden; box-shadow: var(--shadow-sm);
}
th, td { text-align: left; padding: .6rem .75rem; border-bottom: 1px solid var(--hair); vertical-align: top; }
tbody tr:last-child td { border-bottom: 0; }
th {
  background: var(--surface-2); font-size: .66rem; text-transform: uppercase;
  letter-spacing: .05em; color: var(--ink-faint); font-weight: 700;
  position: sticky; top: 0; z-index: 1;
}
tbody tr { transition: background .12s var(--ease); }
tbody tr:hover td { background: var(--accent-soft); }
tr.sev-critical td { background: var(--crit-soft); }
tr.sev-high td     { background: var(--warn-soft); }
.right { text-align: right; }
.mono { font-family: var(--mono); font-size: .77rem; word-break: break-all; }
.action  { color: var(--ink-soft); font-size: .74rem; max-width: 24rem; }
.msgcell { max-width: 22rem; }

/* ── Badges / pills ── */
.badge {
  display: inline-flex; align-items: center; gap: .25rem;
  padding: .14rem .55rem; border-radius: 999px; font-size: .67rem;
  font-weight: 700; text-transform: uppercase; letter-spacing: .04em;
  background: var(--accent-soft); color: var(--accent);
}
.badge.critical { background: var(--crit-soft); color: var(--crit); }
.badge.high     { background: var(--warn-soft); color: var(--warn); }
.badge.ok       { background: var(--ok-soft);   color: var(--ok);   }

/* critical badge — attention pulse */
@keyframes rc-badge-pulse {
  0%   { box-shadow: 0 0 0 0 rgba(215,0,21,.5); }
  70%  { box-shadow: 0 0 0 5px transparent; }
  100% { box-shadow: 0 0 0 0 transparent; }
}
@media (prefers-color-scheme: dark) {
  @keyframes rc-badge-pulse {
    0%   { box-shadow: 0 0 0 0 rgba(255,69,58,.55); }
    70%  { box-shadow: 0 0 0 5px transparent; }
    100% { box-shadow: 0 0 0 0 transparent; }
  }
}
.badge.critical { animation: rc-badge-pulse 2.4s ease-out infinite; }

/* ── Empty state ── */
.empty {
  color: var(--ink-faint); font-size: .85rem;
  padding: 2.5rem 1rem; text-align: center;
}

/* ── Section rule ── */
.section-rule {
  display: flex; align-items: center; gap: .65rem;
  margin: 2rem 0 .8rem;
  font-size: .72rem; text-transform: uppercase; letter-spacing: .08em;
  color: var(--ink-faint); font-weight: 700;
}
.section-rule::after { content: ""; height: 1px; flex: 1; background: var(--hair); }

/* ── Sticky glassmorphism topbar (opt-in) ── */
.bar-top {
  position: sticky; top: 0; z-index: 20;
  display: flex; align-items: center; gap: .85rem; flex-wrap: wrap;
  padding: .75rem clamp(1rem, 4vw, 2.5rem);
  background: rgba(245,245,247,.84);
  backdrop-filter: saturate(180%) blur(24px);
  -webkit-backdrop-filter: saturate(180%) blur(24px);
  border-bottom: 1px solid var(--hair);
}
@media (prefers-color-scheme: dark) {
  .bar-top { background: rgba(28,28,30,.84); }
}

/* ── Loading spinner ── */
@keyframes rc-spin { to { transform: rotate(360deg); } }
.spinner {
  display: inline-block; width: 14px; height: 14px;
  border: 2px solid var(--hair-strong); border-top-color: var(--accent);
  border-radius: 50%; animation: rc-spin .65s linear infinite; vertical-align: middle;
  margin-right: .35rem;
}

/* ── Skeleton shimmer ── */
@keyframes rc-shimmer {
  0%   { background-position: -300% 0; }
  100% { background-position:  300% 0; }
}
.skeleton {
  background: linear-gradient(90deg, var(--surface-2) 25%, var(--bg2) 50%, var(--surface-2) 75%);
  background-size: 300% 100%; animation: rc-shimmer 1.5s ease-in-out infinite;
  border-radius: 4px; color: transparent !important; pointer-events: none; user-select: none;
}

/* ── Entry animations ── */
@keyframes rc-rise  { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
@keyframes rc-rowIn { from { opacity: 0; transform: translateY(3px); } to { opacity: 1; transform: none; } }
.cards .card { animation: rc-rise .45s var(--ease) both; }

/* ── Live pulse dot ── */
@keyframes rc-live-pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50%       { opacity: .6; transform: scale(.85); }
}
.live-dot {
  display: inline-block; width: 8px; height: 8px;
  background: var(--ok); border-radius: 50%;
  animation: rc-live-pulse 2.2s ease-in-out infinite;
  vertical-align: middle; margin-right: .3rem;
}

/* ── Accessibility ── */
@media (prefers-reduced-motion: reduce) { * { transition: none !important; animation: none !important; } }
"""

CONSOLE_JS = r"""
/* Recupero console micro-interactions (app.js v1) */
(function () {
  "use strict";

  // ── Animated number counter ─────────────────────────────────────────────
  function countUp(el) {
    if (!el || el.hasAttribute("data-counting")) return;
    var raw = el.getAttribute("data-target") || el.textContent.trim();
    el.setAttribute("data-target", raw);
    // Only count if the value is mostly numeric (skip "—", "$1.2M", complex strings)
    var stripped = raw.replace(/[^\d.]/g, "");
    var num = parseFloat(stripped);
    if (isNaN(num) || num < 2 || stripped.length < raw.length * 0.35) return;
    el.setAttribute("data-counting", "1");
    var dur = Math.max(350, Math.min(900, 180 + Math.sqrt(num) * 38));
    var t0 = performance.now();
    (function tick(now) {
      var p = Math.min(1, (now - t0) / dur);
      var e = 1 - Math.pow(1 - p, 3); // cubic ease-out
      el.textContent = Math.round(num * e).toLocaleString();
      if (p < 1) { requestAnimationFrame(tick); }
      else { el.textContent = raw; el.removeAttribute("data-counting"); }
    })(t0);
  }

  // ── Stagger table rows in on load ───────────────────────────────────────
  function staggerRows(root) {
    (root || document).querySelectorAll("tbody tr").forEach(function (row, i) {
      row.style.animation =
        "rc-rowIn .3s cubic-bezier(.32,.72,0,1) " + (i * 16 + 25) + "ms both";
    });
  }

  // ── Watch a DOM node for dynamic content injection ──────────────────────
  function watch(id, fn) {
    var el = document.getElementById(id);
    if (!el) return;
    var timer = 0;
    new MutationObserver(function () {
      clearTimeout(timer);
      timer = setTimeout(function () { fn(el); }, 0);
    }).observe(el, { childList: true });
  }

  watch("cards",     function (el) { el.querySelectorAll(".card .v").forEach(countUp); });
  watch("tablewrap", staggerRows);
  watch("out",       function (el) {
    el.querySelectorAll(".card .v").forEach(countUp);
    staggerRows(el);
  });

  // Public API for consoles that need manual triggers (e.g. after tab switch)
  window.RC = { countUp: countUp, staggerRows: staggerRows };
})();
"""
