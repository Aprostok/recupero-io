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
  --crit-border: rgba(215,0,21,.22); --warn-border: rgba(185,119,14,.22); --ok-border: rgba(29,138,78,.22);
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
    --crit-border: rgba(255,69,58,.32); --warn-border: rgba(255,214,10,.28); --ok-border: rgba(48,209,88,.28);
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

/* ── Progress bars (inline rate visualisation) ── */
.pbar { display: inline-flex; width: 56px; height: 4px; background: var(--hair-strong); border-radius: 99px; vertical-align: middle; overflow: hidden; flex-shrink: 0; }
.pbar-fill { height: 100%; background: var(--accent); border-radius: 99px; transition: width .6s var(--ease); min-width: 0; }
.pbar-fill.ok   { background: var(--ok);   }
.pbar-fill.warn { background: var(--warn); }
.pbar-fill.crit { background: var(--crit); }

/* ── .mono copy affordance ── */
td.mono, div.mono { cursor: copy; }
td.mono:hover, div.mono:hover { opacity: .82; }

/* ── Verdict hero (address profile) ── */
.verdict-hero {
  display: flex; align-items: center; gap: 1.1rem;
  border-radius: var(--r); padding: 1.15rem 1.4rem;
  border: 1px solid var(--hair); box-shadow: var(--shadow-sm);
  animation: rc-rise .4s var(--ease) both;
}
.verdict-hero.v-sanctioned, .verdict-hero.v-high { background: var(--crit-soft); border-color: var(--crit-border); }
.verdict-hero.v-medium { background: var(--warn-soft); border-color: var(--warn-border); }
.verdict-hero.v-low, .verdict-hero.v-clean { background: var(--ok-soft); border-color: var(--ok-border); }
.vh-icon { font-size: 2.2rem; flex-shrink: 0; line-height: 1; }
.vh-body { flex: 1; min-width: 0; }
.vh-label { font-size: 1.3rem; font-weight: 800; letter-spacing: -0.025em; line-height: 1.1; }
.verdict-hero.v-sanctioned .vh-label, .verdict-hero.v-high .vh-label { color: var(--crit); }
.verdict-hero.v-medium .vh-label { color: var(--warn); }
.verdict-hero.v-low .vh-label, .verdict-hero.v-clean .vh-label { color: var(--ok); }
.vh-sub { font-size: .84rem; color: var(--ink-soft); margin-top: .25rem; }
.vh-bar { height: 5px; border-radius: 99px; background: var(--hair-strong); margin-top: .6rem; max-width: 220px; overflow: hidden; }
@keyframes bar-grow { from { width: 0 } to { width: var(--tw, 0%) } }
.vh-bar-fill { height: 100%; border-radius: 99px; animation: bar-grow .85s var(--ease) forwards; }
.verdict-hero.v-sanctioned .vh-bar-fill, .verdict-hero.v-high .vh-bar-fill { background: var(--crit); }
.verdict-hero.v-medium .vh-bar-fill { background: var(--warn); }
.verdict-hero.v-low .vh-bar-fill, .verdict-hero.v-clean .vh-bar-fill { background: var(--ok); }

/* ── Deliverable cards (case overview) ── */
.deliv-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: .75rem; margin: 1rem 0; }
.deliv-card {
  display: flex; flex-direction: column; gap: .5rem;
  background: var(--surface); border: 1px solid var(--hair); border-radius: var(--r);
  padding: 1rem 1.1rem; box-shadow: var(--shadow-sm);
  transition: transform .22s var(--ease), box-shadow .22s var(--ease), border-color .22s;
  animation: rc-rise .4s var(--ease) both;
}
.deliv-card.present { border-color: var(--ok-border); }
.deliv-card.absent  { opacity: .62; }
.deliv-card-head { display: flex; align-items: center; gap: .55rem; }
.deliv-card-icon { font-size: 1.35rem; }
.deliv-card-name { font-weight: 700; font-size: .95rem; letter-spacing: -0.01em; }
.deliv-card-status { margin-left: auto; font-size: .72rem; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; }
.deliv-card.present .deliv-card-status { color: var(--ok); }
.deliv-card.absent  .deliv-card-status { color: var(--ink-faint); }
.deliv-links { display: flex; flex-wrap: wrap; gap: .4rem; margin-top: .25rem; }
.deliv-links a { font-size: .78rem; color: var(--accent); border: 1px solid var(--accent-soft); border-radius: var(--r-sm); padding: .22rem .55rem; transition: background .15s; }
.deliv-links a:hover { background: var(--accent-soft); text-decoration: none; }
.deliv-card:hover { transform: translateY(-1px); box-shadow: var(--shadow-md); border-color: transparent; }
.deliv-card.present:hover { border-color: var(--ok-border); }

/* ── Risk band pills (screening) ── */
.rband { display: inline-block; padding: .12rem .48rem; border-radius: 999px; font-size: .67rem; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; }
.rband.critical, .rband.sanctioned { background: var(--crit-soft); color: var(--crit); }
.rband.high { background: var(--warn-soft); color: var(--warn); }
.rband.medium { background: var(--warn-soft); color: var(--warn); }
.rband.low, .rband.clean { background: var(--ok-soft); color: var(--ok); }
.score-crit { color: var(--crit); font-weight: 700; }
.score-high { color: var(--warn); font-weight: 600; }
.score-ok   { color: var(--ok);   }

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

/* ── Generic chips ── */
.chip {
  display: inline-flex; align-items: center; gap: .28rem;
  background: var(--surface); border: 1px solid var(--hair);
  border-radius: 999px; padding: .18rem .62rem;
  font-size: .75rem; font-weight: 600; color: var(--ink-soft); white-space: nowrap;
  transition: background .15s var(--ease), border-color .15s var(--ease);
}
.chip.crit { background: var(--crit-soft); border-color: var(--crit-border); color: var(--crit); }
.chip.warn { background: var(--warn-soft); border-color: var(--warn-border); color: var(--warn); }
.chip.ok   { background: var(--ok-soft);   border-color: var(--ok-border);   color: var(--ok);   }
.chips-row { display: flex; flex-wrap: wrap; align-items: center; gap: .35rem; margin: .5rem 0 .9rem; }
.chips-row .chips-label { font-size: .67rem; font-weight: 700; text-transform: uppercase; letter-spacing: .06em; color: var(--ink-faint); white-space: nowrap; }

/* ── Urgency / action chips ── */
.act-chip { display: inline-block; padding: .18rem .6rem; border-radius: var(--r-sm); font-size: .72rem; font-weight: 700; letter-spacing: .02em; text-transform: uppercase; background: var(--surface-2); color: var(--ink-soft); white-space: nowrap; }
.act-chip.immediate { background: var(--crit-soft); color: var(--crit); }
.act-chip.same-day  { background: var(--warn-soft); color: var(--warn); }
.act-chip.routine   { background: var(--ok-soft);   color: var(--ok);   }

/* ── Delta / direction values ── */
.delta-pos { color: var(--ok);   font-weight: 700; }
.delta-neg { color: var(--crit); font-weight: 700; }

/* ── Recovery rate bar (law-firm table) ── */
.rec-bar { display: inline-flex; width: 56px; height: 5px; border-radius: 99px; background: var(--hair-strong); overflow: hidden; flex-shrink: 0; vertical-align: middle; }
.rec-bar-fill { height: 100%; background: var(--ok); border-radius: 99px; transition: width .7s var(--ease); }
.rec-bar-fill.warn { background: var(--warn); }
.rec-bar-fill.crit { background: var(--crit); }

/* ── Step number bubble (incident plans) ── */
.step-bubble { display: inline-flex; align-items: center; justify-content: center; width: 20px; height: 20px; border-radius: 50%; background: var(--accent-soft); color: var(--accent); font-size: .68rem; font-weight: 800; flex-shrink: 0; vertical-align: middle; }

/* ── AI disclaimer banner ── */
.ai-disclaimer {
  display: flex; align-items: flex-start; gap: .9rem;
  background: var(--warn-soft); border: 1px solid var(--warn-border);
  border-radius: var(--r); padding: 1rem 1.2rem; margin-bottom: 1.2rem;
  animation: rc-rise .35s var(--ease) both;
}
.ai-disclaimer-icon { font-size: 1.5rem; flex-shrink: 0; line-height: 1.2; }
.ai-disclaimer-body { flex: 1; min-width: 0; }
.ai-disclaimer-title { font-weight: 800; color: var(--warn); font-size: .9rem; letter-spacing: -.01em; margin-bottom: .25rem; }
.ai-disclaimer-note { font-size: .77rem; color: var(--ink-soft); line-height: 1.5; }

/* ── Table sort + filter ── */
thead th { cursor: pointer; user-select: none; -webkit-user-select: none; }
thead th:hover { color: var(--ink-soft); }
.rc-sa { font-size: .62rem; opacity: .38; margin-left: .25rem; transition: opacity .12s; vertical-align: middle; display: inline-block; pointer-events: none; }
.rc-sa::after { content: "\21C5"; }
thead th:hover .rc-sa { opacity: .72; }
thead th[data-rc-asc]  .rc-sa { opacity: 1; color: var(--accent); }
thead th[data-rc-desc] .rc-sa { opacity: 1; color: var(--accent); }
thead th[data-rc-asc]  .rc-sa::after { content: "\25B2"; }
thead th[data-rc-desc] .rc-sa::after { content: "\25BC"; }
.rc-filter-bar {
  display: flex; align-items: center; gap: .55rem;
  padding: .42rem .78rem; background: var(--surface-2);
  border: 1px solid var(--hair); border-bottom: 0;
  border-radius: var(--r) var(--r) 0 0;
}
.rc-filter-icon { font-size: 1rem; color: var(--ink-faint); flex-shrink: 0; line-height: 1; }
.rc-filter-input {
  flex: 1; border: 0; background: transparent; outline: none;
  font-size: .82rem; color: var(--ink); font-family: var(--font); padding: .1rem 0;
}
.rc-filter-input::placeholder { color: var(--ink-faint); }
.rc-filter-count { font-size: .72rem; color: var(--ink-faint); white-space: nowrap; padding-right: .2rem; }
.rc-export-btn {
  flex-shrink: 0; padding: .22rem .6rem; border: 1px solid var(--hair-strong); border-radius: var(--r-sm);
  background: transparent; color: var(--ink-soft); font-size: .72rem; font-weight: 590; cursor: pointer;
  font-family: var(--font); line-height: 1.4;
  transition: background .15s var(--ease), color .15s var(--ease), border-color .15s var(--ease);
}
.rc-export-btn:hover { background: var(--accent-soft); color: var(--accent); border-color: var(--accent); box-shadow: none; transform: none; }

/* ── Score ring (conic-gradient gauge) ── */
.score-ring {
  --score: 0;
  display: inline-flex; align-items: center; justify-content: center;
  width: 44px; height: 44px; border-radius: 50%; flex-shrink: 0; position: relative;
  background: conic-gradient(var(--ring-color, var(--accent)) calc(var(--score) * 36deg), var(--hair-strong) 0deg);
  animation: rc-rise .55s var(--ease) both;
}
.score-ring.sm { width: 28px; height: 28px; }
.score-ring .ring-inner {
  position: absolute; top: 5px; right: 5px; bottom: 5px; left: 5px;
  border-radius: 50%; background: var(--surface);
  display: flex; align-items: center; justify-content: center;
  font-size: .7rem; font-weight: 800; line-height: 1; color: var(--ink);
}
.score-ring.sm .ring-inner { top: 4px; right: 4px; bottom: 4px; left: 4px; font-size: .56rem; }
.score-ring.r-crit { --ring-color: var(--crit); }
.score-ring.r-high { --ring-color: var(--warn); }
.score-ring.r-ok   { --ring-color: var(--ok);   }

/* ── Accessibility ── */
@media (prefers-reduced-motion: reduce) { * { transition: none !important; animation: none !important; } }
"""

CONSOLE_JS = r"""
/* Recupero console micro-interactions (app.js v2) */
(function () {
  "use strict";

  // ── Animated number counter ─────────────────────────────────────────────
  function countUp(el) {
    if (!el || el.hasAttribute("data-counting")) return;
    var raw = el.getAttribute("data-target") || el.textContent.trim();
    el.setAttribute("data-target", raw);
    var stripped = raw.replace(/[^\d.]/g, "");
    var num = parseFloat(stripped);
    if (isNaN(num) || num < 2 || stripped.length < raw.length * 0.35) return;
    el.setAttribute("data-counting", "1");
    var dur = Math.max(350, Math.min(900, 180 + Math.sqrt(num) * 38));
    var t0 = performance.now();
    (function tick(now) {
      var p = Math.min(1, (now - t0) / dur);
      var e = 1 - Math.pow(1 - p, 3);
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

  // ── Sort helpers ─────────────────────────────────────────────────────────
  function _cellVal(td) {
    if (!td) return "";
    var v = (td.getAttribute("data-sort") || td.textContent || "").trim();
    var stripped = v.replace(/[$,%\s]/g, "");
    var n = parseFloat(stripped.replace(/[^0-9.-]/g, ""));
    return isNaN(n) ? v.toLowerCase() : n;
  }

  function _sortTable(table, col) {
    var ths = table.querySelectorAll("thead th");
    var th = ths[col];
    if (!th) return;
    var asc = th.hasAttribute("data-rc-asc");
    ths.forEach(function (h) {
      h.removeAttribute("data-rc-asc");
      h.removeAttribute("data-rc-desc");
    });
    if (asc) { th.setAttribute("data-rc-desc", ""); }
    else      { th.setAttribute("data-rc-asc",  ""); }
    var dir = asc ? -1 : 1;
    var tbody = table.querySelector("tbody");
    if (!tbody) return;
    var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr"));
    rows.sort(function (a, b) {
      var av = _cellVal(a.querySelectorAll("td")[col]);
      var bv = _cellVal(b.querySelectorAll("td")[col]);
      if (av < bv) return -dir;
      if (av > bv) return  dir;
      return 0;
    });
    rows.forEach(function (r) { tbody.appendChild(r); });
    rows.forEach(function (r, i) {
      r.style.animation = "none";
      var _ = r.offsetHeight;
      r.style.animation = "rc-rowIn .22s cubic-bezier(.32,.72,0,1) " + (i * 10) + "ms both";
    });
  }

  // Wire sort arrows onto every <thead th> in el (or document)
  function attachSort(el) {
    (el || document).querySelectorAll("table").forEach(function (table) {
      if (table.getAttribute("data-rc-sort")) return;
      table.setAttribute("data-rc-sort", "1");
      table.querySelectorAll("thead th").forEach(function (th, i) {
        if (!th.querySelector(".rc-sa")) {
          var sa = document.createElement("span");
          sa.className = "rc-sa";
          th.appendChild(sa);
        }
        th.addEventListener("click", function () { _sortTable(table, i); });
      });
    });
  }

  // ── Filter bar ───────────────────────────────────────────────────────────
  function attachFilter(el) {
    var root = el || document;
    root.querySelectorAll("table").forEach(function (table) {
      if (table.getAttribute("data-rc-filter")) return;
      var tbody = table.querySelector("tbody");
      if (!tbody) return;
      var allRows = Array.prototype.slice.call(tbody.querySelectorAll("tr"));
      if (allRows.length < 5) return;
      table.setAttribute("data-rc-filter", "1");

      var bar = document.createElement("div");
      bar.className = "rc-filter-bar";
      bar.innerHTML =
        '<span class="rc-filter-icon">&#9906;</span>' +
        '<input class="rc-filter-input" type="text" placeholder="Filter rows…" autocomplete="off" spellcheck="false">' +
        '<span class="rc-filter-count"></span>';
      if (table.parentNode) { table.parentNode.insertBefore(bar, table); }

      var inp = bar.querySelector(".rc-filter-input");
      var cnt = bar.querySelector(".rc-filter-count");
      cnt.textContent = allRows.length + " rows";

      // CSV export button (appended to the filter bar)
      var expBtn = document.createElement("button");
      expBtn.className = "rc-export-btn";
      expBtn.title = "Export visible rows as CSV";
      expBtn.textContent = "↓ CSV";
      expBtn.addEventListener("click", function () { exportTable(table); });
      bar.appendChild(expBtn);

      inp.addEventListener("input", function () {
        var q = inp.value.trim().toLowerCase();
        var vis = 0;
        allRows.forEach(function (row) {
          var match = !q || (row.textContent || "").toLowerCase().indexOf(q) >= 0;
          row.style.display = match ? "" : "none";
          if (match) { vis++; }
        });
        cnt.textContent = q ? (vis + " / " + allRows.length) : (allRows.length + " rows");
      });
    });
  }

  // ── CSV export ───────────────────────────────────────────────────────────
  function exportTable(table, filename) {
    var rows = [];
    var ths = table.querySelectorAll("thead th");
    if (ths.length) {
      rows.push(Array.prototype.map.call(ths, function (th) {
        return '"' + (th.textContent || "").replace(/"/g, '""').replace(/[\r\n]+/g, " ").trim() + '"';
      }).join(","));
    }
    table.querySelectorAll("tbody tr").forEach(function (row) {
      if (row.style.display === "none") return;
      rows.push(Array.prototype.map.call(row.querySelectorAll("td"), function (td) {
        return '"' + (td.getAttribute("data-export") || td.textContent || "")
               .replace(/"/g, '""').replace(/[\r\n]+/g, " ").trim() + '"';
      }).join(","));
    });
    var csv = rows.join("\r\n");
    var blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url; a.download = filename || "recupero-export.csv";
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { if (a.parentNode) { a.parentNode.removeChild(a); } URL.revokeObjectURL(url); }, 1200);
  }

  // ── Skeleton loading helpers ─────────────────────────────────────────────
  function skeletonCards(n) {
    var h = "";
    for (var i = 0; i < (n || 4); i++) {
      h += '<div class="card">' +
           '<div class="v skeleton" style="width:48px;height:1.7rem;border-radius:6px">&nbsp;</div>' +
           '<div class="l skeleton" style="width:72px;height:.65rem;border-radius:4px;margin-top:.6rem">&nbsp;</div>' +
           '</div>';
    }
    return h;
  }

  function skeletonTable(rows, cols) {
    rows = rows || 5; cols = cols || 4;
    var h = '<table style="pointer-events:none"><thead><tr>';
    for (var c = 0; c < cols; c++) {
      h += '<th><span class="skeleton" style="display:inline-block;width:' + (44 + c * 14) + 'px;height:.65rem;border-radius:4px">&nbsp;</span></th>';
    }
    h += '</tr></thead><tbody>';
    for (var r = 0; r < rows; r++) {
      h += '<tr>';
      for (var cc = 0; cc < cols; cc++) {
        h += '<td><span class="skeleton" style="display:inline-block;width:' + (52 + (cc + r) * 7 % 44) + 'px;height:.75rem;border-radius:4px">&nbsp;</span></td>';
      }
      h += '</tr>';
    }
    return h + '</tbody></table>';
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

  watch("cards", function (el) {
    el.querySelectorAll(".card .v").forEach(countUp);
  });
  watch("tablewrap", function (el) {
    staggerRows(el);
    attachSort(el);
    attachFilter(el);
  });
  watch("out", function (el) {
    el.querySelectorAll(".card .v").forEach(countUp);
    staggerRows(el);
    attachSort(el);
    attachFilter(el);
  });

  // ── "/" key: focus first visible filter bar ───────────────────────────────
  document.addEventListener("keydown", function (ev) {
    if (ev.key !== "/" || ev.metaKey || ev.ctrlKey || ev.altKey) return;
    var t = ev.target;
    if (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" ||
        t.isContentEditable) return;
    var inp = document.querySelector(".rc-filter-input");
    if (inp) { ev.preventDefault(); inp.focus(); inp.select(); }
  });

  // ── Clipboard copy: click any .mono to copy its text ─────────────────────
  (function () {
    if (!navigator.clipboard || !navigator.clipboard.writeText) return;
    document.addEventListener("click", function (ev) {
      var el = ev.target.closest(".mono");
      if (!el || el.tagName === "A" || ev.target.tagName === "A") return;
      var text = (el.getAttribute("data-copy") || el.textContent || "").trim();
      if (text.length < 6) return;
      navigator.clipboard.writeText(text).then(function () {
        var was = el.innerHTML;
        var wasColor = el.style.color;
        el.textContent = "✓ Copied";
        el.style.color = "var(--ok)";
        setTimeout(function () { el.innerHTML = was; el.style.color = wasColor; }, 950);
      }).catch(function () {});
    });
  })();

  // Public API
  window.RC = {
    countUp: countUp,
    staggerRows: staggerRows,
    attachSort: attachSort,
    attachFilter: attachFilter,
    exportTable: exportTable,
    skeletonCards: skeletonCards,
    skeletonTable: skeletonTable
  };
})();
"""
