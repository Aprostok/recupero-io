"""Shared operator-console design system (v0.38 UI).

One source of truth for the Apple-grade look across every console. Served at
``GET /v1/console/app.css`` and linked from each console template (replacing
per-page inline styles). Styles the COMMON vocabulary the consoles already use
— body / headings / .sub / .bar / inputs / select / button / table / .badge /
.mono / #msg / .summary / .card — so a console adopts the full theme just by
linking this and dropping its inline <style>.

Kept as a Python string (not a .css file) so it is always packaged with the
wheel (package_data ships *.html, not *.css) and needs no new build step.
"""

CONSOLE_CSS = """
/* ── Recupero console design system (Apple-grade) ── */
:root {
  --bg: #f5f5f7; --bg2: #eef1f6; --surface: #ffffff; --surface-2: #fbfbfd;
  --ink: #1d1d1f; --ink-soft: #6e6e73; --ink-faint: #86868b;
  --hair: rgba(0,0,0,.09); --hair-strong: rgba(0,0,0,.13);
  --accent: #0071e3; --accent-press: #0058b0; --accent-soft: rgba(0,113,227,.10);
  --crit: #d70015; --crit-soft: rgba(215,0,21,.07);
  --warn: #b9770e; --warn-soft: rgba(185,119,14,.10); --ok: #1d8a4e;
  --r-sm: 9px; --r: 14px;
  --ease: cubic-bezier(.32,.72,0,1);
  --font: -apple-system, BlinkMacSystemFont, "SF Pro Display", "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  --shadow-sm: 0 1px 2px rgba(0,0,0,.04), 0 1px 3px rgba(0,0,0,.05);
  --shadow-md: 0 8px 28px rgba(0,0,0,.08), 0 2px 6px rgba(0,0,0,.05);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #000; --bg2: #0c0c0e; --surface: #1c1c1e; --surface-2: #161618;
    --ink: #f5f5f7; --ink-soft: #aeaeb2; --ink-faint: #8e8e93;
    --hair: rgba(255,255,255,.10); --hair-strong: rgba(255,255,255,.16);
    --accent: #0a84ff; --accent-press: #409cff; --accent-soft: rgba(10,132,255,.16);
    --crit: #ff453a; --crit-soft: rgba(255,69,58,.13);
    --warn: #ffd60a; --warn-soft: rgba(255,214,10,.14); --ok: #30d158;
    --shadow-sm: 0 1px 3px rgba(0,0,0,.5);
    --shadow-md: 0 10px 30px rgba(0,0,0,.55);
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
h1 { font-size: clamp(1.5rem, 3vw, 1.9rem); font-weight: 700; letter-spacing: -0.025em; margin: 1.6rem 0 .25rem; }
h2 { font-size: 1.15rem; font-weight: 640; letter-spacing: -0.02em; margin: 1.4rem 0 .5rem; }
.sub { color: var(--ink-soft); font-size: .85rem; line-height: 1.5; margin: 0 0 1.2rem; max-width: 76ch; }
a { color: var(--accent); text-decoration: none; } a:hover { text-decoration: underline; }

/* control bar */
.bar { display: flex; flex-wrap: wrap; gap: .6rem; align-items: center; margin: 0 0 1.3rem; }
input[type=password], input[type=text], input[type=number], select {
  padding: .55rem .8rem; border: 1px solid var(--hair-strong); border-radius: var(--r-sm);
  font-size: .85rem; background: var(--surface); color: var(--ink);
  transition: border-color .18s var(--ease), box-shadow .18s var(--ease);
}
input[type=password], input#key, input[type=text].mono { font-family: var(--mono); }
input:focus, select:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 4px var(--accent-soft); }
button {
  padding: .55rem 1.05rem; border: 0; background: var(--accent); color: #fff; border-radius: var(--r-sm);
  cursor: pointer; font-size: .84rem; font-weight: 580; letter-spacing: -0.01em;
  transition: background .16s, transform .12s var(--ease), box-shadow .16s; box-shadow: var(--shadow-sm);
}
button:hover { background: var(--accent-press); }
button:active { transform: scale(.96); }
button.secondary { background: var(--surface); color: var(--accent); border: 1px solid var(--hair-strong); }
button.secondary:hover { background: var(--surface-2); }
button:disabled { opacity: .5; cursor: default; transform: none; }

/* status text */
#msg { font-size: .8rem; color: var(--ink-soft); margin-left: .4rem; }
.err { color: var(--crit); } .ok { color: var(--ok); }

/* summary line */
.summary { font-size: .85rem; margin-bottom: 1.1rem; color: var(--ink-soft); }
.summary .crit { color: var(--crit); font-weight: 700; }
.summary .hi { color: var(--warn); font-weight: 700; }

/* cards */
.card, .panel {
  background: var(--surface); border: 1px solid var(--hair); border-radius: var(--r);
  padding: 1rem 1.15rem; box-shadow: var(--shadow-sm);
}
.cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(168px, 1fr)); gap: .8rem; margin: 1.2rem 0; }
.card .v { font-size: 1.7rem; font-weight: 700; letter-spacing: -0.03em; font-variant-numeric: tabular-nums; }
.card .l { font-size: .68rem; text-transform: uppercase; letter-spacing: .06em; color: var(--ink-faint); margin-top: .45rem; font-weight: 600; }

/* tables */
table {
  width: 100%; border-collapse: separate; border-spacing: 0; background: var(--surface);
  font-size: .82rem; border: 1px solid var(--hair); border-radius: var(--r); overflow: hidden; box-shadow: var(--shadow-sm);
}
th, td { text-align: left; padding: .6rem .75rem; border-bottom: 1px solid var(--hair); vertical-align: top; }
tbody tr:last-child td { border-bottom: 0; }
th { background: var(--surface-2); font-size: .66rem; text-transform: uppercase; letter-spacing: .05em; color: var(--ink-faint); font-weight: 700; }
tbody tr { transition: background .12s; }
tbody tr:hover td { background: var(--accent-soft); }
tr.sev-critical td { background: var(--crit-soft); }
tr.sev-high td { background: var(--warn-soft); }
.right { text-align: right; }
.mono { font-family: var(--mono); font-size: .77rem; word-break: break-all; }
.action { color: var(--ink-soft); font-size: .74rem; max-width: 24rem; }
.msgcell { max-width: 22rem; }

/* badges / pills */
.badge {
  display: inline-block; padding: .12rem .5rem; border-radius: 999px; font-size: .68rem;
  font-weight: 700; text-transform: uppercase; letter-spacing: .03em;
  background: var(--accent-soft); color: var(--accent);
}
.badge.critical { background: var(--crit-soft); color: var(--crit); }
.badge.high { background: var(--warn-soft); color: var(--warn); }

.empty { color: var(--ink-faint); font-size: .85rem; padding: 1rem 0; }
@media (prefers-reduced-motion: reduce) { * { transition: none !important; animation: none !important; } }
"""
