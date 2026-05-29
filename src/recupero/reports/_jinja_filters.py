"""Shared Jinja filters for defense-in-depth XSS hardening.

Recupero renders HTML deliverables (briefs, legal-request letters,
victim summaries, freeze digests, portfolio dashboards) that downstream
get opened in operator browsers or attached to emails. Jinja autoescape
defends against `{{ value }}` interpolation, but it does NOT defend
against two attribute-context attacks that come up across our templates:

  1. ``href="{{ url }}"`` where ``url`` could be ``javascript:alert(1)``
     or ``data:text/html,...`` — autoescape escapes the quote character
     but a `javascript:` URL doesn't need a quote to fire.
  2. CRLF injection into an attribute that the browser later treats as
     a header (rare in static HTML, but a hardening-affordance for our
     monitoring-dispatcher emails which run the same templates).

We solve both with one small filter, ``safe_url``, registered on every
Jinja Environment that renders an `href`/`src`-bearing template.

Threat model in scope:
  * On-chain labels (Etherscan tag set is attacker-controllable for new
    addresses).
  * Issuer freeze-outcome responses (compliance teams might paste
    arbitrary text into the followup field).
  * Address-display names from Investigator handoff JSON.
  * The interactive-graph JSON blob (already separately defended in
    graph_ui.py at the data layer).

Threat model NOT in scope:
  * Backend-generated explorer URLs from
    `recupero._common.ADDRESS_EXPLORER_BY_CHAIN` — these come from a
    fixed allowlist. ``safe_url`` is defense-in-depth against a future
    bug that lets attacker-controlled bytes reach the URL field.
"""
from __future__ import annotations

import re
from typing import Any

# ----- safe_url filter ----- #

_ALLOWED_SCHEME_RE = re.compile(
    r"\A\s*(?:https?|mailto|tel)\s*:", flags=re.IGNORECASE
)
# Site-relative (`/portal/...`), in-page (`#anchor`), and protocol-
# relative-with-domain (`//etherscan.io/...`) are also safe in our
# templates; we explicitly allow only the first two — protocol-
# relative is intentionally rejected because it inherits the page's
# scheme but is rarely useful in our deliverables and is a known
# phishing-attack shape.
_SAFE_PREFIXES = ("/", "#")


def safe_url(value: Any) -> str:
    """Return ``value`` only if it parses to an allowlisted scheme.

    Allowlisted schemes (case-insensitive): ``http``, ``https``,
    ``mailto``, ``tel``. Plus site-relative paths starting with ``/``
    and in-page anchors starting with ``#``.

    Anything else — ``javascript:``, ``data:``, ``vbscript:``, ``file:``,
    ``ftp:``, an empty string with a NUL byte prefix, or whitespace-
    obfuscated variants — collapses to ``"#"`` so the rendered HTML
    contains a benign placeholder link rather than an executable URL.

    CR / LF / NUL bytes are stripped unconditionally to defeat
    header-injection variants when the same templates render into
    SMTP message bodies.

    Empty / None input → ``""`` (so ``{% if url %}`` template guards
    continue to work).
    """
    if value is None:
        return ""
    s = str(value)
    if not s:
        return ""

    # Strip control characters that could split an attribute/header.
    # Done BEFORE scheme check so `\x00javascript:alert(1)` is caught.
    s = s.replace("\r", "").replace("\n", "").replace("\x00", "").replace("\t", "")

    # In-page or site-relative — safe by inspection.
    if s.startswith(_SAFE_PREFIXES):
        return s

    # Scheme-bearing — must match the allowlist.
    if _ALLOWED_SCHEME_RE.match(s):
        # Strip leading whitespace that the regex allowed through,
        # to keep the rendered href tidy.
        return s.lstrip()

    # No allowed scheme and no safe prefix — neuter.
    return "#"


# ----- safe_text filter ----- #


def safe_text(value: Any) -> str:
    """Coerce ``value`` to a string, stripping bidi-override and
    other invisible control characters that could spoof identifier
    display order in a brief.

    The Unicode bidi-override characters (U+202E RIGHT-TO-LEFT
    OVERRIDE, U+202D LEFT-TO-RIGHT OVERRIDE, etc.) can flip a
    rendered identifier — e.g., ``"alice‮gnp.exe"`` displays
    as ``"aliceexe.png"``. Address-label fields and identifier
    display names should NOT carry these characters.

    Applied selectively in templates via ``{{ label | safe_text }}``;
    not auto-applied to every interpolation because some legitimate
    case-note fields (translated victim statements) may contain
    legitimate RTL text that we shouldn't strip.
    """
    if value is None:
        return ""
    s = str(value)
    # Strip the bidi-override family + zero-width chars + NULs.
    return _BIDI_RE.sub("", s)


_BIDI_RE = re.compile(
    "["
    "‪-‮"   # bidi embedding / override
    "⁦-⁩"   # bidi isolate
    "​-‏"   # zero-width + LTR/RTL marks
    "­"          # soft hyphen
    "\x00"
    "]"
)


# ----- registration helper ----- #


def register_safe_filters(env) -> None:
    """Register the defense-in-depth filters on a Jinja Environment.

    Call this immediately after constructing every ``Environment``
    that renders templates containing `href`/`src` attributes.

    Also registers ``short_address`` — v0.32.1 cross-cutting polish
    (Jacob audit §3.1): templates can now use ``{{ addr | short_address }}``
    instead of the ad-hoc ``{{ addr[:10] }}…{{ addr[-6:] }}`` slicing,
    so the same address renders identically across every artifact.

    Idempotent — re-registration is a no-op.
    """
    from recupero.util.addr_format import short_address

    env.filters.setdefault("safe_url", safe_url)
    env.filters.setdefault("safe_text", safe_text)
    env.filters.setdefault("short_address", short_address)


__all__ = ["safe_url", "safe_text", "register_safe_filters"]
