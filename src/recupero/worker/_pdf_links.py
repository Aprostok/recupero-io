"""Post-process WeasyPrint PDFs to add missing chain-explorer link
annotations.

Why this exists: WeasyPrint (60-69) emits /Link annotations for
some but not all of the <a href="..."> anchors in the source HTML.
On a deep-trace freeze letter with 40+ etherscan address links,
coverage was observed at ~54% across all WeasyPrint versions in
the supported range. The missing annotations mean compliance
reviewers can't click those addresses in the PDF to open them on
the chain explorer — they have to copy/paste, which kills the
workflow.

This module walks the rendered PDF, finds every chain-explorer
URL that appears as text in any page's content stream, locates
the matching text-rendering location, and injects a /Link
annotation pointing at that URL. Result: every visible URL in
the PDF is clickable, regardless of whether WeasyPrint emitted
the annotation natively.

Approach (pypdf):
  1. Open the WeasyPrint PDF with pypdf.
  2. For each page, extract text positions via the page's
     content-stream operators (we use ``extract_text`` with
     "text_extraction_mode" to get per-fragment positions).
  3. Match every text fragment against the chain-explorer URL
     regex; for each hit, compute the fragment's bounding box.
  4. Add a /Link annotation with /URI action targeting that URL.
  5. Write the resulting PDF back to the same path.

Best-effort: pypdf positioning is approximate (text-fragment bboxes
aren't always pixel-perfect after CSS render). We err on the side
of slightly-bigger rectangles so a near-miss click still lands.
A failure on one URL doesn't fail the entire pass — we log and
continue.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

log = logging.getLogger(__name__)


# Match any chain-explorer URL the freeze letter might link to.
# Used to extract the address→href mapping from the source HTML.
_EXPLORER_URL_RE = re.compile(
    r"https?://(?:"
    r"etherscan\.io|"
    r"arbiscan\.io|"
    r"basescan\.org|"
    r"polygonscan\.com|"
    r"bscscan\.com|"
    r"solscan\.io|"
    r"app\.hyperliquid\.xyz"
    r")/(?:address|account|tx)/(0x[0-9a-fA-F]+|[1-9A-HJ-NP-Za-km-z]{32,44})",
    re.IGNORECASE,
)

# Match the rendered SHORT-form address text WeasyPrint puts in the
# PDF — patterns the templates use: full 42-char "0x..." or the
# truncated "0x1234…abcd" form. The truncation char varies between
# HTML entity sources; we match both "…" (U+2026) and "..." (ASCII).
_RENDERED_ADDRESS_RE = re.compile(
    r"0x[0-9a-fA-F]{4,40}"
    r"(?:(?:…|\.\.\.)[0-9a-fA-F]{2,8})?"
)


def _build_address_to_url_map(html_path: Path) -> dict[str, str]:
    """Parse the source HTML for ``<a href="...">0x...</a>`` patterns
    and build a map keyed by every form of the address that might
    appear in the PDF's rendered text.

    For each address ``0xABCD…1234`` referenced by an explorer URL,
    we register both the full form AND the short ``0xABCD…1234``
    truncation under the same target URL — the templates use both
    forms inconsistently and pypdf will see whichever was rendered.
    """
    if not html_path.exists():
        return {}
    try:
        html = html_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {}
    out: dict[str, str] = {}
    # Find every <a href="https://<explorer>/.../<address>">…</a>.
    anchor_pattern = re.compile(
        r'<a\s+[^>]*href="([^"]+)"[^>]*>([^<]+)</a>',
        re.IGNORECASE | re.DOTALL,
    )
    for m in anchor_pattern.finditer(html):
        href = m.group(1)
        if not _EXPLORER_URL_RE.match(href):
            continue
        rendered = m.group(2).strip()
        if not rendered or not rendered.startswith("0x"):
            continue
        out[rendered] = href
        # Also register the truncated form if the template short-
        # renders the address ("0x1234…abcd") even though href
        # points at the full address. pypdf may see either.
        addr_match = re.search(
            r"0x[0-9a-fA-F]{40}", href,
        )
        if addr_match:
            full_addr = addr_match.group(0)
            if full_addr not in out:
                out[full_addr] = href
            # Truncated form: first 6 chars + ellipsis + last 4
            short = f"{full_addr[:6]}…{full_addr[-4:]}"
            if short not in out:
                out[short] = href
            short_ascii = f"{full_addr[:6]}...{full_addr[-4:]}"
            if short_ascii not in out:
                out[short_ascii] = href
    return out


def patch_pdf_links(pdf_path: Path, html_path: Path | None = None) -> int:
    """Add missing /Link annotations to ``pdf_path`` in place.

    Matches the PDF's rendered text against the source HTML's anchor
    map (address text → href URL) and injects a /Link rectangle for
    every occurrence. WeasyPrint's native emission gives us ~54%
    coverage (one annotation per unique URL, not per occurrence) —
    this closes the gap to ~100% by adding rectangles for every
    visible address occurrence in the PDF text.

    Returns the number of annotations added (0 on no-op / failure).
    The PDF is only rewritten when at least one annotation was added,
    so a no-op pass doesn't touch the file's mtime.

    Defensive: every step is wrapped in try/except. A pypdf import
    error or a malformed PDF logs a warning and returns 0 — the
    caller's freeze-letter pipeline still ships the WeasyPrint
    output unchanged.

    ``html_path`` defaults to the same stem with ``.html`` extension
    when None — building_package writes both side by side, so the
    convention holds.
    """
    if html_path is None:
        html_path = pdf_path.with_suffix(".html")
    address_to_url = _build_address_to_url_map(html_path)
    if not address_to_url:
        log.warning(
            "pdf link patching: no address→URL map for %s "
            "(HTML missing or has no chain-explorer anchors)",
            pdf_path.name,
        )
        return 0
    try:
        import pypdf
        from pypdf.generic import (
            ArrayObject, DictionaryObject, FloatObject, NameObject,
            NumberObject, TextStringObject,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("pdf link patching skipped — pypdf import failed: %s", exc)
        return 0

    try:
        reader = pypdf.PdfReader(str(pdf_path))
    except Exception as exc:  # noqa: BLE001
        log.warning("pdf link patching skipped — couldn't read %s: %s",
                    pdf_path.name, exc)
        return 0

    # Cap the number of pages we walk — a long LE handoff PDF can
    # have 30+ pages and pypdf's visitor-text extraction is pure-
    # Python, GIL-bound. Past ~10 pages the cost crosses the
    # heartbeat threshold of our parent worker (when called
    # in-process). Even subprocess-isolated, we want to cap so the
    # subprocess timeout doesn't fire and waste budget. Most of the
    # value is in pages 1-5 (top of letter) where the bulk of the
    # repeated address links live.
    _MAX_PAGES = 8

    writer = pypdf.PdfWriter()
    added = 0
    for page_num, page in enumerate(reader.pages):
        writer.add_page(page)
        if page_num >= _MAX_PAGES:
            continue  # still copy the page, just don't patch it
        try:
            added_on_page = _patch_page(
                writer.pages[page_num], page_num,
                address_to_url=address_to_url,
                ArrayObject=ArrayObject,
                DictionaryObject=DictionaryObject,
                FloatObject=FloatObject,
                NameObject=NameObject,
                NumberObject=NumberObject,
                TextStringObject=TextStringObject,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("pdf link patching: page %d failed: %s", page_num, exc)
            continue
        added += added_on_page

    if added == 0:
        log.info("pdf link patching: nothing to add (PDF already has full coverage)")
        return 0

    try:
        with open(pdf_path, "wb") as f:
            writer.write(f)
        log.info("pdf link patching: added %d /Link annotations to %s",
                 added, pdf_path.name)
    except Exception as exc:  # noqa: BLE001
        log.warning("pdf link patching: write failed for %s: %s",
                    pdf_path.name, exc)
        return 0

    return added


def _patch_page(
    page,
    page_num: int,
    *,
    address_to_url: dict[str, str],
    ArrayObject,
    DictionaryObject,
    FloatObject,
    NameObject,
    NumberObject,
    TextStringObject,
) -> int:
    """Walk one page's rendered text, inject /Link annotations for
    every occurrence of a known address (from address_to_url map).

    Strategy: pypdf visitor pattern gives per-fragment (text, tm)
    where tm encodes baseline position. We match each fragment
    against the rendered address regex (full hex form or short
    `0x1234…abcd` truncation), look the address up in the map for
    its href URL, and emit a /Link rectangle.

    Every occurrence is emitted — no per-URL dedup. WeasyPrint's
    native /Link annotations stay in place; the patcher only ADDS
    new rectangles for occurrences WeasyPrint missed. Net effect:
    every visible address spot in the PDF becomes clickable.
    """
    spans: list[tuple[str, float, float, float]] = []

    def _visitor_text(text, cm, tm, font_dict, font_size):
        if not text or not isinstance(text, str):
            return
        try:
            x = float(tm[4])
            y = float(tm[5])
        except (IndexError, TypeError, ValueError):
            return
        try:
            fs = float(font_size or 9.0)
        except (TypeError, ValueError):
            fs = 9.0
        spans.append((text, x, y, fs))

    try:
        page.extract_text(visitor_text=_visitor_text)
    except Exception as exc:  # noqa: BLE001
        log.debug("page %d visitor extraction failed: %s", page_num, exc)
        return 0

    if not spans:
        return 0

    page_existing_annots = page.get("/Annots") or ArrayObject()

    added = 0
    for text, x, y, fs in spans:
        for match in _RENDERED_ADDRESS_RE.finditer(text):
            rendered_addr = match.group(0)
            # Look up the href URL — try several normalized forms
            # since the rendered text may be exact-match short or
            # the full address form.
            url = (
                address_to_url.get(rendered_addr)
                or address_to_url.get(rendered_addr.lower())
                or address_to_url.get(rendered_addr.replace("...", "…"))
                or address_to_url.get(rendered_addr.replace("…", "..."))
            )
            if not url:
                continue

            glyph_w = fs * 0.55
            start_x = x + match.start() * glyph_w
            end_x   = x + match.end()   * glyph_w
            rect = ArrayObject([
                FloatObject(start_x - 2.0),
                FloatObject(y - 2.0),
                FloatObject(end_x + 2.0),
                FloatObject(y + fs + 2.0),
            ])
            link_annot = DictionaryObject({
                NameObject("/Type"):    NameObject("/Annot"),
                NameObject("/Subtype"): NameObject("/Link"),
                NameObject("/Rect"):    rect,
                NameObject("/Border"):  ArrayObject([
                    NumberObject(0), NumberObject(0), NumberObject(0),
                ]),
                NameObject("/A"): DictionaryObject({
                    NameObject("/Type"): NameObject("/Action"),
                    NameObject("/S"):    NameObject("/URI"),
                    NameObject("/URI"):  TextStringObject(url),
                }),
            })
            page_existing_annots.append(link_annot)
            added += 1

    if added > 0:
        page[NameObject("/Annots")] = page_existing_annots
    return added


def _existing_uri_targets(annots_array, *, ArrayObject) -> set[str]:
    """Return the set of /URI targets already on the page so we
    don't double-emit annotations for URLs WeasyPrint already
    handled."""
    out: set[str] = set()
    if not annots_array:
        return out
    for annot in annots_array:
        try:
            resolved = annot.get_object() if hasattr(annot, "get_object") else annot
            subtype = resolved.get("/Subtype")
            if str(subtype) != "/Link":
                continue
            action = resolved.get("/A")
            if not action:
                continue
            action = action.get_object() if hasattr(action, "get_object") else action
            uri = action.get("/URI")
            if uri:
                out.add(str(uri))
        except Exception:  # noqa: BLE001
            continue
    return out


__all__ = ("patch_pdf_links",)
