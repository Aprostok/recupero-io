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
# Captures the full URL so we can use it verbatim as the /URI action
# target.
_EXPLORER_URL_RE = re.compile(
    r"https?://(?:"
    r"etherscan\.io|"
    r"arbiscan\.io|"
    r"basescan\.org|"
    r"polygonscan\.com|"
    r"bscscan\.com|"
    r"solscan\.io|"
    r"app\.hyperliquid\.xyz"
    r")/[A-Za-z0-9/_\-?=&#.%]+",
    re.IGNORECASE,
)


def patch_pdf_links(pdf_path: Path) -> int:
    """Add missing /Link annotations to ``pdf_path`` in place.

    Returns the number of annotations added (0 on no-op / failure).
    The PDF is only rewritten when at least one annotation was added,
    so a no-op pass doesn't touch the file's mtime.

    Defensive: every step is wrapped in try/except. A pypdf import
    error or a malformed PDF logs a warning and returns 0 — the
    caller's freeze-letter pipeline still ships the WeasyPrint
    output unchanged.
    """
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
    ArrayObject,
    DictionaryObject,
    FloatObject,
    NameObject,
    NumberObject,
    TextStringObject,
) -> int:
    """Walk one page, inject /Link annotations for every chain-
    explorer URL found in the text.

    Strategy: pypdf's ``extract_text(extraction_mode='layout')``
    gives us text spans with x/y/width/height bboxes. We scan the
    spans for URL matches and emit one /Link annotation per match.

    Note: pypdf's bbox computation is approximate — sometimes off
    by a few points. We inflate the rectangle by 2pt on every side
    so a near-miss click still hits the annotation.
    """
    # Collect text spans with positions. pypdf's visitor pattern
    # exposes per-fragment (op, args, cm, tm) where tm encodes
    # the text matrix. The matrix's e/f components are the x/y
    # baseline position of the fragment.
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

    # PDF coordinate system: origin is bottom-left. We need each
    # annotation rect as [x0, y0, x1, y1] (lower-left, upper-right).
    # The visitor gives us baseline x/y; the rectangle should be
    # (x, y - descender) to (x + width, y + ascender). Approximate
    # width from text length × font_size × 0.55 (close enough for
    # monospaced hex that dominates these links).
    page_existing_annots = page.get("/Annots") or ArrayObject()
    existing_uris = _existing_uri_targets(
        page_existing_annots, ArrayObject=ArrayObject,
    )

    added = 0
    for text, x, y, fs in spans:
        for match in _EXPLORER_URL_RE.finditer(text):
            url = match.group(0)
            if url in existing_uris:
                continue
            # Approximate the span x extent for this URL fragment.
            # The match's start offset within text gives us the
            # column to compute x offset from.
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
