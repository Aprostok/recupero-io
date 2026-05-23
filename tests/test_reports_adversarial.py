"""Adversarial-input regression tests for src/recupero/reports.

RIGOR-Jacob Z4 hardening — these tests lock down hostile inputs that
flow from operator-controlled brief / freeze_asks fields into the
legal-request renderer. Each test corresponds to a concrete bug
fixed in the same commit. The trigger paths are real (not synthetic):

  * brief.EXCHANGES[*].exchange — populated from token labels +
    exchange-deposit detection, which ultimately sources external
    label data. An attacker who plants a malicious token label gets
    that string into the renderer.
  * freeze_asks.onward_cex_flows[*].exchange — same provenance.
  * freeze_asks.onward_cex_flows[*].flow_usd_value — derived from
    on-chain transfer USD valuation; a price-oracle glitch could
    inject Inf/NaN and we must not render `$inf` into a draft
    grand-jury subpoena.
"""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from recupero.reports.legal_requests import (
    _render_exchange_subpoena_requests,
    render_legal_request,
)


def _minimal_brief(**overrides) -> dict:
    base = {
        "CASE_ID": "V-CFI-9999",
        "VICTIM_NAME": "Jane Doe",
        "VICTIM_JURISDICTION": "California, USA",
        "INVESTIGATOR_NAME": "Test Investigator",
        "INVESTIGATOR_EMAIL": "test@recupero.io",
        "INVESTIGATOR_ENTITY_FULL": "Recupero LLC",
        "INCIDENT_DATE": "2026-04-01",
        "INCIDENT_TYPE": "wire-fraud scam",
        "TOTAL_LOSS_USD": "$48,200.00",
        "EXCHANGES": [],
        "CROSS_CHAIN_HANDOFFS": [],
        "DEX_SWAPS": [],
    }
    base.update(overrides)
    return base


# ---- Bug 1: path traversal via brief.EXCHANGES[*].exchange (subpoena/mlat/314b) ----


@pytest.mark.parametrize("rtype", ["subpoena", "mlat", "314b"])
def test_legal_request_filename_rejects_path_traversal(rtype: str) -> None:
    """An attacker-controlled exchange name like ``../../etc/passwd``
    must NOT escape ``output_dir``. Pre-fix the renderer wrote to
    ``output_dir/subpoena_../../etc/passwd.html``, which Path()
    flattens into a file outside the operator's chosen output dir.
    The sanitizer must strip path separators and `..` segments so
    the file lands as a SIBLING in ``output_dir``, not nested.
    """
    brief = _minimal_brief(
        EXCHANGES=[
            {
                "exchange": "../../etc/passwd",
                "address": "0xabc",
                "total_received_usd": "$1",
            },
        ],
    )
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp).resolve()
        renders = render_legal_request(
            brief, request_type=rtype, output_dir=tmp_path,
        )
        assert len(renders) == 1
        out = renders[0].output_path.resolve()
        # The hardening MUST keep the written file directly inside
        # output_dir (no nested subdirs from traversal segments).
        assert out.parent == tmp_path, (
            f"Output {out} escaped output_dir {tmp_path}"
        )
        # No `..`, `/`, `\` should remain in the basename.
        assert ".." not in out.name
        assert "/" not in out.name
        assert "\\" not in out.name


def test_legal_request_filename_rejects_windows_separator() -> None:
    """Windows path separators (\\) must be stripped too — pre-fix
    a Windows operator could be tricked into writing outside
    ``output_dir`` via ``..\\evil``.

    Locks the basename, not the resolved-parent, because Path
    flattening on Windows can hide the traversal (`tmp/subpoena_..\\..`
    happens to resolve back near tmp on a deep temp prefix). The
    real signature of a working sanitizer is that ``out.name``
    contains no separators.
    """
    brief = _minimal_brief(
        EXCHANGES=[
            {
                "exchange": "..\\evil",
                "address": "0xabc",
                "total_received_usd": "$1",
            },
        ],
    )
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp).resolve()
        renders = render_legal_request(
            brief, request_type="subpoena", output_dir=tmp_path,
        )
        out_path = renders[0].output_path
        # The on-disk filename (as the renderer constructed it) must
        # not contain any separators OR `..` segments. We inspect the
        # un-resolved path so Path() collapsing can't hide the bug.
        assert "\\" not in out_path.name, f"name={out_path.name!r}"
        assert "/" not in out_path.name
        assert ".." not in out_path.name


def test_legal_request_filename_rejects_null_byte() -> None:
    """A NUL byte in exchange name historically truncates the on-disk
    filename on POSIX. The sanitizer must drop it entirely.
    """
    brief = _minimal_brief(
        EXCHANGES=[
            {
                "exchange": "evil\x00stuff",
                "address": "0xabc",
                "total_received_usd": "$1",
            },
        ],
    )
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        renders = render_legal_request(
            brief, request_type="subpoena", output_dir=tmp_path,
        )
        out = renders[0].output_path
        assert "\x00" not in str(out)


# ---- Bug 2: path traversal in exchange-subpoena renderer ----


def test_exchange_subpoena_rejects_path_traversal() -> None:
    """Same class of bug on the exchange-subpoena renderer, which
    reads from ``freeze_asks.onward_cex_flows[*].exchange``.

    Pre-fix the renderer did ``.lower().replace(" ", "_").replace(".", "")``,
    which deletes the dot from `..` but preserves `/`, so the path
    ``../evil`` becomes ``/evil`` (still escapes output_dir).
    """
    brief = _minimal_brief(
        _freeze_asks={
            "onward_cex_flows": [
                {
                    "exchange": "../evil",
                    "flow_usd_value": "100.00",
                    "token_symbol": "USDT",
                    "upstream_address": "0x" + "a" * 40,
                    "upstream_explorer_url": "",
                    "cex_address": "0x" + "b" * 40,
                    "cex_explorer_url": "",
                    "transfer_count": 1,
                    "first_flow_at": "2026-04-01T00:00:00Z",
                    "last_flow_at": "2026-04-01T00:00:00Z",
                },
            ],
        },
    )
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp).resolve()
        renders = _render_exchange_subpoena_requests(
            brief, output_dir=tmp_path,
        )
        assert len(renders) == 1
        out = renders[0].output_path.resolve()
        assert out.parent == tmp_path, (
            f"Output {out} escaped output_dir {tmp_path}"
        )
        assert ".." not in out.name
        assert "/" not in out.name
        assert "\\" not in out.name


# ---- Bug 3: Inf/NaN aggregation renders `$inf` into legal docs ----


def test_exchange_subpoena_rejects_inf_usd_value() -> None:
    """A poisoned ``flow_usd_value="Infinity"`` would currently render
    ``$inf`` as the cover-page banner total in the grand-jury subpoena
    draft. That's a legal-document quality bug — the operator might
    send it without noticing.
    """
    _flow_extra = {
        "upstream_address": "0x" + "a" * 40,
        "upstream_explorer_url": "",
        "cex_address": "0x" + "b" * 40,
        "cex_explorer_url": "",
        "transfer_count": 1,
        "first_flow_at": "2026-04-01T00:00:00Z",
        "last_flow_at": "2026-04-01T00:00:00Z",
    }
    brief = _minimal_brief(
        _freeze_asks={
            "onward_cex_flows": [
                {
                    "exchange": "Binance",
                    "flow_usd_value": "Infinity",
                    "token_symbol": "USDT",
                    **_flow_extra,
                },
                {
                    "exchange": "Binance",
                    "flow_usd_value": "1000",
                    "token_symbol": "USDT",
                    **_flow_extra,
                },
            ],
        },
    )
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        renders = _render_exchange_subpoena_requests(
            brief, output_dir=tmp_path,
        )
        assert len(renders) == 1
        html = renders[0].output_path.read_text(encoding="utf-8")
        # Must not leak inf/nan into the draft.
        assert "$inf" not in html.lower()
        assert "$nan" not in html.lower()


def test_exchange_subpoena_rejects_nan_usd_value() -> None:
    brief = _minimal_brief(
        _freeze_asks={
            "onward_cex_flows": [
                {
                    "exchange": "Binance",
                    "flow_usd_value": "NaN",
                    "token_symbol": "USDT",
                    "upstream_address": "0x" + "a" * 40,
                    "upstream_explorer_url": "",
                    "cex_address": "0x" + "b" * 40,
                    "cex_explorer_url": "",
                    "transfer_count": 1,
                    "first_flow_at": "2026-04-01T00:00:00Z",
                    "last_flow_at": "2026-04-01T00:00:00Z",
                },
            ],
        },
    )
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        renders = _render_exchange_subpoena_requests(
            brief, output_dir=tmp_path,
        )
        assert len(renders) == 1
        html = renders[0].output_path.read_text(encoding="utf-8")
        assert "$nan" not in html.lower()
        assert "$inf" not in html.lower()
