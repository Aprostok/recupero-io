"""v0.23.0 — Multi-Victim Cluster tests.

Covers:
  * _extract_perp_wallets_from_brief — pure-function shape
  * _gen_cluster_public_id — stable hash; same input → same output
  * build_or_update_cluster_for_case — DB-mocked happy + no-overlap paths
  * LE handoff renders Section 5.6 with cluster info
  * Cluster handoff template renders end-to-end
  * render_cluster_handoff handles missing cluster, missing DSN
  * Filename sanitization on cluster public_id
"""

from __future__ import annotations

import tempfile
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch
from uuid import UUID, uuid4

import pytest

from recupero.monitoring.cluster_builder import (
    ClusterMembership,
    _extract_perp_wallets_from_brief,
    _gen_cluster_public_id,
    build_or_update_cluster_for_case,
    fetch_cluster_summary,
)


# ─────────────────────────────────────────────────────────────────────────────
# Pure-function helpers
# ─────────────────────────────────────────────────────────────────────────────


def test_extract_perp_wallets_includes_hub_and_freezable_holdings():
    """All freezable + UNRECOVERABLE holding addresses are surfaced
    as cluster-bridge candidates — they're the perp-controlled wallets
    that bind cases together."""
    brief = {
        "PRIMARY_CHAIN": "ethereum",
        "PERP_HUB": {"address": "0xHUB" + "0" * 39, "chain": "ethereum"},
        "ALL_ISSUER_HOLDINGS": [
            {"issuer": "Tether", "holdings": [
                {"address": "0xTETH" + "0" * 38, "chain": "ethereum"},
            ]},
            {"issuer": "Circle", "holdings": [
                {"address": "0xCIRC" + "0" * 38, "chain": "ethereum"},
            ]},
        ],
    }
    pairs = _extract_perp_wallets_from_brief(brief)
    # Lowercase canonicalization applied to all EVM addresses
    addrs = {p[0] for p in pairs}
    assert "0xhub" + "0" * 39 in addrs
    assert "0xteth" + "0" * 38 in addrs
    assert "0xcirc" + "0" * 38 in addrs


def test_extract_perp_wallets_dedups_overlap_between_hub_and_holdings():
    """If the perp hub also appears as a holding (V-CFI01 shape), the
    pair set must dedup to a single entry."""
    brief = {
        "PRIMARY_CHAIN": "ethereum",
        "PERP_HUB": {"address": "0xHUB" + "0" * 39, "chain": "ethereum"},
        "ALL_ISSUER_HOLDINGS": [
            {"issuer": "Sky Protocol", "holdings": [
                {"address": "0xHUB" + "0" * 39, "chain": "ethereum"},
            ]},
        ],
    }
    pairs = _extract_perp_wallets_from_brief(brief)
    hub_pairs = [p for p in pairs if p[0] == "0xhub" + "0" * 39]
    assert len(hub_pairs) == 1


def test_extract_perp_wallets_empty_brief_returns_empty():
    """No hub, no holdings → empty pair list (no cluster build)."""
    assert _extract_perp_wallets_from_brief({}) == []
    assert _extract_perp_wallets_from_brief(
        {"PRIMARY_CHAIN": "ethereum", "PERP_HUB": {}, "ALL_ISSUER_HOLDINGS": []},
    ) == []


def test_gen_cluster_public_id_stable_for_same_seed():
    """Two operators observing the same perp wallet must produce the
    same public_id — defends idempotency under concurrent emit_brief."""
    a = _gen_cluster_public_id("0xABCD1234", "ethereum")
    b = _gen_cluster_public_id("0xABCD1234", "ethereum")
    assert a == b
    assert a.startswith("CL-")
    assert len(a) == 9  # "CL-" + 6 hex chars


def test_gen_cluster_public_id_case_insensitive_on_address():
    """Mixed-case vs lowercase address must produce the same id —
    otherwise EVM addresses normalize differently across observers."""
    a = _gen_cluster_public_id("0xABCD1234", "ethereum")
    b = _gen_cluster_public_id("0xabcd1234", "ethereum")
    assert a == b


def test_gen_cluster_public_id_differs_for_different_seeds():
    """Different seed wallets produce distinct public_ids."""
    a = _gen_cluster_public_id("0xABCD1234", "ethereum")
    b = _gen_cluster_public_id("0xDEAD0000", "ethereum")
    assert a != b


# ─────────────────────────────────────────────────────────────────────────────
# build_or_update_cluster_for_case — DB-mocked
# ─────────────────────────────────────────────────────────────────────────────


def test_build_cluster_noop_without_dsn():
    """No DSN → no-op (None) so emit_brief on a local CLI path
    doesn't try to reach a database."""
    result = build_or_update_cluster_for_case(
        {"PERP_HUB": {"address": "0xABCD", "chain": "ethereum"}},
        investigation_id=uuid4(),
        case_id=None,
        dsn=None,
    )
    assert result is None


def test_build_cluster_noop_without_investigation_id():
    """No investigation_id → no-op. The cluster requires an investigation
    UUID to bridge into case_cluster_members."""
    result = build_or_update_cluster_for_case(
        {"PERP_HUB": {"address": "0xABCD", "chain": "ethereum"}},
        investigation_id=None,
        case_id=None,
        dsn="postgres://fake",
    )
    assert result is None


def test_build_cluster_noop_when_no_perp_wallets():
    """Empty brief (no hub, no holdings) → no-op."""
    result = build_or_update_cluster_for_case(
        {},
        investigation_id=uuid4(),
        case_id=None,
        dsn="postgres://fake",
    )
    assert result is None


def test_build_cluster_noop_when_no_prior_overlap():
    """When no prior case shares any perp wallet, the function returns
    None (no cluster bookkeeping). This is the typical first-of-a-perp
    case path."""
    brief = {
        "PRIMARY_CHAIN": "ethereum",
        "PERP_HUB": {"address": "0xABCD" + "0" * 38, "chain": "ethereum"},
        "ALL_ISSUER_HOLDINGS": [],
    }
    with patch(
        "recupero.monitoring.cluster_builder._table_exists",
        return_value=True,
    ), patch(
        "recupero.monitoring.cluster_builder._find_prior_overlap_cases",
        return_value=[],
    ):
        result = build_or_update_cluster_for_case(
            brief,
            investigation_id=uuid4(),
            case_id=None,
            dsn="postgres://fake",
        )
    assert result is None


def test_build_cluster_noop_when_table_missing():
    """If migration 019 hasn't been applied, the function detects the
    missing case_clusters table and returns None rather than raising."""
    brief = {
        "PRIMARY_CHAIN": "ethereum",
        "PERP_HUB": {"address": "0xABCD" + "0" * 38, "chain": "ethereum"},
    }
    with patch(
        "recupero.monitoring.cluster_builder._table_exists",
        return_value=False,
    ):
        result = build_or_update_cluster_for_case(
            brief,
            investigation_id=uuid4(),
            case_id=None,
            dsn="postgres://fake",
        )
    assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# LE handoff Section 5.6 rendering
# ─────────────────────────────────────────────────────────────────────────────


def _render_le_with_cluster(cluster_membership):
    """Render the LE handoff on the V-CFI01 fixture with a given
    cluster_membership dict."""
    from tests.test_v_cfi01_full_render import _build_v_cfi01_case, VICTIM
    from recupero.reports.brief import InvestigatorInfo, generate_briefs
    from recupero.reports.victim import VictimInfo

    case = _build_v_cfi01_case()
    victim = VictimInfo(
        name="V-CFI01", wallet_address=VICTIM,
        state="NY", country="US", email="victim@test.com",
    )
    investigator = InvestigatorInfo(
        name="Test", organization="Recupero", email="t@example.com",
    )
    with tempfile.TemporaryDirectory(prefix="v23_le_") as tmp:
        bundle = generate_briefs(
            primary_case=case,
            linked_cases=[],
            victim=victim,
            investigator=investigator,
            case_dir=Path(tmp),
            cluster_membership=cluster_membership,
        )
        return bundle.le_path.read_text(encoding="utf-8")


def test_le_renders_section_5_6_when_cluster_has_two_or_more_members():
    """A cluster with N>=2 members surfaces in Section 5.6 with public_id,
    aggregate loss, co-victim count, and coordination recommendations."""
    membership = {
        "cluster_id": "11111111-1111-1111-1111-111111111111",
        "public_id": "CL-AB12CD",
        "is_new_cluster": False,
        "member_case_count": 12,
        "co_victim_count": 11,
        "total_loss_usd": "42500000.00",
        "total_loss_usd_human": "$42,500,000.00",
        "joined_via_address": "0xdeadbeef" + "0" * 32,
        "joined_via_chain": "ethereum",
    }
    html = _render_le_with_cluster(membership)
    assert "Multi-Victim Cluster" in html
    assert "CL-AB12CD" in html
    assert "12" in html  # member_case_count
    assert "11" in html  # co_victim_count
    assert "$42,500,000.00" in html
    assert "render-cluster CL-AB12CD" in html


def test_le_hides_section_5_6_when_cluster_membership_none():
    """No cluster → Section 5.6 is omitted; LE renders cleanly."""
    html = _render_le_with_cluster(None)
    assert "Multi-Victim Cluster" not in html
    assert "5.6" not in html


def test_le_hides_section_5_6_when_cluster_has_only_one_member():
    """A cluster of size 1 (just this case — no prior overlap) is
    effectively no cluster; Section 5.6 stays hidden so the LE
    document doesn't claim a cluster of one."""
    membership = {
        "cluster_id": "11111111-1111-1111-1111-111111111111",
        "public_id": "CL-AB12CD",
        "is_new_cluster": True,
        "member_case_count": 1,
        "co_victim_count": 0,
        "total_loss_usd": "1000000.00",
        "total_loss_usd_human": "$1,000,000",
        "joined_via_address": "0xabcd",
        "joined_via_chain": "ethereum",
    }
    html = _render_le_with_cluster(membership)
    assert "Multi-Victim Cluster" not in html


# ─────────────────────────────────────────────────────────────────────────────
# render_cluster_handoff standalone deliverable
# ─────────────────────────────────────────────────────────────────────────────


def test_render_cluster_handoff_returns_none_without_dsn():
    """No DSN → None (CLI surfaces a clean error message)."""
    from recupero.reports.cluster_handoff import render_cluster_handoff

    with tempfile.TemporaryDirectory(prefix="cluster_handoff_") as tmp:
        path = render_cluster_handoff(
            "CL-FAKE01",
            output_dir=Path(tmp),
            dsn=None,
        )
    assert path is None


def test_render_cluster_handoff_returns_none_for_missing_cluster():
    """When fetch_cluster_summary returns None (cluster doesn't exist),
    the renderer returns None."""
    from recupero.reports.cluster_handoff import render_cluster_handoff

    with patch(
        "recupero.monitoring.cluster_builder.fetch_cluster_summary",
        return_value=None,
    ), tempfile.TemporaryDirectory(prefix="cluster_handoff_") as tmp:
        path = render_cluster_handoff(
            "CL-FAKE01",
            output_dir=Path(tmp),
            dsn="postgres://fake",
        )
    assert path is None


def test_render_cluster_handoff_writes_full_document():
    """Happy path — fetch returns a populated cluster, the template
    renders, the file lands on disk with the cluster public_id +
    aggregate stats."""
    from datetime import UTC, datetime
    from recupero.reports.cluster_handoff import render_cluster_handoff

    fake_cluster = {
        "id": UUID("22222222-2222-2222-2222-222222222222"),
        "public_id": "CL-AB12CD",
        "seed_perp_address": "0xdead" + "b" * 36,
        "seed_perp_chain": "ethereum",
        "shared_perp_addresses": ["0xdead" + "b" * 36],
        "shared_perp_chains": ["ethereum"],
        "member_case_count": 4,
        "total_loss_usd": Decimal("12500000.00"),
        "status": "active",
        "label": None,
        "notes": None,
        "created_at": datetime(2026, 1, 15, tzinfo=UTC),
        "updated_at": datetime(2026, 5, 18, tzinfo=UTC),
        "members": [
            {
                "cluster_id": UUID("22222222-2222-2222-2222-222222222222"),
                "case_id": UUID("33333333-3333-3333-3333-333333333333"),
                "investigation_id": UUID("44444444-4444-4444-4444-444444444444"),
                "role": "originator",
                "case_total_loss_usd": Decimal("3000000.00"),
                "joined_via_address": "0xdead" + "b" * 36,
                "joined_via_chain": "ethereum",
                "joined_at": datetime(2026, 1, 15, tzinfo=UTC),
            },
            {
                "cluster_id": UUID("22222222-2222-2222-2222-222222222222"),
                "case_id": UUID("55555555-5555-5555-5555-555555555555"),
                "investigation_id": UUID("66666666-6666-6666-6666-666666666666"),
                "role": "joined",
                "case_total_loss_usd": Decimal("4500000.00"),
                "joined_via_address": "0xdead" + "b" * 36,
                "joined_via_chain": "ethereum",
                "joined_at": datetime(2026, 3, 22, tzinfo=UTC),
            },
        ],
    }

    with patch(
        "recupero.monitoring.cluster_builder.fetch_cluster_summary",
        return_value=fake_cluster,
    ), tempfile.TemporaryDirectory(prefix="cluster_handoff_") as tmp:
        out_dir = Path(tmp)
        path = render_cluster_handoff(
            "CL-AB12CD",
            output_dir=out_dir,
            dsn="postgres://fake",
        )
        assert path is not None
        assert path.exists()
        assert path.name == "cluster_handoff_CL-AB12CD.html"
        html = path.read_text(encoding="utf-8")

    # Headline + aggregate
    assert "CL-AB12CD" in html
    assert "$12,500,000.00" in html
    assert "Multi-Victim" in html and "Cluster Handoff" in html
    # Member table — both originator + joined cases rendered
    assert "originator" in html
    assert "joined" in html
    # Per-case loss formatted
    assert "$3,000,000.00" in html
    assert "$4,500,000.00" in html


def test_render_cluster_handoff_sanitizes_unsafe_public_id_in_filename():
    """Defense-in-depth: a public_id with unsafe chars (path-traversal,
    NUL bytes) is sanitized in the output filename."""
    from datetime import UTC, datetime
    from recupero.reports.cluster_handoff import render_cluster_handoff

    fake_cluster = {
        "id": UUID("22222222-2222-2222-2222-222222222222"),
        "public_id": "../../etc/passwd",
        "seed_perp_address": "0xabc",
        "seed_perp_chain": "ethereum",
        "shared_perp_addresses": [],
        "shared_perp_chains": [],
        "member_case_count": 1,
        "total_loss_usd": Decimal("1.00"),
        "status": "active",
        "label": None,
        "notes": None,
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "updated_at": datetime(2026, 1, 1, tzinfo=UTC),
        "members": [],
    }
    with patch(
        "recupero.monitoring.cluster_builder.fetch_cluster_summary",
        return_value=fake_cluster,
    ), tempfile.TemporaryDirectory(prefix="cluster_handoff_unsafe_") as tmp:
        path = render_cluster_handoff(
            "../../etc/passwd",
            output_dir=Path(tmp),
            dsn="postgres://fake",
        )
    assert path is not None
    assert ".." not in path.name
    assert "/" not in path.name
