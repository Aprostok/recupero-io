"""Continuous (cross-case) cluster store (#7) — pure union-find planner + the
fake-DB accumulate/lookup paths."""

from __future__ import annotations

from contextlib import contextmanager

from recupero.trace.cluster_store import (
    accumulate_cluster,
    lookup_cluster,
    plan_cluster_assignment,
)

# ---- pure planner ---- #


def test_plan_new_cluster_when_no_member_known() -> None:
    p = plan_cluster_assignment(["0xa", "0xb"], existing={})
    assert p.canonical_id.startswith("cluster_")
    assert p.merged_from == []
    # Deterministic: same member set → same id.
    assert plan_cluster_assignment(["0xb", "0xa"], existing={}).canonical_id == p.canonical_id


def test_plan_joins_single_existing_cluster() -> None:
    p = plan_cluster_assignment(["0xa", "0xc"], existing={"0xa": "cluster_zzz"})
    assert p.canonical_id == "cluster_zzz"
    assert p.merged_from == []


def test_plan_merges_two_existing_clusters() -> None:
    # Incoming bridges two previously-separate clusters → union into the
    # lexicographically smallest id; the other merges in.
    p = plan_cluster_assignment(
        ["0xa", "0xb"], existing={"0xa": "cluster_bbb", "0xb": "cluster_aaa"},
    )
    assert p.canonical_id == "cluster_aaa"
    assert p.merged_from == ["cluster_bbb"]


# ---- fake DB ---- #


class _FakeCursor:
    def __init__(self, fetchall=None, fetchone_queue=None) -> None:
        self.executed: list[tuple] = []
        self._fetchall = fetchall or []
        self._fetchone_queue = list(fetchone_queue or [])

    def execute(self, sql, params=None):  # noqa: ANN001
        self.executed.append((sql, params))

    def fetchall(self):
        return self._fetchall

    def fetchone(self):
        return self._fetchone_queue.pop(0) if self._fetchone_queue else None

    def __enter__(self):
        return self

    def __exit__(self, *exc):  # noqa: ANN002
        return False


class _FakeConn:
    def __init__(self, cur) -> None:
        self._cur = cur

    def cursor(self):
        return self._cur

    def __enter__(self):
        return self

    def __exit__(self, *exc):  # noqa: ANN002
        return False


def _patch(monkeypatch, cur) -> None:
    @contextmanager
    def _fake(dsn, **kw):  # noqa: ANN001
        yield _FakeConn(cur)
    monkeypatch.setattr("recupero._common.db_connect", _fake)


# ---- accumulate ---- #


def test_accumulate_no_dsn_returns_none() -> None:
    assert accumulate_cluster(None, ["0xa", "0xb"], "ethereum") is None


def test_accumulate_singleton_returns_none() -> None:
    # <2 members short-circuits before any DB touch.
    assert accumulate_cluster("postgresql://x", ["0xa"], "ethereum") is None


def test_accumulate_new_cluster_upserts_each_member(monkeypatch) -> None:
    cur = _FakeCursor(fetchall=[])  # no existing members
    _patch(monkeypatch, cur)
    cid = accumulate_cluster(
        "postgresql://x", ["0xb", "0xa"], "ethereum",
        heuristic="co_spending", confidence="high",
    )
    assert cid and cid.startswith("cluster_")
    # 1 SELECT + 2 UPSERTs (no merge since no existing). No UPDATE.
    sqls = [s for s, _ in cur.executed]
    assert any("SELECT address, cluster_id" in s for s in sqls)
    assert sum(1 for s in sqls if "INSERT INTO public.cluster_membership" in s) == 2
    assert not any("UPDATE public.cluster_membership SET cluster_id" in s for s in sqls)


def test_accumulate_merges_existing(monkeypatch) -> None:
    # Two incoming members already belong to two different clusters → merge.
    cur = _FakeCursor(fetchall=[("0xa", "cluster_bbb"), ("0xb", "cluster_aaa")])
    _patch(monkeypatch, cur)
    cid = accumulate_cluster("postgresql://x", ["0xa", "0xb"], "ethereum")
    assert cid == "cluster_aaa"
    sqls = [s for s, _ in cur.executed]
    # A merge UPDATE folds cluster_bbb into the canonical id.
    assert any("UPDATE public.cluster_membership SET cluster_id" in s for s in sqls)


def test_accumulate_never_raises_on_db_error(monkeypatch) -> None:
    @contextmanager
    def _boom(dsn, **kw):  # noqa: ANN001
        raise RuntimeError("db down")
        yield  # pragma: no cover
    monkeypatch.setattr("recupero._common.db_connect", _boom)
    assert accumulate_cluster("postgresql://x", ["0xa", "0xb"], "ethereum") is None


# ---- lookup ---- #


def test_lookup_no_dsn_returns_none() -> None:
    assert lookup_cluster(None, "0xa", "ethereum") is None


def test_lookup_returns_cluster_with_size(monkeypatch) -> None:
    cur = _FakeCursor(fetchone_queue=[("cluster_x", "co_spending", "high"), (4,)])
    _patch(monkeypatch, cur)
    out = lookup_cluster("postgresql://x", "0xa", "ethereum")
    assert out == {"cluster_id": "cluster_x", "heuristic": "co_spending",
                   "confidence": "high", "size": 4}


def test_lookup_miss_returns_none(monkeypatch) -> None:
    cur = _FakeCursor(fetchone_queue=[None])
    _patch(monkeypatch, cur)
    assert lookup_cluster("postgresql://x", "0xunknown", "ethereum") is None
