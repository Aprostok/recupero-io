"""Supabase-backed source for the Case-Index operator console.

A freshly-deployed ``recupero-api`` has an empty, ephemeral LOCAL case store, so
the console shows nothing real. When the deploy is configured for Supabase
Storage (the same bucket the worker writes investigations to), this module lets
the console list + browse those real cases instead.

Opt-in + safe-by-default: the local filesystem path in ``case_index_api`` is
UNCHANGED and remains the default. This module is consulted only when
``RECUPERO_CASE_STORE=supabase`` AND both ``SUPABASE_URL`` +
``SUPABASE_SERVICE_ROLE_KEY`` are set. Any failure here is caught by the caller,
which logs and degrades gracefully (the console never 500s).

For Supabase, a case's ``case_id`` IS its investigation_id (the UUID the bucket
is keyed by). The per-investigation store validates that UUID on construction,
so a malformed id is rejected before any network call.
"""

from __future__ import annotations

import logging
import os
from typing import Any

log = logging.getLogger(__name__)

# Mirror the local index cap so a huge bucket can't make the index slow/heavy.
_MAX_CASES = 500
_MAX_ARTIFACT_ENTRIES = 2000


def enabled() -> bool:
    """True only when explicitly switched to Supabase AND credentials present."""
    if (os.environ.get("RECUPERO_CASE_STORE", "") or "").strip().lower() != "supabase":
        return False
    return bool(
        (os.environ.get("SUPABASE_URL", "") or "").strip()
        and (os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "") or "").strip()
    )


def _creds() -> tuple[str, str, str]:
    url = (os.environ.get("SUPABASE_URL", "") or "").strip()
    key = (os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "") or "").strip()
    bucket = (os.environ.get("RECUPERO_SUPABASE_BUCKET", "") or "").strip() or "investigation-files"
    return url, key, bucket


def _store(investigation_id: str):  # noqa: ANN202 — SupabaseCaseStore
    from recupero.config import load_config
    from recupero.storage.supabase_case_store import SupabaseCaseStore

    cfg, _ = load_config()
    url, key, bucket = _creds()
    return SupabaseCaseStore(
        cfg, supabase_url=url, service_role_key=key,
        investigation_id=investigation_id, bucket=bucket,
    )


def list_cases() -> list[dict[str, Any]]:
    """Every Supabase-backed investigation that has a case.json, with the same
    deliverable-presence flags as the local index. One list call per
    investigation (no recursion)."""
    from recupero.config import load_config
    from recupero.storage.supabase_case_store import list_investigation_ids

    cfg, _ = load_config()
    url, key, bucket = _creds()
    ids = list_investigation_ids(cfg, url, key, bucket=bucket)
    cases: list[dict[str, Any]] = []
    for inv_id in ids:
        if len(cases) >= _MAX_CASES:
            break
        try:
            store = _store(inv_id)
        except ValueError:
            # Not a valid UUID folder — skip (never surface a bad id).
            continue
        try:
            names = set(store.list_top_level_names())
        except Exception as exc:  # noqa: BLE001
            log.warning("supabase list_cases: %s skipped (%s)", inv_id, exc)
            continue
        finally:
            store.close()
        if "case.json" not in names:
            continue
        cases.append({
            "case_id": inv_id,
            "has_brief": "freeze_brief.json" in names,
            "has_ai_triage": "ai_triage.json" in names,
            "has_exhibit_pack": "exhibit_pack" in names,
            "has_graph": "graph_ui.html" in names,
        })
    return cases


def list_artifacts(case_id: str) -> list[dict[str, Any]]:
    """Every artifact for one Supabase-backed case, classified + sized — the
    same shape the local browser returns."""
    from recupero.api.case_index_api import _VIEW_BY_EXT, _classify_artifact

    store = _store(case_id)  # raises ValueError on a non-UUID case_id
    try:
        pairs = store.list_artifacts()
    finally:
        store.close()
    items: list[dict[str, Any]] = []
    for rel, size in pairs[:_MAX_ARTIFACT_ENTRIES]:
        name = rel.rsplit("/", 1)[-1]
        ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
        items.append({
            "name": name,
            "path": rel,
            "category": _classify_artifact(rel),
            "ext": ext,
            "size_bytes": size,
            "view": _VIEW_BY_EXT.get(ext, "download"),
        })
    return items


def read_artifact(case_id: str, relpath: str) -> bytes:
    """Download one artifact's bytes for inline view / download. Traversal is
    guarded by the store's ``read_artifact`` (rejects ``..`` / ``//`` / leading
    slash); size is capped by the store's download cap."""
    store = _store(case_id)
    try:
        return store.read_artifact(relpath)
    finally:
        store.close()


__all__ = ("enabled", "list_artifacts", "list_cases", "read_artifact")
