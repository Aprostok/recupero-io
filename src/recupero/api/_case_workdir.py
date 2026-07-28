"""A local directory holding one case's artifacts, wherever the case lives.

Several per-case operator consoles (exhibit pack, SAR filing, recovery
snapshot, AI triage) do their real work against a local ``case_dir`` --
``build_exhibit_manifest(case_dir)``, ``load_brief(case_dir)``,
``(case_dir / "ai_triage.json").read_bytes()``. That is fine on a local
filesystem deploy and completely broken on a Supabase-backed one, where the
container's ``data/cases`` is empty and every real case 404s even though the
Case Index can list it (the index is the one module that reads through
``_supabase_case_source``).

This module closes that gap without rewriting each console's artifact logic:
``case_workdir`` yields a real directory either way. Filesystem deploys get the
case's actual directory (no copying). Supabase deploys get a temp directory with
the requested artifacts downloaded into it, removed on exit.

Callers declare what they need via ``want`` so a console that reads one small
JSON does not drag down a multi-megabyte ``case.json``. ``want=None`` means
"every artifact", which only the exhibit pack (it walks the whole tree to hash
every file) actually needs.
"""

from __future__ import annotations

import contextlib
import logging
import shutil
import tempfile
from collections.abc import Iterator, Sequence
from pathlib import Path

log = logging.getLogger(__name__)

# Cap what one request will pull out of object storage. Anyone with bucket
# write access can plant an enormous artifact; a read-only console must not be
# turned into an OOM / disk-fill vector by it.
_MAX_MATERIALIZE_BYTES = 64 * 1024 * 1024


class CaseNotFound(Exception):
    """No such case, or the case has no artifacts. Callers map this to 404."""


class CaseStoreUnavailable(Exception):
    """The store itself failed (network / 5xx). Callers map this to 503.

    Deliberately distinct from :class:`CaseNotFound`: reporting a Supabase
    outage as "case not found" sends an operator hunting for a case that
    exists.
    """


@contextlib.contextmanager
def case_workdir(
    case_id: str,
    *,
    want: Sequence[str] | None = None,
) -> Iterator[Path]:
    """Yield a local directory containing ``case_id``'s artifacts.

    ``want`` is a sequence of case-relative paths (e.g.
    ``["freeze_brief.json"]``); ``None`` requests every artifact. Requested
    paths that the case does not have are simply absent from the yielded
    directory -- the consoles already treat a missing artifact as "not
    produced yet", so this preserves that behaviour.

    Raises :class:`CaseNotFound` or :class:`CaseStoreUnavailable`.
    """
    from recupero.api import _supabase_case_source as _sb

    if not _sb.enabled():
        # Filesystem deploy: hand back the real directory, copying nothing.
        # read_case is the existence check (it is path-traversal-guarded and
        # does NOT create the directory, unlike CaseStore.case_dir).
        from recupero.config import load_config
        from recupero.storage.case_store import CaseStore

        cfg, _ = load_config()
        store = CaseStore(cfg)
        try:
            store.read_case(case_id)
        except (OSError, ValueError) as exc:
            raise CaseNotFound(f"case not found: {case_id!r}") from exc
        yield store.cases_root / case_id
        return

    try:
        items = _sb.list_artifacts(case_id)
    except ValueError as exc:  # non-UUID id -- rejected before any network call
        raise CaseNotFound(f"case not found: {case_id!r}") from exc
    except Exception as exc:  # noqa: BLE001 -- store outage, not a missing case
        raise CaseStoreUnavailable(str(exc)) from exc

    if not items:
        raise CaseNotFound(f"case has no artifacts: {case_id!r}")

    available = [str(i["path"]) for i in items]
    if want is None:
        selected = available
    else:
        wanted = set(want)
        selected = [p for p in available if p in wanted]

    tmp = Path(tempfile.mkdtemp(prefix="recupero-case-"))
    try:
        root = tmp.resolve()
        budget = _MAX_MATERIALIZE_BYTES
        for rel in selected:
            dest = (tmp / rel).resolve()
            # The path list comes from object storage, so treat it as
            # untrusted: a planted "../.." entry must not write outside tmp.
            if not dest.is_relative_to(root):
                log.warning("case_workdir: skipping escaping path %r", rel)
                continue
            try:
                blob = _sb.read_artifact(case_id, rel)
            except FileNotFoundError:
                continue  # listed but gone; treat as not-produced
            except Exception as exc:  # noqa: BLE001
                raise CaseStoreUnavailable(str(exc)) from exc
            budget -= len(blob)
            if budget < 0:
                log.warning(
                    "case_workdir: %s exceeded the %d-byte materialize cap; "
                    "stopping early", case_id, _MAX_MATERIALIZE_BYTES,
                )
                break
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(blob)
        yield tmp
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def artifact_names(case_id: str) -> list[str] | None:
    """Case-relative artifact paths, or ``None`` on a filesystem deploy.

    For presence-only checks (does this case have a freeze brief?) downloading
    bytes is pure waste -- the Supabase listing already answers the question.
    Returns ``None`` when Supabase is not in play, telling the caller to fall
    back to its existing on-disk checks.
    """
    from recupero.api import _supabase_case_source as _sb

    if not _sb.enabled():
        return None
    try:
        return [str(i["path"]) for i in _sb.list_artifacts(case_id)]
    except ValueError as exc:
        raise CaseNotFound(f"case not found: {case_id!r}") from exc
    except Exception as exc:  # noqa: BLE001
        raise CaseStoreUnavailable(str(exc)) from exc


__all__ = (
    "CaseNotFound",
    "CaseStoreUnavailable",
    "artifact_names",
    "case_workdir",
)
