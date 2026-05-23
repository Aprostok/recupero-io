"""Download the briefs/ directory for an investigation into _validation_download/.

Used to inspect the deliverables produced on Railway after a validation
run — pulls every HTML, PDF, SVG, manifest in briefs/ to a local dir so
we can open them in a browser / PDF reader.

Run:
    python scripts/download_validation_briefs.py <investigation_id>
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

# Force UTF-8 console output so we can print unicode arrows on Windows
# without choking the cp1252 default codepage.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from dotenv import load_dotenv  # noqa: E402

from recupero.config import load_config  # noqa: E402
from recupero.storage.supabase_case_store import SupabaseCaseStore  # noqa: E402


_SAFE_ID = re.compile(r"^[A-Za-z0-9._-]+$")


def _safe_local_path(out_dir: Path, relative: str) -> Path:
    """Resolve ``out_dir / relative`` and refuse anything that escapes
    ``out_dir`` (path traversal via ``..`` or absolute paths in
    bucket-listed filenames). Returns the resolved local path.
    """
    if not relative or relative.startswith(("/", "\\")):
        raise ValueError(f"refusing absolute bucket path: {relative!r}")
    candidate = (out_dir / relative).resolve()
    root = out_dir.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"refusing path traversal in bucket filename: {relative!r}"
        ) from exc
    return candidate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("investigation_id")
    args = parser.parse_args()

    # Reject anything that isn't a plain identifier — investigation_id
    # is appended to a filesystem path, so disallow path separators and
    # ``..`` segments before we ever touch disk. The `_SAFE_ID` regex
    # allows dots as separators but a pure-dot string (e.g. ".." or
    # "...") is path-traversal in disguise — reject explicitly.
    raw_id = args.investigation_id or ""
    if (not _SAFE_ID.match(raw_id)
            or ".." in raw_id
            or set(raw_id) <= {"."}):
        print(
            "ERROR: investigation_id must match "
            f"{_SAFE_ID.pattern!r} and contain no '..' segment; "
            f"got {raw_id!r}",
            file=sys.stderr,
        )
        return 2

    load_dotenv(override=True)
    cfg, _ = load_config()
    supabase_url = os.environ["SUPABASE_URL"]
    service_role = os.environ["SUPABASE_SERVICE_ROLE_KEY"]

    out_dir = (
        Path(__file__).parent / "_validation_download" / args.investigation_id
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    with SupabaseCaseStore(cfg, supabase_url, service_role,
                            investigation_id=args.investigation_id) as store:
        # Briefs/ contents — the deliverables we care about.
        files = sorted(store.list_files("briefs"))
        print(f"briefs/ has {len(files)} file(s):")
        for f in files:
            print(f"  {f}")
        print()
        for f in files:
            full_bucket_path = f"briefs/{f}"
            # SupabaseCaseStore exposes read_text/read_bytes via the
            # store's underlying client; we'll use the _download helper.
            data = store._download(  # noqa: SLF001
                store.storage_prefix + full_bucket_path
            )
            try:
                local = _safe_local_path(out_dir, f)
            except ValueError as exc:
                print(f"  ! skipping {f}: {exc}", file=sys.stderr)
                continue
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(data)
            print(f"  ↓ {f}  ({len(data):,} bytes)")
    print(f"\nDownloaded to: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
