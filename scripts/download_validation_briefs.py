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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("investigation_id")
    args = parser.parse_args()

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
            local = out_dir / f
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(data)
            print(f"  ↓ {f}  ({len(data):,} bytes)")
    print(f"\nDownloaded to: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
