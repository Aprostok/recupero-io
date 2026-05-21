"""recupero-ops correlation-stats

Reports summary stats from the cross-case correlation index
(``public.address_observations``). Useful for monitoring the
compounding-moat capability:

  * How many addresses have we ever recorded?
  * How many recidivist addresses (appeared in 2+ cases)?
  * Top-10 addresses by case appearance count?
  * How many of those are OFAC- / drainer- / mixer-attributed?

Recommended cadence: monthly review. The numbers should grow
strictly upward as more cases land.

Output:
  - Prints a 3-section summary report
  - Exit code:
      0 = success
      1 = DB unreachable / query failed
"""

from __future__ import annotations

import logging
from typing import Any

from recupero._common import db_connect

log = logging.getLogger(__name__)


def run(*, dsn: str) -> int:
    """Print correlation index stats. Returns exit code."""
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError:
        print("ERROR: psycopg not installed.")
        return 1

    print("Querying public.address_observations …")
    print()

    try:
        with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
            # 1. Aggregate counts.
            cur.execute("""
                    SELECT
                        COUNT(*)                              AS total_rows,
                        COUNT(DISTINCT (address, chain))      AS distinct_addresses,
                        COUNT(DISTINCT case_id)               AS distinct_cases,
                        COUNT(*) FILTER (WHERE is_ofac_exposed)       AS ofac_observations,
                        COUNT(*) FILTER (WHERE is_mixer_exposed)      AS mixer_observations,
                        COUNT(*) FILTER (WHERE is_drainer_attributed) AS drainer_observations
                      FROM public.address_observations;
                """)
            summary = cur.fetchone() or {}

            # 2. Recidivist addresses (appeared in 2+ cases).
            cur.execute("""
                    SELECT
                        address, chain,
                        COUNT(DISTINCT case_id) AS prior_cases,
                        BOOL_OR(is_ofac_exposed)       AS ever_ofac,
                        BOOL_OR(is_mixer_exposed)      AS ever_mixer,
                        BOOL_OR(is_drainer_attributed) AS ever_drainer,
                        SUM(usd_flowed)                AS total_usd
                      FROM public.address_observations
                     WHERE case_id IS NOT NULL
                     GROUP BY address, chain
                    HAVING COUNT(DISTINCT case_id) >= 2
                     ORDER BY prior_cases DESC, total_usd DESC NULLS LAST
                     LIMIT 10;
                """)
            top_recidivists: list[dict[str, Any]] = list(cur.fetchall())

            # 3. Recidivist counts.
            cur.execute("""
                    SELECT COUNT(*) AS recidivist_count
                      FROM (
                          SELECT address, chain
                            FROM public.address_observations
                           WHERE case_id IS NOT NULL
                           GROUP BY address, chain
                          HAVING COUNT(DISTINCT case_id) >= 2
                      ) AS r;
                """)
            rec_row = cur.fetchone() or {}
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: DB query failed — {exc}")
        return 1

    # ----- Render report ----- #

    print("=== Cross-case correlation index ===")
    print()
    print(f"  Total observation rows:    {summary.get('total_rows', 0):,}")
    print(f"  Distinct addresses seen:   {summary.get('distinct_addresses', 0):,}")
    print(f"  Distinct cases covered:    {summary.get('distinct_cases', 0):,}")
    print(f"  Recidivist addresses (≥2 cases): "
          f"{rec_row.get('recidivist_count', 0):,}")
    print()
    print(f"  OFAC-exposed observations:    {summary.get('ofac_observations', 0):,}")
    print(f"  Mixer-exposed observations:   {summary.get('mixer_observations', 0):,}")
    print(f"  Drainer-attributed observations: "
          f"{summary.get('drainer_observations', 0):,}")
    print()

    print("=== Top-10 recidivist addresses ===")
    print()
    if not top_recidivists:
        print("  (none yet — every address recorded has appeared in only 1 case)")
    else:
        for i, row in enumerate(top_recidivists, start=1):
            addr = row["address"]
            chain = row["chain"]
            flags = []
            if row.get("ever_ofac"):
                flags.append("OFAC")
            if row.get("ever_drainer"):
                flags.append("DRAINER")
            if row.get("ever_mixer"):
                flags.append("MIXER")
            flag_str = f" [{','.join(flags)}]" if flags else ""
            usd = row.get("total_usd")
            usd_str = f"${usd:,.2f}" if usd is not None else "—"
            short_addr = addr[:10] + "…" + addr[-6:] if len(addr) > 20 else addr
            print(
                f"  {i:2d}. {short_addr:25s} {chain:10s} "
                f"{row['prior_cases']} cases  {usd_str}{flag_str}"
            )
    print()
    print(
        "These addresses recycle across cases — auto-flagged in the "
        "CROSS_CASE_CORRELATION brief section. Subpoena the prior-case "
        "files when one of them shows up in a new investigation."
    )
    return 0


__all__ = ("run",)
