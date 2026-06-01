"""Answer-key-free correctness checks for cross-chain bridge hops (v0.34).

A single-chain trace dead-ends at a bridge; the bridge-pairing oracle
(``recupero.trace.bridge_pairings``) confirms the on-chain destination by the
protocol's own cross-chain id matched on BOTH chains — cryptographic proof that
needs no human answer key. These validators let a produced case **self-audit**
those confirmed hops, enforcing the two properties a confirmed cross-chain edge
must satisfy:

  1. **No ``high`` without proof** (``cross_chain_edge_confirmed``). A cross-chain
     edge may be ``high`` confidence ONLY when it carries the cryptographic proof
     — a matched ``order_id`` AND the destination tx that referenced it. A record
     claiming ``high`` without both is the cardinal forensic error (a fabricated
     destination) and is reported ``critical``.

  2. **Value conservation** (``cross_chain_value_conserved``). For protocols that
     deliver the SAME asset on both chains, the destination amount must lie within
     ``[src·(1 − maxFee), src]`` — a bridge takes a fee, it never adds value. A
     confirmed pairing that violates this is a likely mispairing / skimming and is
     reported ``high``. Cross-asset protocols (DLN give≠take, CCIP arbitrary
     payload, Synapse …AndSwap) are NOT checked — the amounts aren't comparable,
     and we never fabricate a violation from an apples-to-oranges comparison.

The confirmation records are the dicts the tracer writes to
``case.config_used["bridge_confirmations"]`` (see
``tracer._continue_past_dex_and_bridges``); each carries protocol, order_id,
source/destination chain+tx, recipient, raw_amount, src_raw_amount, same_asset,
confidence, basis. Everything here is pure and unit-testable — no I/O.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any

from recupero.validators.output_integrity import Violation


def _coerce_int(value: Any) -> int | None:
    """Best-effort int from str/int/None (raw amounts are stored as strings so
    arbitrarily large token amounts survive JSON). None on anything else."""
    if value is None:
        return None
    if isinstance(value, bool):  # bool is an int subclass — reject explicitly
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def validate_bridge_confirmations(
    confirmations: Iterable[Any] | None,
    *,
    get_spec: Callable[[str | None], Any] | None = None,
) -> list[Violation]:
    """Self-audit the case's cryptographically-confirmed cross-chain edges.

    Returns a list of :class:`Violation` (empty when every confirmation is
    sound). Never raises on a malformed record — a non-mapping entry is reported
    as a ``warning`` and skipped. ``get_spec`` defaults to
    ``bridge_pairings.get_pair_spec`` (injectable for tests).
    """
    if get_spec is None:
        from recupero.trace.bridge_pairings import get_pair_spec as get_spec
    from recupero.trace.bridge_pairings import bridge_conservation_ok

    violations: list[Violation] = []
    for i, c in enumerate(confirmations or []):
        if not isinstance(c, Mapping):
            violations.append(Violation(
                check="cross_chain_confirmation_shape",
                severity="warning",
                detail=f"confirmation #{i} is not a mapping: {type(c).__name__}",
            ))
            continue

        proto = c.get("protocol") or "?"
        conf = str(c.get("confidence") or "").lower()
        oid = c.get("order_id")
        dst_tx = c.get("dst_tx")
        label = (
            f"{proto} {c.get('source_chain') or '?'}→{c.get('dst_chain') or '?'} "
            f"(src_tx {str(c.get('source_tx'))[:12]}…)"
        )

        # 1) No high-confidence cross-chain edge without cryptographic proof.
        if conf == "high" and (not oid or not dst_tx):
            missing = "order_id" if not oid else "destination tx"
            violations.append(Violation(
                check="cross_chain_edge_confirmed",
                severity="critical",
                detail=(
                    f"{label}: claims HIGH confidence but is missing its "
                    f"cryptographic proof ({missing} absent). A cross-chain edge "
                    f"may be HIGH only when the protocol's order-id is matched on "
                    f"BOTH chains — otherwise it is an unproven (fabricated) "
                    f"destination."
                ),
            ))

        # 2) Same-asset value conservation.
        spec = get_spec(proto)
        same_asset = c.get("same_asset")
        if same_asset is None and spec is not None:
            same_asset = getattr(spec, "same_asset", False)
        if spec is not None and same_asset:
            src = _coerce_int(c.get("src_raw_amount"))
            dst = _coerce_int(c.get("raw_amount"))
            ok, reason = bridge_conservation_ok(src, dst, spec.max_fee_pct)
            if not ok:
                violations.append(Violation(
                    check="cross_chain_value_conserved",
                    severity="high",
                    detail=f"{label}: {reason}",
                ))

    return violations


def render_bridge_confirmation_report(
    confirmations: Iterable[Any] | None,
) -> str:
    """Render the human-auditable per-case bridge-confirmation report — the
    proof a reviewer reads INSTEAD of an answer key. Markdown; deterministic."""
    confs = [c for c in (confirmations or []) if isinstance(c, Mapping)]
    lines = ["# Cross-chain bridge confirmation report", ""]
    if not confs:
        lines.append(
            "No cryptographically-confirmed cross-chain destinations "
            "(no supported bridge hop was confirmed, or confirmation was off)."
        )
        return "\n".join(lines)

    lines.append(
        f"{len(confs)} cross-chain destination(s) CONFIRMED by the protocol's own "
        f"order-id matched on both chains (cryptographic proof — no answer key):"
    )
    lines.append("")
    for c in confs:
        amt = c.get("raw_amount")
        src_amt = c.get("src_raw_amount")
        lines.append(
            f"- **{c.get('protocol', '?')}** "
            f"{c.get('source_chain', '?')} → {c.get('dst_chain', '?')}"
        )
        lines.append(f"  - order-id: `{c.get('order_id', '?')}`")
        lines.append(f"  - source tx: `{c.get('source_tx', '?')}`")
        lines.append(f"  - destination tx: `{c.get('dst_tx', '?')}`")
        lines.append(f"  - recipient: `{c.get('recipient') or '(unresolved)'}`")
        if src_amt is not None:
            lines.append(f"  - source raw amount: {src_amt}")
        lines.append(
            f"  - destination raw amount: {amt if amt is not None else '(unknown)'}"
        )
        lines.append(f"  - confidence: {c.get('confidence', '?')}")
        if c.get("basis"):
            lines.append(f"  - basis: {c.get('basis')}")
    return "\n".join(lines)


__all__ = (
    "validate_bridge_confirmations",
    "render_bridge_confirmation_report",
)
