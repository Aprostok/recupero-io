"""Token honeypot / rug-pull risk scorer (v0.13.3).

Pure function `score_token` combines local bytecode heuristics +
optional GoPlus API enrichment. Returns a TokenRiskAssessment.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any

log = logging.getLogger(__name__)


# Bytecode patterns associated with known honeypot mechanisms.
# These are SUBSTRINGS of the runtime bytecode — matched
# case-insensitively. NOT a definitive proof on their own
# (sometimes legitimate contracts use the same patterns), but
# strongly suggestive when combined.
_HONEYPOT_BYTECODE_PATTERNS: dict[str, str] = {
    # 4-byte selector for `setBuyTax(uint256)` — tax rugs.
    "ed8e84e3": "setBuyTax mutator present",
    # Selector for `setSellTax(uint256)`.
    "31fb0ad7": "setSellTax mutator present",
    # `setMaxTxAmount(uint256)` — choke transfers post-launch.
    "1694505e": "setMaxTxAmount mutator present",
    # `addToBlacklist(address)` — buy-only token blacklist.
    "9d3bf8b3": "blacklist mutator present",
    # `_isExcludedFromFee` storage slot pattern (excluded list often
    # signals tax rug where insiders bypass).
    "5d098b38": "exclude-from-fee gate present",
}


@dataclass(frozen=True)
class TokenRiskSignal:
    """One observed risk indicator."""
    kind: str            # 'bytecode_pattern' | 'high_buy_no_sell' | 'rug_lp_removal' | 'goplus_honeypot'
    severity: int        # 1..4
    description: str
    evidence: str | None = None  # e.g. specific bytecode slice / tx hash


@dataclass
class TokenRiskAssessment:
    contract_address: str
    chain: str
    verdict: str         # 'honeypot' | 'high_risk_rug' | 'medium_risk' | 'low_risk' | 'clean'
    risk_score: int      # 0..10
    signals: list[TokenRiskSignal] = field(default_factory=list)
    investigator_note: str = ""
    data_sources_used: list[str] = field(default_factory=list)

    def to_json_safe(self) -> dict[str, Any]:
        return asdict(self)


def score_token(
    contract_address: str,
    *,
    chain: str = "ethereum",
    bytecode: str | None = None,
    tx_history_stats: dict[str, Any] | None = None,
    goplus_result: dict[str, Any] | None = None,
) -> TokenRiskAssessment:
    """Score a token contract for honeypot / rug-pull risk.

    Args:
      contract_address: the token's contract address.
      chain: 'ethereum' | 'bsc' | 'polygon' | etc.
      bytecode: optional contract bytecode (hex string, with or
        without 0x prefix). When provided, bytecode pattern
        matching contributes signals.
      tx_history_stats: optional dict with:
        - 'buy_count': int (transfers to a Uniswap router)
        - 'sell_success_count': int (successful sells observed)
        - 'lp_removed_within_24h_of_launch': bool
        - 'launch_block': int | None
      goplus_result: optional dict matching GoPlus API response —
        see https://docs.gopluslabs.io/reference/token-security-api.
        Caller is responsible for fetching it (we don't make HTTP
        calls in this pure-function path).

    Returns a TokenRiskAssessment.
    """
    signals: list[TokenRiskSignal] = []
    sources: list[str] = []

    # Z8-D: bytecode must be a string. Anything else (int, bytes,
    # list, object()) would crash ``.lower()`` / ``.removeprefix()``.
    if bytecode is not None and isinstance(bytecode, str):
        sources.append("bytecode_heuristic")
        signals.extend(_score_bytecode(bytecode))

    # Z8-A: tx_history_stats must be a dict. A string / list / int
    # / etc. would crash ``stats.get(...)``.
    if tx_history_stats is not None and isinstance(tx_history_stats, dict):
        sources.append("tx_history_heuristic")
        signals.extend(_score_tx_history(tx_history_stats))

    # Z8-E: goplus_result must be a dict. Anything else would crash
    # ``"result" in goplus`` (raises TypeError on int).
    if goplus_result is not None and isinstance(goplus_result, dict):
        sources.append("goplus_api")
        signals.extend(_score_goplus(goplus_result))

    # Combine signal severities into a score + verdict.
    risk_score, verdict = _aggregate(signals)
    note = _build_investigator_note(verdict, signals)

    return TokenRiskAssessment(
        contract_address=contract_address,
        chain=chain,
        verdict=verdict,
        risk_score=risk_score,
        signals=signals,
        investigator_note=note,
        data_sources_used=sources,
    )


# ---- Signal builders ---- #


def _score_bytecode(bytecode: str) -> list[TokenRiskSignal]:
    """Walk known honeypot-pattern selectors over the bytecode."""
    out: list[TokenRiskSignal] = []
    # `lstrip("0x")` is a classic bug: it strips a CHARACTER SET, not a prefix,
    # so any leading '0' or 'x' chars get eaten. A bytecode "0x000001f4..."
    # would become "1f4...", silently dropping leading-zero selectors that
    # honeypot detectors look for. `removeprefix` strips only the literal "0x".
    bc = bytecode.lower().removeprefix("0x")
    for selector, description in _HONEYPOT_BYTECODE_PATTERNS.items():
        if selector in bc:
            out.append(TokenRiskSignal(
                kind="bytecode_pattern",
                severity=2,
                description=description,
                evidence=f"selector={selector}",
            ))
    return out


def _safe_count(val: Any) -> int | None:
    """Coerce a tx-history count to a non-negative int.

    Z8-B / Z8-C hardening: attacker-controlled stats may inject
    NaN, +/-Infinity, non-numeric strings, or negative values. We:

      * return 0 for NaN / non-numeric / empty / None inputs (treat
        as "no data")
      * return a very large sentinel for +Infinity (treat as "very
        many")
      * return 0 for any negative value — negative counts are
        nonsense, and pre-fix ``sell_success == 0`` failed open for
        sell_success_count = -1, silently bypassing honeypot
        detection (FALSE-CLEAN on real honeypots).
    """
    if val is None or val is True or val is False:
        # Bool subclasses int but we shouldn't treat True/False as
        # counts — treat as no-data.
        if isinstance(val, bool):
            return int(val) if val else 0
        return 0
    # Float: reject NaN and Infinity explicitly.
    if isinstance(val, float):
        if val != val:  # NaN
            return 0
        if val == float("inf"):
            return 10**9  # treat as "very many"
        if val == float("-inf"):
            return 0
        try:
            n = int(val)
        except (ValueError, OverflowError):
            return 0
        return max(0, n)
    # Int: clamp negatives to 0.
    if isinstance(val, int):
        return max(0, val)
    # String / other: try parse, else 0.
    try:
        s = str(val).strip()
    except Exception:  # noqa: BLE001
        return 0
    if not s:
        return 0
    try:
        n = int(s)
    except (TypeError, ValueError):
        try:
            f = float(s)
        except (TypeError, ValueError):
            return 0
        if f != f or f == float("inf") or f == float("-inf"):
            return 0
        n = int(f)
    return max(0, n)


def _safe_launch_block_evidence(val: Any) -> str:
    """Render launch_block defensively for the evidence string.

    Z8-F hardening: launch_block may be attacker-controlled HTML.
    Embedding it verbatim in evidence (which can flow into HTML/PDF
    LE reports) is an XSS / formatting hazard. Coerce to int when
    possible, else render a cap-bounded plain-text repr that
    cannot contain "<script>".
    """
    if val is None:
        return "launch_block=None"
    if isinstance(val, bool):
        return f"launch_block={int(val)}"
    if isinstance(val, int):
        return f"launch_block={val}"
    if isinstance(val, float):
        if val != val or val == float("inf") or val == float("-inf"):
            return "launch_block=invalid"
        return f"launch_block={int(val)}"
    # String / anything else: try parse to int, else strip HTML and cap.
    try:
        n = int(str(val).strip())
        return f"launch_block={n}"
    except (TypeError, ValueError):
        # Strip dangerous tag markers and cap length so a hostile
        # input can't leak through to LE-bound PDFs.
        safe = (
            str(val)
            .replace("<", "")
            .replace(">", "")
            .replace("\x00", "")
        )[:32]
        return f"launch_block={safe!r}"


def _score_tx_history(stats: dict[str, Any]) -> list[TokenRiskSignal]:
    out: list[TokenRiskSignal] = []
    # Z8-B/C: defensive count parsing.
    buy_count = _safe_count(stats.get("buy_count", 0))
    sell_success = _safe_count(stats.get("sell_success_count", 0))

    # Strong honeypot indicator: many buys, no (or negative) sells.
    # Use `<= 0` so a hostile negative sell_success can't bypass the
    # `== 0` check that the pre-fix code used. `_safe_count` clamps
    # negatives to 0 already, but defense in depth.
    if buy_count >= 20 and sell_success <= 0:
        out.append(TokenRiskSignal(
            kind="high_buy_no_sell",
            severity=4,
            description=(
                f"{buy_count} buys observed; ZERO successful sells. "
                "Classic honeypot — funds are locked at the contract."
            ),
            evidence=f"buys={buy_count} sells_succeeded={sell_success}",
        ))
    elif buy_count >= 5 and sell_success <= 0:
        out.append(TokenRiskSignal(
            kind="high_buy_no_sell",
            severity=3,
            description=(
                f"{buy_count} buys, no successful sells. Possible "
                "honeypot — verify before clearing."
            ),
            evidence=f"buys={buy_count} sells_succeeded={sell_success}",
        ))

    # Rug-pull indicator: LP removed within 24h of launch.
    if stats.get("lp_removed_within_24h_of_launch"):
        out.append(TokenRiskSignal(
            kind="rug_lp_removal",
            severity=4,
            description=(
                "Liquidity pool removed within 24 hours of token "
                "launch — classic rug-pull pattern. Funds in the "
                "token are unrecoverable."
            ),
            # Z8-F: sanitize launch_block — could be hostile HTML.
            evidence=_safe_launch_block_evidence(stats.get("launch_block")),
        ))
    return out


def _score_goplus(goplus: dict[str, Any]) -> list[TokenRiskSignal]:
    """Extract signals from a GoPlus API response.

    GoPlus's ``token_security`` endpoint returns a dict keyed by
    lowercased contract address. The interesting fields:

      * is_honeypot: "1" | "0"
      * cannot_sell_all: "1" | "0"     — can't sell entire balance
      * transfer_pausable: "1" | "0"   — owner can pause transfers
      * hidden_owner: "1" | "0"        — ownership obfuscated
      * is_proxy: "1" | "0"            — proxy upgrade risk
      * is_blacklisted: "1" | "0"      — known blacklist mechanism

    We extract the boolean-flavored "1" responses and emit a
    signal per concerning flag.
    """
    out: list[TokenRiskSignal] = []
    # The actual response wraps the token dict inside ``result``
    # keyed by contract addr. Accept either flat or wrapped shapes.
    token_data: dict[str, Any] | None = None
    if "result" in goplus and isinstance(goplus["result"], dict):
        # Wrapped: pick the only entry
        token_data = next(iter(goplus["result"].values()), None)
    else:
        token_data = goplus
    if not isinstance(token_data, dict):
        return out

    def _flag(key: str) -> bool:
        return str(token_data.get(key, "")) == "1"

    if _flag("is_honeypot"):
        out.append(TokenRiskSignal(
            kind="goplus_honeypot",
            severity=4,
            description="GoPlus API classifies token as a honeypot.",
            evidence="is_honeypot=1",
        ))
    if _flag("cannot_sell_all"):
        out.append(TokenRiskSignal(
            kind="goplus_cannot_sell",
            severity=3,
            description=(
                "GoPlus: contract prevents selling the entire balance. "
                "Honeypot-adjacent pattern."
            ),
            evidence="cannot_sell_all=1",
        ))
    if _flag("transfer_pausable"):
        out.append(TokenRiskSignal(
            kind="goplus_pausable",
            severity=2,
            description=(
                "GoPlus: contract owner can pause all transfers. "
                "Rug-pull / freeze risk."
            ),
            evidence="transfer_pausable=1",
        ))
    if _flag("hidden_owner"):
        out.append(TokenRiskSignal(
            kind="goplus_hidden_owner",
            severity=3,
            description="GoPlus: contract ownership is obfuscated.",
            evidence="hidden_owner=1",
        ))
    if _flag("is_blacklisted"):
        out.append(TokenRiskSignal(
            kind="goplus_blacklist",
            severity=3,
            description=(
                "GoPlus: contract has a blacklist mechanism. "
                "Specific addresses can be silently blocked from "
                "transfers (honeypot-adjacent)."
            ),
            evidence="is_blacklisted=1",
        ))
    if _flag("is_proxy"):
        out.append(TokenRiskSignal(
            kind="goplus_proxy",
            severity=1,
            description=(
                "GoPlus: contract is a proxy — owner can upgrade "
                "the implementation. Rug-pull vector if owner is "
                "anonymous."
            ),
            evidence="is_proxy=1",
        ))
    return out


# ---- Aggregation ---- #


def _aggregate(signals: list[TokenRiskSignal]) -> tuple[int, str]:
    """Combine signals → (risk_score 0..10, verdict).

    Verdict ladder:
      * ANY severity=4 signal → honeypot or high_risk_rug
      * 2+ severity=3 signals → high_risk_rug
      * 1 severity=3 signal → medium_risk
      * Only severity 1-2 signals → low_risk
      * No signals → clean
    """
    if not signals:
        return 0, "clean"

    sev4 = [s for s in signals if s.severity >= 4]
    sev3 = [s for s in signals if s.severity == 3]
    sev2 = [s for s in signals if s.severity == 2]

    if sev4:
        # Distinguish honeypot vs rug.
        any_honeypot = any(
            s.kind in ("high_buy_no_sell", "goplus_honeypot")
            for s in sev4
        )
        any_rug = any(s.kind == "rug_lp_removal" for s in sev4)
        if any_honeypot:
            return 10, "honeypot"
        if any_rug:
            return 9, "high_risk_rug"
        return 9, "high_risk_rug"
    if len(sev3) >= 2:
        return 7, "high_risk_rug"
    if sev3:
        return 5, "medium_risk"
    if sev2:
        return 3, "low_risk"
    # Only sev1 signals
    return 1, "low_risk"


def _build_investigator_note(verdict: str, signals: list[TokenRiskSignal]) -> str:
    if verdict == "honeypot":
        return (
            "HONEYPOT — token contract prevents selling. Funds at this "
            "contract are unrecoverable on-chain. Recovery options are "
            "limited to legal recourse against the deployer."
        )
    if verdict == "high_risk_rug":
        return (
            "HIGH-RISK RUG — token contract has multiple rug-pull / "
            "liquidity-removal indicators. Funds at this contract are "
            "likely unrecoverable."
        )
    if verdict == "medium_risk":
        kinds = ", ".join(sorted({s.kind for s in signals}))
        return (
            f"MEDIUM-RISK — one strong concerning signal ({kinds}). "
            "Verify with manual contract review before recommending."
        )
    if verdict == "low_risk":
        return (
            "LOW-RISK — weak signals only. Continue with normal "
            "trace / freeze workflow."
        )
    return "CLEAN — no detected honeypot or rug-pull indicators."


__all__ = (
    "TokenRiskSignal",
    "TokenRiskAssessment",
    "score_token",
)
