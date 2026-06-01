"""v0.34 multi-chain perpetrator-pivot trace.

A victim trace on one chain can't see the perpetrator's cross-chain splits. The
pivot re-traces the consolidation HUB on every supported chain and merges the
findings. These tests pin the two pieces of new logic:

  * ``identify_pivot_hub`` — pick the largest-USD inbound recipient that is NOT
    the seed, NOT a labeled service (exchange/bridge/mixer/vault), preferring an
    EOA (the perp's pass-through wallet) over a terminal contract position;
  * ``run_pivot_multichain`` — re-trace the hub on every pivot chain EXCEPT its
    discovery chain, force value-trace ON, keep only chains where the hub was
    active, and survive per-chain failures.

Duck-typed stand-ins (SimpleNamespace) — no DB, no network.
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

from recupero.models import Chain
from recupero.trace import pivot_trace


def _label(category):
    return SimpleNamespace(category=category, type=None, name=category)


def _t(to, usd, *, chain=Chain.ethereum, depth=1, is_contract=False, label=None):
    return SimpleNamespace(
        to_address=to,
        from_address="0xseed",
        usd_value_at_tx=None if usd is None else Decimal(str(usd)),
        chain=chain,
        hop_depth=depth,
        counterparty=SimpleNamespace(is_contract=is_contract, label=label),
    )


def _case(transfers, seed="0xSEED000000000000000000000000000000000000"):
    return SimpleNamespace(seed_address=seed, transfers=transfers)


# --------------------------- identify_pivot_hub -----------------------------


def test_picks_largest_unlabeled_eoa_recipient() -> None:
    case = _case([
        _t("0xHUB0000000000000000000000000000000000aa", 3_120_000),  # hub (EOA)
        _t("0xsmall00000000000000000000000000000000bb", 1_000),      # dust
    ])
    hub = pivot_trace.identify_pivot_hub(case, min_usd=Decimal("50000"))
    assert hub is not None
    assert hub[0] == "0xHUB0000000000000000000000000000000000aa"
    assert hub[1] == Chain.ethereum


def test_excludes_the_seed() -> None:
    seed = "0xSEED000000000000000000000000000000000000"
    case = _case([_t(seed, 9_000_000)], seed=seed)
    assert pivot_trace.identify_pivot_hub(case) is None


def test_excludes_labeled_services() -> None:
    case = _case([
        _t("0xExchange00000000000000000000000000000011", 8_000_000,
           label=_label("Exchange: Binance hot wallet")),
        _t("0xbridge000000000000000000000000000000aa22", 7_000_000,
           label=_label("bridge")),
    ])
    # Both are services -> no hub.
    assert pivot_trace.identify_pivot_hub(case) is None


def test_prefers_eoa_over_contract_vault_even_if_smaller_depth_ties() -> None:
    """A terminal vault/contract position (e.g. Midas) must not be chosen over
    the perp's EOA pass-through hub, even with equal/large USD."""
    case = _case([
        _t("0xVAULT00000000000000000000000000000000c1", 3_120_000,
           depth=2, is_contract=True),                       # Midas-like vault
        _t("0xHUB0000000000000000000000000000000000aa", 3_120_000,
           depth=1, is_contract=False),                      # perp EOA hub
    ])
    hub = pivot_trace.identify_pivot_hub(case)
    assert hub[0] == "0xHUB0000000000000000000000000000000000aa"


def test_contract_hub_allowed_when_no_eoa_qualifies() -> None:
    """If the only qualifying hub is a contract (e.g. a Safe multisig), still
    return it rather than None."""
    case = _case([
        _t("0xSafe00000000000000000000000000000000aa33", 6_000_000,
           is_contract=True),
    ])
    hub = pivot_trace.identify_pivot_hub(case)
    assert hub is not None
    assert hub[0] == "0xSafe00000000000000000000000000000000aa33"


def test_below_min_usd_returns_none() -> None:
    case = _case([_t("0xsmall00000000000000000000000000000000bb", 10_000)])
    assert pivot_trace.identify_pivot_hub(case, min_usd=Decimal("50000")) is None


def test_unpriced_transfers_ignored() -> None:
    case = _case([_t("0xunpriced0000000000000000000000000000cc", None)])
    assert pivot_trace.identify_pivot_hub(case) is None


def _t_tok(to, amount, symbol, *, usd=None, depth=1, is_contract=False):
    return SimpleNamespace(
        to_address=to, from_address="0xseed",
        usd_value_at_tx=None if usd is None else Decimal(str(usd)),
        amount_decimal=Decimal(str(amount)),
        token=SimpleNamespace(symbol=symbol, contract=None),
        chain=Chain.ethereum, hop_depth=depth,
        counterparty=SimpleNamespace(is_contract=is_contract, label=None),
    )


def test_unpriced_exotic_token_hub_via_fallback() -> None:
    """v0.34.2 Zigha fix: the hub received 3.1M msyrupUSDp (UNPRICED Midas
    token) + only dust priced — no hub clears the priced floor, so the unpriced
    fallback identifies the hub by its large unpriced inbound. Without this the
    pivot never fires and the cross-chain branch is unreachable."""
    case = _case([
        _t_tok("0xHUB0000000000000000000000000000000000aa", 3_109_861, "msyrupUSDp"),
        _t("0xdust00000000000000000000000000000000bb22", 2_218),  # below floor
    ])
    hub = pivot_trace.identify_pivot_hub(case, min_usd=Decimal("50000"))
    assert hub is not None
    assert hub[0] == "0xHUB0000000000000000000000000000000000aa"


def test_unpriced_homoglyph_poison_not_a_hub() -> None:
    """A large UNPRICED homoglyph-poison inbound (Lisu "USDC") must NEVER be
    chosen as the pivot hub — we must not pivot on address-poisoning spam."""
    case = _case([
        _t_tok("0xpoison0000000000000000000000000000000c1", 9_999_999, "ꓴꓢꓓС"),
    ])
    assert pivot_trace.identify_pivot_hub(case) is None


def test_priced_hub_still_preferred_over_unpriced() -> None:
    """When a priced hub clears the floor, it wins — the unpriced fallback only
    engages when NO priced hub qualifies (behavior preserved)."""
    case = _case([
        _t("0xPRICED0000000000000000000000000000000d1", 5_000_000),
        _t_tok("0xUNPRICED00000000000000000000000000000d2", 9_999_999, "msyrupUSDp"),
    ])
    hub = pivot_trace.identify_pivot_hub(case, min_usd=Decimal("50000"))
    assert hub is not None
    assert hub[0] == "0xPRICED0000000000000000000000000000000d1"


# --------------------------- resolve_pivot_chains ---------------------------


def test_default_pivot_chains(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_PIVOT_CHAINS", raising=False)
    assert pivot_trace.resolve_pivot_chains() == list(pivot_trace.DEFAULT_PIVOT_CHAINS)


def test_env_override_pivot_chains(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_PIVOT_CHAINS", "arbitrum, base ,boguschain,arbitrum")
    chains = pivot_trace.resolve_pivot_chains()
    assert chains == [Chain.arbitrum, Chain.base]  # dedup + unknown skipped


def test_is_pivot_enabled(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_PIVOT_MULTICHAIN", raising=False)
    assert pivot_trace.is_pivot_enabled() is False
    monkeypatch.setenv("RECUPERO_PIVOT_MULTICHAIN", "1")
    assert pivot_trace.is_pivot_enabled() is True
    monkeypatch.setenv("RECUPERO_PIVOT_MULTICHAIN", "no")
    assert pivot_trace.is_pivot_enabled() is False


# --------------------------- run_pivot_multichain ---------------------------


def test_run_pivot_skips_hub_chain_and_collects_active(monkeypatch) -> None:
    calls: list[tuple] = []

    def fake_run_trace(**kw):
        calls.append((kw["chain"], kw.get("value_trace")))
        # hub active on arbitrum only; empty elsewhere
        active = kw["chain"] == Chain.arbitrum
        return SimpleNamespace(
            transfers=[object()] if active else [],
            seed_address=kw["seed_address"],
        )

    import recupero.trace.tracer as tracer_mod
    monkeypatch.setattr(tracer_mod, "run_trace", fake_run_trace)

    out = pivot_trace.run_pivot_multichain(
        hub_address="0xHUB", hub_chain=Chain.ethereum, incident_time=None,
        parent_case_id="CASE", config=None, env=None, case_dir=None,
        chains=[Chain.ethereum, Chain.arbitrum, Chain.base],
    )
    # ethereum (hub_chain) skipped; arbitrum + base attempted
    traced_chains = [c for c, _ in calls]
    assert Chain.ethereum not in traced_chains
    assert set(traced_chains) == {Chain.arbitrum, Chain.base}
    # value-trace forced on for every pivot call
    assert all(vt is True for _, vt in calls)
    # only the active chain (arbitrum) kept
    assert len(out) == 1
    assert out[0].seed_address == "0xHUB"


def test_run_pivot_survives_per_chain_failure(monkeypatch) -> None:
    def fake_run_trace(**kw):
        if kw["chain"] == Chain.base:
            raise RuntimeError("dead RPC on base")
        return SimpleNamespace(transfers=[object()], seed_address=kw["seed_address"])

    import recupero.trace.tracer as tracer_mod
    monkeypatch.setattr(tracer_mod, "run_trace", fake_run_trace)

    out = pivot_trace.run_pivot_multichain(
        hub_address="0xHUB", hub_chain=Chain.ethereum, incident_time=None,
        parent_case_id="CASE", config=None, env=None, case_dir=None,
        chains=[Chain.arbitrum, Chain.base, Chain.optimism],
    )
    # base failed but arbitrum + optimism succeeded — failure didn't abort.
    assert len(out) == 2
