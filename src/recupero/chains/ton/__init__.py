"""TON (The Open Network) chain support.

TON is a high-value missing chain for fund tracing — it is a major DPRK / scam
off-ramp, and USDT-TON (a Jetton) is the dominant stablecoin-laundering rail on
the network, mirroring USDT-TRC20 on Tron.

Module layout mirrors the Tron module:
  * ``address`` — TON address codec (raw ``0:hex`` ↔ user-friendly base64url
    with workchain tag + CRC16). Canonical form for tracing is the
    bounce-flag-agnostic raw form.
  * ``client`` — TonClient over the public TON Center API (v2 for native-TON
    transactions, v3 for decoded Jetton transfers).
  * ``adapter`` — TonAdapter (native TON + Jetton outflows, evidence receipts).

Data shapes were captured live from toncenter.com before implementation; the
address codec is verified against live raw↔friendly vector pairs.
"""
