"""Bitcoin chain support (v0.13.0).

Why Bitcoin still matters
-------------------------

Despite stablecoin laundering moving to Tron, Bitcoin remains the
dominant chain for:

  * Ransomware payments (still ~85% paid in BTC per Chainalysis 2024)
  * Darknet markets (Hydra successors, AlphaBay 2, Versus)
  * OG exchange withdrawals (cold-wallet vintages from 2013-2019)
  * State-actor cases (DPRK Lazarus, FSB Conti) where the cash-out
    legs are BTC even when the laundering legs are not

TRM Labs and Chainalysis both treat Bitcoin as their flagship chain
— they started there in 2014/2015. Without Bitcoin support, any
ransomware case dead-ends the moment the trace touches a ``1...``
or ``bc1...`` address.

UTXO vs account model
---------------------

Bitcoin's UTXO model is a fundamentally different shape from EVM:

  * EVM: ``addr A`` has a balance. Tx subtracts from A, adds to B.
    One tx = one (or a few) (from, to, amount) tuples.
  * UTXO: ``addr A`` doesn't have a balance — it has a set of UTXOs
    (unspent transaction outputs). To send, A signs a tx that spends
    one or more of its UTXOs as inputs and creates new UTXOs as
    outputs (one or more, often including a "change" output back
    to A). A tx can have N inputs and M outputs.

For tracing purposes we map UTXO → Transfer using a peel-chain
heuristic:

  * Inputs all "belong to" the same wallet (the common-input
    heuristic; Bitcoin's main pseudonymity weakness).
  * Outputs are classified:
      - "Change" output: typically the LARGER output, often to a
        fresh address — this stays with the sender wallet.
      - "Send" output: the smaller or round-number output — this
        is the actual transfer.
    Real-world ML classifiers do better than this, but for
    deterministic forensics we use the round-number / address-
    reuse heuristic.
  * We synthesize one Transfer record per (input_set → send_output)
    pair, with amount = send output value. The Transfer's
    ``from_address`` is the FIRST input address (canonical
    representative of the input set).

Limitations of v0.13.0
----------------------

  * No CoinJoin unwrapping (Wasabi, Samourai Whirlpool, JoinMarket).
    The peel-chain heuristic assumes a single sender per tx;
    CoinJoins violate that. Out-of-the-box, CoinJoin transactions
    get treated as "noise" — Transfers may be created with
    arbitrary from/to selection but the trace shouldn't be relied
    on past a CoinJoin.

  * No Lightning Network support. LN moves off-chain; on-chain
    we only see the channel open/close.

  * No Ordinals / BRC-20 inscription tracking. Forensic value
    is currently low — defer.

Reference docs:
  https://github.com/Blockstream/esplora/blob/master/API.md
  https://mempool.space/docs/api/rest
"""
