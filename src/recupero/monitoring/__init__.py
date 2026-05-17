"""Live address-monitoring + webhook alerts (v0.13.2).

TRM Labs' KYT (Know Your Transaction) and Chainalysis Kryptos both
sell this as a separate product: "tell me when address X moves funds."
Useful for:

  * Freeze workflow: alert the moment a frozen-asset candidate
    moves any balance — so the operator can re-trace before the
    funds disperse.

  * Compliance: exchange compliance teams monitor sanctioned
    addresses for inflows so they can pre-emptively block deposits.

  * Recovery: when a stolen-fund trace lands at a CEX deposit
    address, alert if the address sends any tokens elsewhere
    (perpetrator may withdraw before the exchange freezes).

How it works
------------

Operators create *subscriptions* in ``public.monitoring_subscriptions``.
Each subscription specifies:

  * An address + chain to watch
  * A trigger type (any_movement / movement_above_usd / balance_drop /
    ofac_contact)
  * A webhook URL to POST when the trigger fires
  * Optional HMAC-SHA256 signing key

The worker's ``monitor_tick.py`` stage polls every active subscription
on a fixed cron interval (default: every 5 minutes), comparing the
latest on-chain tx to the cached ``last_observed_tx_hash``. New
activity that matches the trigger fires a webhook POST.

Webhook payload format
----------------------

POST to webhook_url with JSON body::

    {
      "subscription_id": "...",
      "trigger_type": "movement_above_usd",
      "address": "0x...",
      "chain": "ethereum",
      "alert": {
        "tx_hash": "0x...",
        "block_time": "2026-05-17T12:34:56Z",
        "amount_usd": "12500.00",
        "counterparty": "0x...",
        "counterparty_label": "Binance Hot Wallet",
        "explorer_url": "https://etherscan.io/tx/0x..."
      },
      "fired_at": "2026-05-17T12:34:58Z"
    }

If webhook_secret is set, the request includes header
``X-Recupero-Signature: sha256=<hex>`` where the HMAC-SHA256 is
computed over the raw body using the secret. Receivers should
verify before trusting the payload.
"""
