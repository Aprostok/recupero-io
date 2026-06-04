"""Keyed (paid) attribution-data providers.

Unlike the free bulk-harvest fetchers in ``labels.auto_ingest`` (which pull
LISTS of labeled addresses), commercial attribution vendors (MistTrack, Arkham,
TRM, etc.) are query-BY-ADDRESS: you hand them an address, they return that
address's entity label + risk. So they belong here as ENRICHMENT providers —
called on the high-value unlabeled addresses surfaced by
``trace.attribution_coverage`` (the labeling targets), resolving each into a
``CandidateLabel`` for the existing review→promote pipeline.

Every provider is:
  * env-gated on its own API key — returns nothing when the key is unset, so a
    deploy without the key behaves exactly as before;
  * best-effort — any network / shape / auth failure degrades to ``None`` /
    ``[]``, never raises into a trace or the daily cron;
  * doctrine-safe — output lands as LOW-confidence candidates for operator
    review, never auto-promoted, never fabricated.
"""
