"""Token-gated customer portal at ``/portal/<token>``.

Three responsibilities:

  * ``tokens`` — generate + verify long-lived bearer tokens that map
    to a ``cases.id``. Backed by ``public.case_tokens``.
  * ``server`` — HTTP handler that the worker's _health_server.py
    delegates to for any path starting with ``/portal``. Returns
    Jinja-rendered HTML.
  * ``templates`` — Jinja2 templates for the status page, the
    engagement-signature flow, and a 404/expired fallback.

Why a separate package (not under worker/)? Two reasons:

  1. The portal serves external traffic (the victim's browser), not
     the operator's admin UI. Keeping it isolated makes the surface
     area easy to audit — every input path lives in one folder.
  2. Future deploy split: we may eventually pull this out into its
     own Railway service so the worker's queue traffic doesn't
     compete with portal page loads. A clean package boundary
     makes that lift trivial.
"""

from __future__ import annotations

__all__: tuple[str, ...] = ()
