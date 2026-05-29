"""Web-layer surfaces for Recupero (v0.32.1).

This package holds the operator-facing HTML UIs that wrap the
existing JSON APIs. The first inhabitant is ``templates/review_gate.html``
— a minimal operator console for the v0.32 brief-review queue
(see ``recupero.dispatcher.review_api`` for the API surface). Pre-
v0.32.1 the only way to action a pending brief was to ``curl`` the
``/v1/reviews/queue`` and ``/v1/reviews/{id}/approve|reject`` endpoints
by hand, which the cross-cutting audit (Jacob §4) flagged as a
deploy-blocker for operators on-call at 2 AM.

Keep this dir vanilla: no JS frameworks, no build step, no asset
pipeline. Templates are rendered by Jinja2 from the API's existing
Environment. Anything more elaborate belongs in a separate
single-page-app repo.
"""

from __future__ import annotations

__all__: list[str] = []
