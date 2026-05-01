"""State machine for the investigations queue.

The worker only writes status values from this module. Anything that doesn't
match a name here is a bug or out-of-band intervention by the admin UI.
"""

from __future__ import annotations

from typing import Final


# ----- Statuses ----- #
# Wire values match the public.investigations.status_check constraint in
# Jacob's admin UI repo:
#   pending, claimed, tracing, finding_freeze_targets, drafting_editorial,
#   awaiting_review, review_approved, emitting, building_package, complete, failed
# Constant names below are the worker's internal vocabulary; values are the
# wire strings. Don't rename a value without coordinating with Jacob.

QUEUED: Final = "pending"                          # UI inserted; waiting for a worker
CLAIMED: Final = "claimed"                         # Worker locked it; about to start

# Active stages
TRACING: Final = "tracing"
LISTING_FREEZE_TARGETS: Final = "finding_freeze_targets"
EDITORIAL_DRAFTING: Final = "drafting_editorial"
EMITTING: Final = "emitting"

# Pause point: human review of brief_editorial.json
REVIEW_REQUIRED: Final = "awaiting_review"
REVIEW_APPROVED: Final = "review_approved"

# Reserved: JS builder step that runs AFTER emit_brief writes freeze_brief.json.
# The worker doesn't perform this stage today (Jacob's UI/JS pipeline owns it),
# but the constant exists so we don't accidentally collide with the wire value.
BUILDING_PACKAGE: Final = "building_package"

# Terminal
COMPLETED: Final = "complete"
FAILED: Final = "failed"


# ----- Sets used by claim SQL and the pipeline ----- #

# A worker may pick up a row in any of these statuses.
CLAIMABLE_STATUSES: frozenset[str] = frozenset({QUEUED, REVIEW_APPROVED})

# A row in any of these is being worked on by some worker. If its heartbeat
# is stale, another worker may steal it.
ACTIVE_STATUSES: frozenset[str] = frozenset({
    CLAIMED,
    TRACING,
    LISTING_FREEZE_TARGETS,
    EDITORIAL_DRAFTING,
    EMITTING,
})

TERMINAL_STATUSES: frozenset[str] = frozenset({COMPLETED, FAILED})


# ----- Stage labels (for current_stage column / logs) ----- #
# These match the active statuses 1:1 today. Keeping them as a separate set
# makes future progress-only updates (e.g. "tracing:depth=2:done=44%") possible
# without touching the state machine.

STAGE_LABELS: frozenset[str] = ACTIVE_STATUSES
