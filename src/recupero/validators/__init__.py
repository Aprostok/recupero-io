"""Output-integrity validators for Recupero case artifacts.

Per Jacob's v0.20.15 review (Part 4): structural invariants that
must hold for every customer-facing case output, regardless of the
case's specific shape. The validator catches CATEGORIES of bugs
rather than individual instances — which is the discipline shift
needed to break the "headline fix, new structural bug" cycle.

Public surface:

    from recupero.validators.output_integrity import (
        validate_case_output, ValidationResult, Violation,
    )

    result = validate_case_output(case_output_dir)
    if not result.ok:
        for v in result.violations:
            print(f"{v.severity}: {v.check} — {v.detail}")
"""

from recupero.validators.output_integrity import (
    ValidationResult,
    Violation,
    validate_case_output,
)

__all__ = ("ValidationResult", "Violation", "validate_case_output")
