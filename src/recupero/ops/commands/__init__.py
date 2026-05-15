"""Per-command implementations for recupero-ops.

Each module exposes a ``run(...)`` function that returns the exit
code for the operator's shell. Modules are imported lazily by
``recupero.ops.cli`` so importing the cli package itself is fast.
"""
