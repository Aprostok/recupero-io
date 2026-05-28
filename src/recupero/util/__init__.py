"""Shared utility helpers used across the recupero codebase.

Modules here are intended to be small, dependency-light, and safe to import
from anywhere (no chain adapters, no DB clients, no Jinja). If you find
yourself adding something heavyweight, put it in a more specific package.
"""

from recupero.util.addr_format import short_address

__all__ = ["short_address"]
