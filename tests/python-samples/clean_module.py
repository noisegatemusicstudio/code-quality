"""A small, clean module so the hosted scan runs Ruff on real Python."""

from __future__ import annotations


def total(values: list[int]) -> int:
    """Return the sum of the values."""
    result = 0
    for value in values:
        result += value
    return result
