"""Private staged-prefix queue shared by durable batch writers."""

from __future__ import annotations

from typing import Generic, TypeVar


_T = TypeVar("_T")


class _StagedBatch(Generic[_T]):
    """Ordered uncommitted items with one stable staged prefix."""

    def __init__(self) -> None:
        self._items: list[_T] = []
        self._staged_size = 0

    def append(self, item: _T) -> None:
        self._items.append(item)

    def stage(self) -> tuple[_T, ...]:
        if self._staged_size == 0:
            self._staged_size = len(self._items)
        return tuple(self._items[: self._staged_size])

    def commit(self) -> None:
        if self._staged_size == 0:
            raise RuntimeError("no staged batch to commit")
        del self._items[: self._staged_size]
        self._staged_size = 0

    @property
    def pending_count(self) -> int:
        return len(self._items)
