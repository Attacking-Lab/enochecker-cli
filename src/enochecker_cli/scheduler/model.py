from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence


@dataclass(frozen=True, slots=True)
class Component:
    head: int
    dependents: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class Instance:
    M: int
    K: int
    C: int
    fanouts: tuple[int, ...]

    def __init__(self, M: int, K: int, C: int, fanouts: Iterable[int]):
        fanouts_tuple = tuple(fanouts)
        if not isinstance(M, int) or not isinstance(K, int) or not isinstance(C, int):
            raise TypeError("M, K, and C must be integers")
        if M <= 0 or K <= 0 or C <= 0:
            raise ValueError("M, K, and C must be positive")
        if K > M:
            raise ValueError("K cannot exceed M")
        if not fanouts_tuple:
            raise ValueError("an instance must contain at least one component")
        if any(not isinstance(d, int) or d < 0 for d in fanouts_tuple):
            raise ValueError("fanouts must be non-negative integers")
        object.__setattr__(self, "M", M)
        object.__setattr__(self, "K", K)
        object.__setattr__(self, "C", C)
        object.__setattr__(self, "fanouts", fanouts_tuple)

    @property
    def N(self) -> int:
        return len(self.fanouts) + sum(self.fanouts)

    @property
    def legal_start_count(self) -> int:
        return self.M - self.K + 1

    @property
    def wave_count(self) -> int:
        return self.M // self.K

    @property
    def components(self) -> tuple[Component, ...]:
        result: list[Component] = []
        task = 0
        for degree in self.fanouts:
            result.append(Component(task, tuple(range(task + 1, task + degree + 1))))
            task += degree + 1
        return tuple(result)

    def is_valid(self, starts: Sequence[int]) -> bool:
        if len(starts) != self.N:
            return False
        last_start = self.M - self.K
        if any(
            not isinstance(start, int) or start < 0 or start > last_start
            for start in starts
        ):
            return False
        for component in self.components:
            head_start = starts[component.head]
            if any(
                starts[dependent] < head_start + self.K
                for dependent in component.dependents
            ):
                return False
        changes = [0] * (self.M + 1)
        for start in starts:
            changes[start] += 1
            changes[start + self.K] -= 1
        running = 0
        for time in range(self.M):
            running += changes[time]
            if running > self.C:
                return False
        return True

    def assert_valid(self, starts: Sequence[int]) -> None:
        if not self.is_valid(starts):
            raise ValueError("invalid schedule")
