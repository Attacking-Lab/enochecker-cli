from __future__ import annotations

import math
import random
import threading
import time
from dataclasses import dataclass
from typing import Sequence

from .model import Component, Instance


@dataclass(frozen=True, slots=True)
class NodeTypeProfile:
    role: str
    edge_count: int
    edge_direction: str
    star_fanout: int
    node_count: int
    profile: tuple[float, ...]


@dataclass(frozen=True, slots=True)
class ProfileReport:
    profile: tuple[float, ...]
    node_type_profiles: tuple[NodeTypeProfile, ...]
    max_probability: float
    flat_floor: float
    unevenness: float
    worst_task_min_entropy_bits: float
    pool_size: int
    precomputation_seconds: float


class RandomizedScheduler:
    def __init__(
        self,
        instance: Instance,
        *,
        pool_size: int = 256,
        candidates_per_entry: int = 3,
        seed: int | None = None,
        rng: random.Random | None = None,
    ) -> None:
        if pool_size <= 0:
            raise ValueError("pool_size must be positive")
        if candidates_per_entry <= 0:
            raise ValueError("candidates_per_entry must be positive")
        self.instance = instance
        self._components = instance.components
        # Vendored addition: a seeded schedule is a predictable schedule, so
        # production draws come from a CSPRNG rather than Mersenne Twister.
        self._rng = rng if rng is not None else random.Random(seed)
        self._lock = threading.Lock()
        started = time.perf_counter()
        self._pool, self._start_totals = self._build_pool(
            pool_size, candidates_per_entry
        )
        self._precomputation_seconds = time.perf_counter() - started
        self._groups = self._group_components()

    def draw(self) -> tuple[int, ...]:
        with self._lock:
            source = self._pool[self._rng.randrange(len(self._pool))]
            result = [0] * self.instance.N
            for components in self._groups.values():
                sources = list(components)
                self._rng.shuffle(sources)
                for destination, origin in zip(components, sources):
                    result[destination.head] = source[origin.head]
                    dependent_starts = [source[task] for task in origin.dependents]
                    self._rng.shuffle(dependent_starts)
                    for task, start in zip(destination.dependents, dependent_starts):
                        result[task] = start
            return tuple(result)

    def report(self) -> ProfileReport:
        denominator = len(self._pool) * self.instance.N
        profile = tuple(total / denominator for total in self._start_totals)
        return ProfileReport(
            profile=profile,
            node_type_profiles=self._node_type_profiles(),
            max_probability=max(profile),
            flat_floor=1.0 / self.instance.legal_start_count,
            unevenness=_profile_unevenness(profile),
            worst_task_min_entropy_bits=self._worst_task_min_entropy(),
            pool_size=len(self._pool),
            precomputation_seconds=self._precomputation_seconds,
        )

    @property
    def schedules(self) -> tuple[tuple[int, ...], ...]:
        return tuple(self._pool)

    def _build_pool(
        self,
        pool_size: int,
        candidates_per_entry: int,
    ) -> tuple[list[tuple[int, ...]], list[int]]:
        totals = [0] * self.instance.legal_start_count
        pool: list[tuple[int, ...]] = []
        for entry in range(pool_size):
            candidates: list[
                tuple[tuple[int, int, int], tuple[int, ...], list[int]]
            ] = []
            for _ in range(candidates_per_entry):
                schedule = self._candidate()
                counts = [0] * self.instance.legal_start_count
                for start in schedule:
                    counts[start] += 1
                combined = [old + new for old, new in zip(totals, counts)]
                peak = max(combined)
                square = sum(value * value for value in combined)
                spread = max(combined) - min(combined)
                candidates.append(((peak, square, spread), schedule, counts))
            _, selected, counts = min(candidates, key=lambda candidate: candidate[0])
            pool.append(selected)
            for slot, count in enumerate(counts):
                totals[slot] += count
        return pool, totals

    def _candidate(self) -> tuple[int, ...]:
        waves = self._hu_waves()
        predecessors, successors = self._constraint_dag(waves)
        earliest = [0] * self.instance.N
        for wave in waves:
            for task in wave:
                if predecessors[task]:
                    earliest[task] = max(
                        earliest[predecessor] + self.instance.K
                        for predecessor in predecessors[task]
                    )
        last_start = self.instance.M - self.instance.K
        latest = [last_start] * self.instance.N
        for wave in reversed(waves):
            for task in wave:
                if successors[task]:
                    latest[task] = min(
                        latest[successor] - self.instance.K
                        for successor in successors[task]
                    )
        for task in range(self.instance.N):
            if earliest[task] > latest[task]:
                raise RuntimeError("internal constraint DAG is infeasible")
        return self._sample_interpolated(successors, earliest, latest)

    def _sample_interpolated(
        self,
        successors: Sequence[Sequence[int]],
        earliest: Sequence[int],
        latest: Sequence[int],
    ) -> tuple[int, ...]:
        parent = list(range(self.instance.N))

        def root(task: int) -> int:
            while parent[task] != task:
                parent[task] = parent[parent[task]]
                task = parent[task]
            return task

        for task in range(self.instance.N):
            for successor in successors[task]:
                left = root(task)
                right = root(successor)
                if left != right:
                    parent[right] = left
        resolution = 1 << 53
        quantiles: dict[int, int] = {}
        starts = [0] * self.instance.N
        for task in range(self.instance.N):
            component = root(task)
            if component not in quantiles:
                quantiles[component] = self._rng.randrange(resolution)
            quantile = quantiles[component]
            width = latest[task] - earliest[task] + 1
            starts[task] = earliest[task] + quantile * width // resolution
        return tuple(starts)

    def _hu_waves(self) -> list[list[int]]:
        remaining = list(self.instance.fanouts)
        component_by_dependent = [-1] * self.instance.N
        leaves: list[int] = []
        ready_heads: list[int] = []
        for component_index, component in enumerate(self._components):
            if component.dependents:
                for dependent in component.dependents:
                    component_by_dependent[dependent] = component_index
                    leaves.append(dependent)
            else:
                ready_heads.append(component.head)
        self._rng.shuffle(leaves)
        self._rng.shuffle(ready_heads)
        reverse_waves: list[list[int]] = []
        while leaves or ready_heads:
            leaf_count = min(self.instance.C, len(leaves))
            chosen_leaves = [leaves.pop() for _ in range(leaf_count)]
            room = self.instance.C - leaf_count
            chosen_heads = [
                ready_heads.pop() for _ in range(min(room, len(ready_heads)))
            ]
            reverse_waves.append(chosen_leaves + chosen_heads)
            newly_ready: list[int] = []
            for dependent in chosen_leaves:
                component_index = component_by_dependent[dependent]
                remaining[component_index] -= 1
                if remaining[component_index] == 0:
                    newly_ready.append(self._components[component_index].head)
            self._rng.shuffle(newly_ready)
            ready_heads.extend(newly_ready)
        waves = list(reversed(reverse_waves))
        if len(waves) > self.instance.wave_count:
            raise ValueError("the instance is infeasible")
        return waves

    def _constraint_dag(
        self,
        waves: Sequence[Sequence[int]],
    ) -> tuple[list[list[int]], list[list[int]]]:
        predecessors: list[list[int]] = [[] for _ in range(self.instance.N)]
        successors: list[list[int]] = [[] for _ in range(self.instance.N)]
        edges: set[tuple[int, int]] = set()
        original_predecessor = [-1] * self.instance.N
        for component in self._components:
            for dependent in component.dependents:
                edges.add((component.head, dependent))
                original_predecessor[dependent] = component.head
        wave_of = [0] * self.instance.N
        for wave_index, wave in enumerate(waves):
            for task in wave:
                wave_of[task] = wave_index
        match_target = max(0, self.instance.N - self.instance.C)
        left_buckets = [list(wave) for wave in waves]
        for bucket in left_buckets:
            self._rng.shuffle(bucket)
        left_used = [False] * self.instance.N
        matches = 0
        for right_wave, wave in enumerate(waves):
            right_tasks = list(wave)
            self._rng.shuffle(right_tasks)
            for right in right_tasks:
                if matches == match_target:
                    break
                highest_left_wave = right_wave - 1
                while highest_left_wave >= 0:
                    while (
                        left_buckets[highest_left_wave]
                        and left_used[left_buckets[highest_left_wave][-1]]
                    ):
                        left_buckets[highest_left_wave].pop()
                    if left_buckets[highest_left_wave]:
                        break
                    highest_left_wave -= 1
                if highest_left_wave < 0:
                    continue
                original = original_predecessor[right]
                if (
                    original >= 0
                    and not left_used[original]
                    and wave_of[original] == highest_left_wave
                ):
                    left = original
                else:
                    left = left_buckets[highest_left_wave].pop()
                    while left_used[left]:
                        left = left_buckets[highest_left_wave].pop()
                left_used[left] = True
                edges.add((left, right))
                matches += 1
            if matches == match_target:
                break
        if matches != match_target:
            raise RuntimeError("failed to construct the machine path cover")
        for predecessor, successor in edges:
            if wave_of[predecessor] >= wave_of[successor]:
                raise RuntimeError("internal constraint DAG is cyclic")
            predecessors[successor].append(predecessor)
            successors[predecessor].append(successor)
        return predecessors, successors

    def _group_components(self) -> dict[int, tuple[Component, ...]]:
        groups: dict[int, list[Component]] = {}
        for component, degree in zip(self._components, self.instance.fanouts):
            groups.setdefault(degree, []).append(component)
        return {degree: tuple(components) for degree, components in groups.items()}

    def _node_type_profiles(self) -> tuple[NodeTypeProfile, ...]:
        slots = self.instance.legal_start_count
        pool_size = len(self._pool)
        result: list[NodeTypeProfile] = []
        for degree, components in sorted(self._groups.items()):
            counts = [0] * slots
            for schedule in self._pool:
                for component in components:
                    counts[schedule[component.head]] += 1
            denominator = pool_size * len(components)
            result.append(
                NodeTypeProfile(
                    role="head",
                    edge_count=degree,
                    edge_direction="outgoing" if degree else "none",
                    star_fanout=degree,
                    node_count=len(components),
                    profile=tuple(count / denominator for count in counts),
                )
            )
            if degree:
                dependent_counts = [0] * slots
                for schedule in self._pool:
                    for component in components:
                        for dependent in component.dependents:
                            dependent_counts[schedule[dependent]] += 1
                dependent_count = len(components) * degree
                dependent_denominator = pool_size * dependent_count
                result.append(
                    NodeTypeProfile(
                        role="dependent",
                        edge_count=1,
                        edge_direction="incoming",
                        star_fanout=degree,
                        node_count=dependent_count,
                        profile=tuple(
                            count / dependent_denominator for count in dependent_counts
                        ),
                    )
                )
        return tuple(result)

    def _worst_task_min_entropy(self) -> float:
        worst_peak = 0.0
        slots = self.instance.legal_start_count
        pool_size = len(self._pool)
        for degree, components in self._groups.items():
            head_counts = [0] * slots
            dependent_counts = [0] * slots
            for schedule in self._pool:
                for component in components:
                    head_counts[schedule[component.head]] += 1
                    for dependent in component.dependents:
                        dependent_counts[schedule[dependent]] += 1
            head_denominator = pool_size * len(components)
            worst_peak = max(worst_peak, max(head_counts) / head_denominator)
            if degree:
                dependent_denominator = head_denominator * degree
                worst_peak = max(
                    worst_peak, max(dependent_counts) / dependent_denominator
                )
        return -math.log2(worst_peak)


def _profile_unevenness(
    profile: Sequence[float],
    baseline: Sequence[float] | None = None,
) -> float:
    slot_count = len(profile)
    if baseline is None:
        baseline = (1.0 / slot_count,) * slot_count
    if len(baseline) != slot_count:
        raise ValueError("profile and baseline must have the same length")
    maximum_squared_distance = (
        1.0
        - 2.0 * min(baseline)
        + sum(probability * probability for probability in baseline)
    )
    if maximum_squared_distance <= 0.0:
        return 0.0
    squared_distance = sum(
        (probability - expected) ** 2
        for probability, expected in zip(profile, baseline)
    )
    return math.sqrt(squared_distance / maximum_squared_distance)
