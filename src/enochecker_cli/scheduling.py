"""Per-team round schedule for ``sim``, ported from atklab/gameserver's
src/checker_runner/runners/eno.py (the code around ``gen_timeslots``).

The gameserver gives every team its own draw from one precomputed schedule
pool per round geometry, then offsets each task by a sub-second amount. This
module reproduces that pipeline with the same constants and the same derived
M/K/C, so ``sim`` puts the same load on a checker that a game would. Names
and defaults mirror the gameserver's ``EnoRunnerConfig``; when the gameserver
changes how it schedules, port the change here.
"""

from __future__ import annotations

import math
import random
from collections.abc import Sequence
from dataclasses import dataclass

from enochecker_core import CheckerMethod

from enochecker_cli.scheduler import Instance, RandomizedScheduler

# See the gameserver's eno.py for the full rationale behind each constant.
JITTER_SLACK_S = 1
CLIENT_TIMEOUT_GRACE_S = 1
MIN_RUNG_S = 0.01
MIN_JITTER_STEPS = 10
MAX_JITTER_STEPS = int(1 / MIN_RUNG_S)


class ScheduleError(ValueError):
    pass


@dataclass(frozen=True)
class EnoConfig:
    check_past_rounds: int = 10
    timeout: float = 15
    checker_hold: int = 5
    concurrency: int | None = None
    concurrency_factor: int = 2
    pool_size: int = 64

    @property
    def task_timeout_s(self) -> int:
        return math.ceil(self.timeout)


@dataclass(frozen=True)
class TaskKey:
    """One checker task within a team-round. `related_round_offset` is 0 for
    current-round tasks and >=1 for past-round GETFLAG replays."""

    method: CheckerMethod
    variant_id: int
    related_round_offset: int = 0


def build_task_dag(
    flag_variants: int, noise_variants: int, havoc_variants: int, cpt: int
) -> tuple[list[TaskKey], list[int]]:
    """(task keys, per-component fan-outs) in the scheduler's canonical order:
    each component's head immediately followed by its dependents."""
    keys: list[TaskKey] = []
    fanouts: list[int] = []
    for v in range(flag_variants):
        keys.append(TaskKey(CheckerMethod.PUTFLAG, v))
        keys.append(TaskKey(CheckerMethod.GETFLAG, v, 0))
        fanouts.append(1)
        for offset in range(1, cpt + 1):
            keys.append(TaskKey(CheckerMethod.GETFLAG, v, offset))
            fanouts.append(0)
    for v in range(noise_variants):
        keys.append(TaskKey(CheckerMethod.PUTNOISE, v))
        keys.append(TaskKey(CheckerMethod.GETNOISE, v))
        fanouts.append(1)
    for v in range(havoc_variants):
        keys.append(TaskKey(CheckerMethod.HAVOC, v))
        fanouts.append(0)
    return keys, fanouts


def min_rounds(fanouts: Sequence[int], c: int) -> int:
    n = len(fanouts) + sum(fanouts)
    dependents = sum(fanouts)
    rounds = -(-n // c)
    if dependents:
        rounds = max(rounds, 1 + -(-dependents // c))
    return max(1, rounds)


def min_concurrency(fanouts: Sequence[int], rounds: int) -> int | None:
    n = len(fanouts) + sum(fanouts)
    dependents = sum(fanouts)
    if rounds < 1 or (dependents and rounds < 2):
        return None
    c = -(-n // rounds)
    if dependents:
        c = max(c, -(-dependents // (rounds - 1)))
    return max(1, c)


def concurrency(eno: EnoConfig, fanouts: Sequence[int], rounds: int) -> int | None:
    if eno.concurrency is not None:
        return eno.concurrency
    minimum = min_concurrency(fanouts, rounds)
    if minimum is None:
        return None
    return min(len(fanouts) + sum(fanouts), minimum * eno.concurrency_factor)


def task_budget_s(eno: EnoConfig) -> float:
    """Wall-clock seconds one task may occupy: the HTTP client timeout."""
    return eno.timeout + CLIENT_TIMEOUT_GRACE_S


def task_slot_s(eno: EnoConfig) -> int:
    return max(1, eno.task_timeout_s) + CLIENT_TIMEOUT_GRACE_S + JITTER_SLACK_S


def grid(eno: EnoConfig, round_length: int) -> tuple[int, int]:
    return max(1, round_length - eno.checker_hold), task_slot_s(eno)


def min_round_length(eno: EnoConfig, fanouts: Sequence[int]) -> int:
    rounds = (
        min_rounds(fanouts, eno.concurrency)
        if eno.concurrency is not None
        else (2 if sum(fanouts) else 1)
    )
    return rounds * task_slot_s(eno) + eno.checker_hold


def _ladder_steps(task_count: int) -> int:
    return min(max(task_count, MIN_JITTER_STEPS), MAX_JITTER_STEPS)


def sub_second_offsets(starts: Sequence[int], rng: random.Random) -> list[float]:
    by_second: dict[int, list[int]] = {}
    for index, start in enumerate(starts):
        by_second.setdefault(start, []).append(index)

    offsets = [0.0] * len(starts)
    for indices in by_second.values():
        steps = _ladder_steps(len(indices))
        ladder: list[float] = []
        while len(ladder) < len(indices):
            rungs = [rung / steps for rung in range(steps)]
            rng.shuffle(rungs)
            ladder += rungs
        for index, offset in zip(indices, ladder):
            offsets[index] = offset
    return offsets


@dataclass(frozen=True)
class RoundPlan:
    """One round geometry's schedule pool, shared by every team like the
    gameserver shares it across teams within a worker."""

    keys: tuple[TaskKey, ...]
    m: int
    k: int
    c: int
    c_source: str
    min_round_length: int
    scheduler: RandomizedScheduler
    rng: random.Random

    def draw(self) -> dict[TaskKey, float]:
        """Seconds after round start at which each task fires."""
        starts = self.scheduler.draw()
        offsets = sub_second_offsets(starts, self.rng)
        return {
            key: start + offset
            for key, start, offset in zip(self.keys, starts, offsets)
        }


def plan_round(
    eno: EnoConfig,
    round_length: int,
    *,
    flag_variants: int,
    noise_variants: int,
    havoc_variants: int,
    rng: random.Random,
) -> RoundPlan:
    """Build the schedule pool, or raise ValueError with the gameserver
    preflight's verdict when the round cannot hold the task set."""
    if eno.timeout <= 0:
        raise ScheduleError(f"timeout must be > 0 (got {eno.timeout})")
    if round_length - eno.checker_hold <= 0:
        raise ScheduleError(
            f"round_length {round_length}s <= checker_hold {eno.checker_hold}s"
        )
    keys, fanouts = build_task_dag(
        flag_variants, noise_variants, havoc_variants, eno.check_past_rounds
    )
    if not keys:
        raise ScheduleError("checker reports no flag, noise or havoc variants")

    m, k = grid(eno, round_length)
    available = m // k
    c = concurrency(eno, fanouts, available)
    source = (
        "configured"
        if eno.concurrency is not None
        else f"{eno.concurrency_factor}x minimum"
    )
    min_round = min_round_length(eno, fanouts)
    if c is None or min_rounds(fanouts, c) > available:
        needed = min_rounds(fanouts, c) if c is not None else "more"
        raise ScheduleError(
            f"scheduler infeasible: {len(keys)} tasks ({sum(fanouts)} of them "
            f"waiting on a predecessor) need {needed} slots but only {available} "
            f"fit (K={k}s, M={m}s, C={c or '-'} ({source})); "
            f"need round >= {min_round}s"
        )
    scheduler = RandomizedScheduler(
        Instance(M=m, K=k, C=c, fanouts=fanouts), pool_size=eno.pool_size, rng=rng
    )
    return RoundPlan(
        keys=tuple(keys),
        m=m,
        k=k,
        c=c,
        c_source=source,
        min_round_length=min_round,
        scheduler=scheduler,
        rng=rng,
    )
