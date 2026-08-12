"""Round-time scheduling for ``sim --round-time``: pick a per-task start
offset (seconds into the round) for one round's DAG of checker calls, given
a minimum ``k``-second gap between a task and anything depending on it.

Two algorithms are available, selected by name (``sim --scheduler``):

``edf``
    Round-grid EDF sampler (:mod:`enochecker_cli.task_scheduler`, vendored
    from atklab/gameserver / atklab/task-scheduler). Feasibility is verified
    up front and the concurrency cap is exact. Default.

``phase``
    Generalization of the windowed put/get/unconstrained scheduler
    atklab/gameserver used before it adopted task_scheduler (see
    atklab/gameserver commit 8a5caf7 and its parent,
    ``checker_runner/runners/eno.py``'s ``gen_timeslots_flat``). Tasks with
    no predecessor ("put") start in an early window, tasks with a
    predecessor ("get"/exploit) start in a late window separated from the
    early one by at least ``k`` seconds, and everything else ("havoc")
    spreads across the full round; each window is sliced into one interval
    per task and jittered within its slice. It predates the concurrency cap
    and does not enforce one, and it only supports single-hop dependencies
    (a task cannot both have a predecessor and a successor) -- both are why
    task_scheduler replaced it. Kept here for comparison.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from enochecker_cli.task_scheduler import Problem, sample_schedule, verify


@dataclass(frozen=True)
class RoundSchedule:
    start_offset: dict[int, float]


def _edf_schedule(
    n: int, edges: list[tuple[int, int]], m: int, k: int, c: int, jitter: bool
) -> RoundSchedule:
    problem = Problem(n=n, edges=tuple(edges), m=m, k=k, c=c)
    v = verify(problem)
    if not v.feasible:
        raise ValueError(f"cannot fit round in round_time={m}s: {v.reason}")
    sched = sample_schedule(problem, jitter=jitter, verified=v)
    return RoundSchedule(start_offset=dict(sched.start_slot))


def _place_window(
    tasks: list[int], lo: float, hi: float, rng: random.Random, jitter: bool
) -> dict[int, float]:
    if not tasks:
        return {}
    interval = (hi - lo) / len(tasks)
    slots = list(range(len(tasks)))
    rng.shuffle(slots)
    return {
        i: lo + slot * interval + (rng.random() * interval if jitter else 0.0)
        for i, slot in zip(tasks, slots)
    }


def _phase_schedule(
    n: int, edges: list[tuple[int, int]], m: int, k: int, c: int, jitter: bool
) -> RoundSchedule:
    del c  # the phase scheduler predates --concurrency; see module docstring

    preds: list[list[int]] = [[] for _ in range(n)]
    succs: list[list[int]] = [[] for _ in range(n)]
    for a, b in edges:
        succs[a].append(b)
        preds[b].append(a)
    if any(preds[i] and succs[i] for i in range(n)):
        raise ValueError(
            "phase scheduler only supports single-hop dependencies (a task "
            "cannot both depend on something and be depended on); use "
            "--scheduler edf"
        )

    early = [i for i in range(n) if succs[i] and not preds[i]]
    late = [i for i in range(n) if preds[i]]
    unconstrained = [i for i in range(n) if not preds[i] and not succs[i]]

    horizon = m - k
    if horizon < 4 * k:
        raise ValueError(
            f"cannot fit round in round_time={m}s with phase scheduler: "
            f"needs round_time >= {5 * k}s for timeout={k}s (try --scheduler edf)"
        )

    rng = random.SystemRandom()
    start: dict[int, float] = {}
    start.update(_place_window(early, 0, horizon / 4, rng, jitter))
    start.update(_place_window(late, horizon / 2, horizon, rng, jitter))
    start.update(_place_window(unconstrained, 0, horizon, rng, jitter))
    return RoundSchedule(start_offset=start)


SCHEDULERS = {"edf": _edf_schedule, "phase": _phase_schedule}
DEFAULT_SCHEDULER = "edf"


def schedule_round(
    algorithm: str,
    *,
    n: int,
    edges: list[tuple[int, int]],
    m: int,
    k: int,
    c: int,
    jitter: bool,
) -> RoundSchedule:
    try:
        fn = SCHEDULERS[algorithm]
    except KeyError:
        raise ValueError(
            f"unknown scheduler {algorithm!r}; choose from {sorted(SCHEDULERS)}"
        ) from None
    return fn(n, edges, m, k, c, jitter)
