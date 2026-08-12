"""Goal (3): sample a *valid* schedule that is maximally unpredictable.

Both the round assignment and the sub-round jitter are **single-pass, exact
constructions**: at every decision point we compute the precise set of options
that keep the schedule feasible and draw once from it. We never guess a random
configuration and re-roll until it validates -- that bounded shuffle-and-retry
pattern is banned because it is neither verifiable nor guaranteed to terminate
in the space it claims to sample.

Round assignment
----------------
Round by round we decide each ready task in deadline order: run it now or defer.
``can_run`` / ``can_defer`` (the exact EDF oracle) say which choices keep the
instance finishable; at least one is always true on a verified instance, so the
sampler **can never dead-end** -- the runtime half of the goal-(1) guarantee.

When both are legal we place the task now with probability ``1 / rem`` where
``rem = ls - r + 1`` is the number of rounds left until its deadline. This is the
reservoir-sampling weight that makes a task's start round **uniform** over its
feasible window (a fixed probability would give a geometric distribution that
piles tasks up near their deadlines). Urgent tasks are forced; slack tasks
spread evenly.

Sub-round jitter (back to front)
--------------------------------
We place tasks from the last round to the first. Tasks in the **final round get
offset 0** (start exactly at their round boundary) so nothing runs past the tail
of the horizon. Every earlier task's start slot is drawn once, uniformly, from
``[round_start, upper]`` where ``upper`` is bounded by (a) already-placed
successors -- a task must finish before its successor starts, ``s <= s_succ - K``
-- and (b) an exact concurrency bound against the intervals already placed.
Processing back-to-front makes ``round_start`` always feasible (every placed task
lives in a later-or-equal round, hence at slots ``>= round start``), so the draw
interval is never empty and concurrency ``<= C`` holds by construction.

For an adversary to be unable to predict a task, the choices must not be
replayable: by default we draw from ``random.SystemRandom`` (a CSPRNG). Pass a
``seed`` only for reproducible tests -- a seeded schedule is predictable.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from .core import Problem, build_graph, edf_feasible
from .verify import VerifyResult, verify


@dataclass
class Schedule:
    problem: Problem
    round_of: dict[int, int]  # task -> round
    start_slot: dict[int, int]  # task -> absolute start slot (with any jitter)

    def interval(self, i: int) -> tuple[int, int]:
        s = self.start_slot[i]
        return s, s + self.problem.k

    def max_concurrency(self) -> int:
        return _max_concurrency(self.problem, self.start_slot)

    def validate(self) -> None:
        """Raise if this schedule violates any hard constraint."""
        p = self.problem
        if len(self.round_of) != p.n:
            raise ValueError(f"only {len(self.round_of)}/{p.n} tasks scheduled")
        for i in range(p.n):
            s = self.start_slot[i]
            if not (0 <= s <= p.m - p.k):
                raise ValueError(f"task {p.name(i)} start {s} outside [0,{p.m - p.k}]")
        for a, b in p.edges:
            if self.start_slot[b] < self.start_slot[a] + p.k:
                raise ValueError(
                    f"dependency {p.name(a)}->{p.name(b)} violated: "
                    f"{self.start_slot[b]} < {self.start_slot[a]}+{p.k}"
                )
        conc = self.max_concurrency()
        if conc > p.c:
            raise ValueError(f"concurrency exceeded: {conc} concurrent > C={p.c}")


def sample_schedule(
    p: Problem,
    *,
    seed: int | None = None,
    jitter: bool = False,
    verified: VerifyResult | None = None,
) -> Schedule:
    """Draw one valid schedule in a single feasibility-guided pass.

    Each task's start round is sampled uniformly over its feasible window via the
    reservoir weight ``1/rem`` (see module docstring) -- no tuning knob, the fair
    spread is computed. ``jitter`` adds exact, concurrency-safe sub-round start
    offsets. Raises if the instance is infeasible.
    """
    v = verified or verify(p)
    if not v.feasible:
        raise ValueError(f"instance is infeasible: {v.reason}")

    rng = random.Random(seed) if seed is not None else random.SystemRandom()
    g = build_graph(p)
    C, R, ls, preds = p.c, p.rounds, g.ls, g.preds

    done: set[int] = set()
    round_of: dict[int, int] = {}

    for r in range(R):
        ready = [
            i
            for i in range(p.n)
            if i not in done and all(pp in done for pp in preds[i])
        ]
        # Deadline order; random tie-break so which task fills a slot varies too.
        prio = {i: rng.random() for i in ready}
        ready.sort(key=lambda i: (ls[i], prio[i]))

        committed: set[int] = set()
        deferred: frozenset[int] = frozenset()
        for i in ready:
            if len(committed) >= C:  # slot full; remaining (least urgent) defer
                deferred |= {i}
                continue
            can_run = edf_feasible(g, done, committed | {i}, r, forbid=deferred)
            can_defer = edf_feasible(g, done, set(committed), r, forbid=deferred | {i})
            if can_run and can_defer:
                if rng.random() < 1.0 / (ls[i] - r + 1):  # reservoir: uniform round
                    committed.add(i)
                else:
                    deferred |= {i}
            elif can_run:
                committed.add(i)
            elif can_defer:
                deferred |= {i}
            else:
                raise RuntimeError(
                    "no feasible move on a verified instance "
                    "(bug in the feasibility oracle)"
                )

        for i in committed:
            round_of[i] = r
            done.add(i)

    start_slot = (
        _apply_jitter(p, round_of, g.succs, rng)
        if jitter
        else {i: round_of[i] * p.k for i in round_of}
    )

    sched = Schedule(p, round_of, start_slot)
    sched.validate()
    return sched


# --------------------------------------------------------------------------- #
# sub-round jitter -- back-to-front, single pass, exact                       #
# --------------------------------------------------------------------------- #


def _max_concurrency(p: Problem, start_slot: dict[int, int]) -> int:
    events: list[tuple[int, int]] = []
    for s in start_slot.values():
        events.append((s, 1))
        events.append((s + p.k, -1))
    events.sort()
    cur = peak = 0
    for _, d in events:
        cur += d
        peak = max(peak, cur)
    return peak


def _first_unsafe_start(
    placed: list[tuple[int, int]], lo: int, k: int, c: int, hi_cap: int
) -> int:
    """Largest start ``s`` in ``[lo, hi_cap]`` such that every window
    ``[lo..s]`` keeps concurrency < c against ``placed`` -- i.e. one below the
    first start whose K-window would touch an already-saturated region.

    ``lo`` is assumed already safe (guaranteed by back-to-front placement).
    """
    if not placed:
        return hi_cap
    # Sweep to find maximal segments already covered by >= c intervals.
    events: list[tuple[int, int]] = []
    for s, e in placed:
        events.append((s, 1))
        events.append((e, -1))
    events.sort()
    saturated: list[tuple[int, int]] = []
    cur = 0
    seg_start = None
    for t, d in events:
        was = cur
        cur += d
        if was < c <= cur and seg_start is None:
            seg_start = t
        elif was >= c > cur and seg_start is not None:
            saturated.append((seg_start, t))
            seg_start = None
    # A window [s, s+k) hits saturated [a, b) iff a - k < s < b.
    first_unsafe = hi_cap + 1
    for a, b in saturated:
        s_hit = max(lo, a - k + 1)
        if s_hit < b:
            first_unsafe = min(first_unsafe, s_hit)
    return min(hi_cap, first_unsafe - 1)


def _apply_jitter(
    p: Problem, round_of: dict[int, int], succs: list[list[int]], rng: random.Random
) -> dict[int, int]:
    """Place tasks last-round-first; each start drawn once from an exact interval."""
    order = sorted(round_of, key=lambda i: (round_of[i], i), reverse=True)
    start: dict[int, int] = {}
    placed: list[tuple[int, int]] = []
    horizon = p.m - p.k
    last_round = p.rounds - 1

    for i in order:
        lo = round_of[i] * p.k
        if round_of[i] == last_round:  # final round: offset 0, finish by the
            s = lo  # horizon tail -- nothing runs at the end
        else:
            hi = horizon
            for j in succs[i]:  # finish before each placed successor
                if j in start:
                    hi = min(hi, start[j] - p.k)
            hi = min(hi, _first_unsafe_start(placed, lo, p.k, p.c, horizon))
            hi = max(hi, lo)  # cannot happen; lo is always safe
            s = rng.randint(lo, hi)
        start[i] = s
        placed.append((s, s + p.k))

    return start
