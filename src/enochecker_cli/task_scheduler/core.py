"""Core model + the round grid + the EDF feasibility engine.

Model
-----
Time is a line of ``M`` slots ``0 .. M-1``. Every task has duration ``K`` and,
once started at slot ``s``, occupies the half-open interval ``[s, s+K)``.

A dependency ``A -> B`` (``B`` depends on ``A``) forces ``start(B) >= start(A) + K``:
B may not start until A has finished. Because every task lasts exactly ``K`` and
the minimum dependency gap is also ``K``, the canonical grid is *rounds* of ``K``
slots each: round ``r`` covers slots ``[r*K, (r+1)*K)``. On that grid

    * a task occupies exactly one round,
    * a dependency means "successor in a strictly later round", and
    * concurrency ``C`` means "at most C tasks per round".

Round ``r`` maps back to start slot ``r*K``. There are ``R = M // K`` rounds.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True)
class Problem:
    """A scheduling instance.

    tasks are integer ids ``0 .. n-1``. ``edges`` are ``(a, b)`` meaning *b
    depends on a*. ``m`` slots, task duration / min-gap ``k``, max concurrency ``c``.
    """

    n: int
    edges: tuple[tuple[int, int], ...]
    m: int
    k: int
    c: int
    names: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.k <= 0 or self.m <= 0 or self.c <= 0 or self.n < 0:
            raise ValueError("n>=0 and m,k,c must be positive")
        for a, b in self.edges:
            if not (0 <= a < self.n and 0 <= b < self.n):
                raise ValueError(f"edge ({a},{b}) out of range 0..{self.n - 1}")
            if a == b:
                raise ValueError(f"self-dependency on task {a}")

    @property
    def rounds(self) -> int:
        """Number of whole task-length rounds that fit in the horizon."""
        return self.m // self.k

    def name(self, i: int) -> str:
        return self.names[i] if i < len(self.names) else f"t{i}"


@dataclass
class Graph:
    """Derived adjacency + longest-path bounds for a Problem."""

    problem: Problem
    preds: list[list[int]]
    succs: list[list[int]]
    topo: list[int]  # topological order; empty tail signals a cycle
    acyclic: bool
    es: list[int]  # earliest round (longest path from a source)
    depth_to_sink: list[int]  # longest path from task to any sink, in edges
    ls: list[int]  # latest round = R-1 - depth_to_sink
    critical_path: int  # longest dependency chain length, in rounds/tasks


def build_graph(p: Problem) -> Graph:
    preds: list[list[int]] = [[] for _ in range(p.n)]
    succs: list[list[int]] = [[] for _ in range(p.n)]
    for a, b in p.edges:
        succs[a].append(b)
        preds[b].append(a)

    # Kahn topological sort.
    indeg = [len(preds[i]) for i in range(p.n)]
    q = deque(i for i in range(p.n) if indeg[i] == 0)
    topo: list[int] = []
    while q:
        u = q.popleft()
        topo.append(u)
        for v in succs[u]:
            indeg[v] -= 1
            if indeg[v] == 0:
                q.append(v)
    acyclic = len(topo) == p.n

    R = p.rounds
    es = [0] * p.n
    depth = [0] * p.n
    if acyclic:
        for u in topo:
            for v in succs[u]:
                es[v] = max(es[v], es[u] + 1)
        for u in reversed(topo):
            for v in succs[u]:
                depth[u] = max(depth[u], depth[v] + 1)

    ls = [R - 1 - depth[i] for i in range(p.n)]
    critical_path = max((es[i] + depth[i] for i in range(p.n)), default=-1) + 1
    return Graph(p, preds, succs, topo, acyclic, es, depth, ls, critical_path)


def edf_complete(
    g: Graph,
    scheduled: set[int],
    start_round: int,
) -> dict[int, int] | None:
    """Deterministic Earliest-Deadline-First completion from ``start_round``.

    ``scheduled`` are tasks already placed in rounds ``< start_round`` (their
    exact rounds are irrelevant here -- only that they precede ``start_round``).
    Returns a round assignment for the *newly* scheduled tasks, or ``None`` if no
    valid completion exists.

    EDF-with-deadlines is optimal for concurrency ``C <= 2`` (Garey & Johnson) and a
    sound constructive certificate for any ``C``: if it completes, the instance is
    feasible. It is the guaranteed-safe fallback the sampler falls back onto, so
    "the sampler never dead-ends" reduces to "this function found a completion".
    """
    p = g.problem
    C, R, ls, preds = p.c, p.rounds, g.ls, g.preds
    done = set(scheduled)
    out: dict[int, int] = {}

    for r in range(start_round, R):
        unscheduled = [i for i in range(p.n) if i not in done]
        ready = [i for i in unscheduled if all(pp in done for pp in preds[i])]
        ready.sort(key=lambda i: ls[i])
        take = ready[:C]
        taken = set(take)
        # Any task that had to run by now but won't -> infeasible.
        for i in unscheduled:
            if i not in taken and ls[i] <= r:
                return None
        for i in take:
            done.add(i)
            out[i] = r

    return out if len(done) == p.n else None


def edf_feasible(
    g: Graph,
    done: set[int],
    force_now: set[int],
    r: int,
    forbid: frozenset[int] = frozenset(),
) -> bool:
    """Is there a valid completion that runs ``done`` before round ``r``, *at
    least* ``force_now`` at round ``r``, and *none* of ``forbid`` at round ``r``?

    Round ``r`` is filled greedily by EDF around ``force_now`` (skipping
    ``forbid``; running more now is never worse for unit tasks), then the tail
    completes from ``r+1``. This is the oracle the sampler consults to decide,
    per task, whether committing it now (``force_now``) or deferring it
    (``forbid``) keeps the schedule finishable. Deferring a task whose deadline
    is ``r`` shows up as an unavoidable miss and returns ``False``.
    """
    p = g.problem
    C, ls, preds = p.c, g.ls, g.preds
    if len(force_now) > C or (force_now & forbid):
        return False
    done2 = set(done)
    ready = [
        i for i in range(p.n) if i not in done2 and all(pp in done2 for pp in preds[i])
    ]
    if any(i not in ready for i in force_now):
        return False
    run = set(force_now)
    for i in sorted(
        (i for i in ready if i not in run and i not in forbid), key=lambda i: ls[i]
    ):
        if len(run) >= C:
            break
        run.add(i)
    if any(ls[i] <= r for i in ready if i not in run):
        return False
    return edf_complete(g, done2 | run, r + 1) is not None
