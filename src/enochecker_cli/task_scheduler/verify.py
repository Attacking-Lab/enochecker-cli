"""Goal (1): static, once-before-scheduling proof that scheduling will succeed.

``verify`` runs four checks. The first three are cheap *necessary* conditions
that pinpoint *why* an instance is impossible; the fourth is a constructive EDF
pass that, when it succeeds, is a *certificate* -- an actual valid schedule --
and (for concurrency C <= 2) is also exact, so a failure there is a true verdict of
infeasibility, not just "my heuristic gave up".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .core import Graph, Problem, build_graph, edf_complete


@dataclass
class VerifyResult:
    feasible: bool
    reason: str
    rounds: int
    critical_path: int
    es: list[int]
    ls: list[int]
    certificate: dict[int, int] | None  # a proven-valid round assignment
    checks: dict[str, bool] = field(default_factory=dict)
    exact: bool = True  # verdict is exact (C<=2) vs. sound-but-conservative (C>2)

    def __bool__(self) -> bool:
        return self.feasible


def verify(p: Problem) -> VerifyResult:
    g: Graph = build_graph(p)
    R = p.rounds
    checks: dict[str, bool] = {}

    checks["acyclic"] = g.acyclic
    if not g.acyclic:
        return VerifyResult(
            False,
            "dependency graph has a cycle",
            R,
            g.critical_path,
            g.es,
            g.ls,
            None,
            checks,
            exact=True,
        )

    # Critical path: the longest dependency chain needs that many rounds. This
    # also subsumes "a task fits at all": with >=1 task the chain is >=1 round,
    # so critical_path <= R forces R >= 1 (M >= K).
    checks["critical_path_fits"] = g.critical_path <= R
    if g.critical_path > R:
        return VerifyResult(
            False,
            f"critical path needs {g.critical_path} rounds but only {R} fit "
            f"(need M >= {g.critical_path * p.k})",
            R,
            g.critical_path,
            g.es,
            g.ls,
            None,
            checks,
            exact=True,
        )

    # Load bound: N tasks into C*R round-slots.
    checks["load_fits"] = p.n <= p.c * R
    if p.n > p.c * R:
        return VerifyResult(
            False,
            f"{p.n} tasks exceed concurrency C*R = {p.c}*{R} = {p.c * R} round-slots "
            f"(need M >= {-(-p.n // p.c) * p.k})",
            R,
            g.critical_path,
            g.es,
            g.ls,
            None,
            checks,
            exact=True,
        )

    # Constructive certificate: EDF places everything within deadlines & concurrency.
    cert = edf_complete(g, scheduled=set(), start_round=0)
    checks["constructive_edf"] = cert is not None
    exact = p.c <= 2
    if cert is None:
        reason = (
            "no valid schedule exists (concurrency/precedence conflict)"
            if exact
            else "EDF heuristic found no schedule; may be infeasible or hard (C>2)"
        )
        return VerifyResult(
            False, reason, R, g.critical_path, g.es, g.ls, None, checks, exact=exact
        )

    return VerifyResult(
        True,
        "certified: a valid schedule exists and the sampler will always find one",
        R,
        g.critical_path,
        g.es,
        g.ls,
        cert,
        checks,
        exact=exact,
    )


def format_report(p: Problem, v: VerifyResult) -> str:
    lines = []
    verdict = "FEASIBLE" if v.feasible else "INFEASIBLE"
    qual = "" if v.exact else "  (sound heuristic; exact only for C<=2)"
    lines.append(f"== static verify: {verdict} =={qual}")
    lines.append(f"   {v.reason}")
    lines.append(
        f"   N={p.n} tasks, M={p.m} slots, K={p.k} slots/task, C={p.c} concurrency"
    )
    lines.append(
        f"   rounds R = M//K = {v.rounds}   critical path = {v.critical_path} rounds"
    )
    for name, ok in v.checks.items():
        lines.append(f"   [{'x' if ok else ' '}] {name}")
    if v.feasible:
        widths = [v.ls[i] - v.es[i] + 1 for i in range(p.n)]
        tight = min(range(p.n), key=lambda i: widths[i]) if p.n else None
        lines.append(
            "   per-task feasible round window [earliest..latest] "
            "(width = raw wiggle room):"
        )
        for i in range(p.n):
            mark = " <- tightest" if i == tight else ""
            lines.append(
                f"     {p.name(i):>8}: [{v.es[i]}..{v.ls[i]}] width {widths[i]}{mark}"
            )
    return "\n".join(lines)
