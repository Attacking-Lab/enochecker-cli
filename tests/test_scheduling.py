import random

import pytest
from enochecker_core import CheckerMethod

from enochecker_cli.scheduling import (
    EnoConfig,
    ScheduleError,
    build_task_dag,
    plan_round,
    task_budget_s,
)


def _plan(eno: EnoConfig, round_length: int = 60):
    return plan_round(
        eno,
        round_length,
        flag_variants=2,
        noise_variants=1,
        havoc_variants=1,
        rng=random.Random(1),
    )


def test_dag_heads_precede_their_dependents():
    keys, fanouts = build_task_dag(2, 1, 1, cpt=3)
    assert len(keys) == len(fanouts) + sum(fanouts)
    i = 0
    for fanout in fanouts:
        if fanout:
            assert keys[i].method in (CheckerMethod.PUTFLAG, CheckerMethod.PUTNOISE)
        i += 1 + fanout


def test_past_round_getflags_follow_check_past_rounds():
    keys, _ = build_task_dag(2, 0, 0, cpt=4)
    offsets = sorted(
        k.related_round_offset
        for k in keys
        if k.method == CheckerMethod.GETFLAG and k.variant_id == 0
    )
    assert offsets == [0, 1, 2, 3, 4]


def test_draws_respect_dependencies_horizon_and_concurrency():
    eno = EnoConfig()
    plan = _plan(eno)
    for _ in range(200):
        starts = plan.scheduler.draw()
        plan.scheduler.instance.assert_valid(starts)
        slots = plan.draw()
        for key, start in slots.items():
            assert 0 <= start and start + task_budget_s(eno) <= plan.m
            if key.method in (CheckerMethod.GETFLAG, CheckerMethod.GETNOISE):
                if key.related_round_offset == 0:
                    head = (
                        CheckerMethod.PUTFLAG
                        if key.method == CheckerMethod.GETFLAG
                        else CheckerMethod.PUTNOISE
                    )
                    put = next(
                        s
                        for k, s in slots.items()
                        if k.method == head and k.variant_id == key.variant_id
                    )
                    assert start - put >= task_budget_s(eno)


def test_infeasible_round_reports_minimum_length():
    with pytest.raises(ScheduleError, match="need round >= 39s"):
        _plan(EnoConfig(), round_length=20)
