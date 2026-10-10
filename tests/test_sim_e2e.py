import csv
import subprocess
import sys
from collections import Counter
from pathlib import Path

from enochecker_core import CheckerMethod

from stub_checker import StubChecker

TEAMS = 2
ROUNDS = 3
CHECK_PAST_ROUNDS = 2
TIMEOUT_S = 1
# Task budget: timeout plus the client's grace second.
BUDGET_S = TIMEOUT_S + 1


def _sim(port: int, statistics: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "enochecker_cli",
            "-p",
            str(port),
            "-A",
            "127.0.0.1",
            "--timeout",
            str(TIMEOUT_S),
            "sim",
            "--teams",
            str(TEAMS),
            "--rounds",
            str(ROUNDS),
            "--round-time",
            "7",
            "--checker-hold",
            "1",
            "--check-past-rounds",
            str(CHECK_PAST_ROUNDS),
            "--exploiters",
            "1",
            "--statistics",
            str(statistics),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_sim_replays_gameserver_rounds(tmp_path: Path) -> None:
    statistics = tmp_path / "stats.csv"
    # Slower than the task budget, so every havoc times out on the client.
    with StubChecker(havoc_delay_s=BUDGET_S + 0.5) as stub:
        proc = _sim(stub.port, statistics)
    assert proc.returncode == 0, proc.stderr

    with statistics.open() as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == len(stub.served)

    first_round = min(int(r["round_id"]) for r in rows)
    counts = Counter(
        (r["operation"], int(r["round_id"]) - int(r["related_round_id"])) for r in rows
    )
    flag_variants, noise_variants = 2, 1
    assert counts == {
        ("putflag", 0): flag_variants * ROUNDS * TEAMS,
        ("getflag", 0): flag_variants * ROUNDS * TEAMS,
        ("getflag", 1): flag_variants * (ROUNDS - 1) * TEAMS,
        ("getflag", 2): flag_variants * (ROUNDS - 2) * TEAMS,
        ("putnoise", 0): noise_variants * ROUNDS * TEAMS,
        ("getnoise", 0): noise_variants * ROUNDS * TEAMS,
        ("havoc", 0): ROUNDS * TEAMS,
        # Exploits target the previous round, so none run in the first one.
        ("exploit", 1): ROUNDS - 1,
    }

    results = Counter((r["operation"], r["result"]) for r in rows)
    assert results[("havoc", "TIMEOUT")] == ROUNDS * TEAMS
    assert all(r["result"] == "OK" for r in rows if r["operation"] != "havoc"), results

    assert {int(r["team"]) for r in rows if r["operation"] != "exploit"} == set(
        range(1, TEAMS + 1)
    )
    assert all(int(r["related_round_id"]) >= first_round for r in rows), (
        "a getflag ran for a round before the game started"
    )

    starts = {
        (r["round_id"], r["team"], r["operation"], r["variant_id"]): float(r["started"])
        for r in rows
        if r["round_id"] == r["related_round_id"]
    }
    for (round_id, team, operation, variant), start in starts.items():
        put = {"getflag": "putflag", "getnoise": "putnoise"}.get(operation)
        if put is not None:
            gap = start - starts[(round_id, team, put, variant)]
            assert gap >= BUDGET_S, (operation, gap)

    for served in stub.served:
        assert served.message.timeout == TIMEOUT_S * 1000
        assert served.message.round_length == 7000
        if served.message.method != CheckerMethod.EXPLOIT:
            assert served.message.team_id in range(1, TEAMS + 1)
