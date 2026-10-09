import argparse
import dataclasses
import hashlib
from io import TextIOWrapper
import itertools
import random
import pathlib
import time
import types
import asyncio
import collections
import secrets
import sys
from typing_extensions import Self
import os

from dotenv import load_dotenv
from random import Random, SystemRandom
import exrex
import requests
import httpx
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn

from enochecker_core import (
    CheckerMethod,
    CheckerResultMessage,
    CheckerTaskMessage,
    CheckerInfoMessage,
    CheckerTaskResult,
)

from enochecker_cli.scheduling import (
    CLIENT_TIMEOUT_GRACE_S,
    EnoConfig,
    RoundPlan,
    ScheduleError,
    plan_round,
)

TASK_TYPES = [str(i) for i in CheckerMethod]

DEFAULT_TIMEOUT_S = 60
# Mirrors the gameserver's EnoRunnerConfig.timeout and DEFAULT_ROUND_LENGTH_S.
DEFAULT_SIM_TIMEOUT_S = 15
DEFAULT_SIM_ROUND_TIME_S = 60

# What the gameserver reports when a checker misses the deadline it was given.
TIMEOUT_MESSAGE = "TIMEOUT"

FLAG_METHODS = (CheckerMethod.PUTFLAG, CheckerMethod.GETFLAG)
NOISE_METHODS = (CheckerMethod.PUTNOISE, CheckerMethod.GETNOISE)


@dataclasses.dataclass
class LogEntry:
    round_id: int
    related_round_id: int
    operation: str
    variant_id: int
    team: int
    result: str
    started: float
    time_taken: float

    def to_csv(self) -> str:
        return (
            f"{self.round_id},{self.related_round_id},{self.operation},"
            f"{self.variant_id},{self.team},{self.result},"
            f"{self.started:.3f},{self.time_taken:.3f}"
        )

    @staticmethod
    def csv_header() -> str:
        return "round_id,related_round_id,operation,variant_id,team,result,started,time_taken"


def result_label(result: CheckerResultMessage) -> str:
    if (
        result.result == CheckerTaskResult.INTERNAL_ERROR
        and result.message == TIMEOUT_MESSAGE
    ):
        return TIMEOUT_MESSAGE
    return str(CheckerTaskResult(result.result).value)


class CheckerClient:
    def __init__(
        self,
        url: str,
        service_address: str,
        output: pathlib.Path | None,
        flag_regex: str,
        timeout: float,
        seed: int = 0,
        round_length: float | None = None,
    ):
        self.output_path = output
        self.service_address = service_address
        self.flag_regex = flag_regex
        self.url = url.rstrip("/")
        if "://" not in self.url:
            self.url = "http://" + self.url

        random_source = SystemRandom if seed == 0 else Random
        self._id_random = random_source(seed)
        # Unbounded so the client never queues requests the gameserver would
        # have sent: that would hide load and inflate measured task times.
        self._client = httpx.AsyncClient(limits=httpx.Limits(max_connections=None))
        self._log: TextIOWrapper | None = None
        self._connected = False
        self._token = "loadtest-" + secrets.token_urlsafe(10)
        # (related round, team, flag variant, repeat) -> (flag, attack info)
        self._flags: dict[tuple[int, int, int, int], tuple[str, str | None]] = {}
        self.timeout = timeout
        self.round_length = round_length if round_length is not None else timeout
        self.results: collections.Counter[str] = collections.Counter()

        self.flag_variants = 0
        self.noise_variants = 0
        self.havoc_variants = 0
        # Indexed by exploit variant id, each entry is the flag variant it targets
        self.exploit_variants: list[int] = []
        self.test_variants = 0
        self.service_name = ""

    async def __aenter__(self) -> Self:
        await self._client.__aenter__()
        self._log = (
            open(self.output_path, "w").__enter__() if self.output_path else None
        )
        if self._log:
            self._log.write(LogEntry.csv_header() + "\n")
        response = await self._client.get(f"{self.url}/service")
        if response.status_code != 200:
            raise RuntimeError("Failed to get /service from checker")
        metadata = CheckerInfoMessage.model_validate_json(response.text)
        self.flag_variants = metadata.flag_variants
        self.noise_variants = metadata.noise_variants
        self.havoc_variants = metadata.havoc_variants
        self.exploit_variants = metadata.exploit_variants
        self.test_variants = metadata.test_variants
        self.service_name = metadata.service_name
        self._connected = True
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None = None,
        exc_value: BaseException | None = None,
        traceback: types.TracebackType | None = None,
    ) -> None:
        self._connected = False
        if self._log:
            self._log.flush()
            self._log.__exit__(exc_type, exc_value, traceback)
            self._log = None
        self._flags.clear()
        await self._client.__aexit__(exc_type, exc_value, traceback)

    def add_log_entries(self, entries: list[LogEntry]) -> None:
        assert self._connected, "Client is not connected (did you forget `async with`)?"
        for entry in entries:
            self.results[entry.result] += 1
        if self._log:
            for entry in entries:
                self._log.write(entry.to_csv() + "\n")
            self._log.flush()

    def forget_flags(self, before_round: int) -> None:
        for key in [key for key in self._flags if key[0] < before_round]:
            del self._flags[key]

    def display(self) -> str:
        assert self._connected, "Client is not connected (did you forget `async with`)?"
        return "\n".join(
            [
                f"\x1b[1mservice\x1b[0m:      {self.service_name}",
                f"\x1b[32;1mflag stores\x1b[0m:  {self.flag_variants}",
                f"\x1b[33;1mnoise checks\x1b[0m: {self.noise_variants}",
                f"\x1b[33;1mhavoc checks\x1b[0m: {self.havoc_variants}",
                f"\x1b[31;1mexploits\x1b[0m:     {len(self.exploit_variants)}",
                f"\x1b[33;1mtests\x1b[0m:        {self.test_variants}",
            ]
        )

    def _build_request(
        self,
        *,
        method: CheckerMethod,
        round_id: int,
        related_round_id: int,
        team_id: int,
        flag: str | None,
        variant_id: int,
        attack_info: str | None,
        repeat: int,
    ) -> CheckerTaskMessage:
        task_id = self._id_random.randint(0, 1 << 64)
        instance = (
            f"r{related_round_id}-t{team_id}-v{variant_id}-{repeat}-{self._token}"
        )
        if method in FLAG_METHODS:
            chain_id = f"flag-{instance}"
        elif method in NOISE_METHODS:
            chain_id = f"noise-{instance}"
        else:
            chain_id = f"unique-{task_id}-{repeat}-{self._token}"
        return CheckerTaskMessage(
            task_id=task_id,
            method=method,
            address=self.service_address,
            team_id=team_id,
            team_name=f"#{team_id}",
            current_round_id=round_id,
            related_round_id=related_round_id,
            flag=flag,
            variant_id=variant_id,
            timeout=int(self.timeout * 1000),
            round_length=int(self.round_length * 1000),
            task_chain_id=chain_id,
            flag_regex=self.flag_regex,
            flag_hash=hashlib.sha256(flag.encode()).hexdigest() if flag else None,
            attack_info=attack_info,
        )

    async def task(
        self,
        method: CheckerMethod,
        *,
        round_id: int,
        variant_id: int,
        related_round_id: int | None = None,
        team_id: int = 0,
        repeat: int = 0,
        strict: bool = True,
        http: httpx.AsyncClient | None = None,
    ) -> tuple[CheckerResultMessage, float]:
        """Run one checker task and return its result and duration.

        strict (used by `run`) raises on anything but OK, the way a developer
        poking at a checker wants. Non-strict (used by `sim`) reports failures
        as results instead, like the gameserver: under load they are the data.
        """
        assert self._connected, "Client is not connected (did you forget `async with`)?"
        related = round_id if related_round_id is None else related_round_id

        flag: str | None = None
        attack_info: str | None = None
        if method == CheckerMethod.PUTFLAG:
            flag = exrex.getone(self.flag_regex, limit=64)
            # Stored before the request: the gameserver checks a flag whether
            # or not its PUTFLAG succeeded.
            self._flags[(related, team_id, variant_id, repeat)] = (flag, None)
        elif method == CheckerMethod.GETFLAG:
            flag, attack_info = self._flags[(related, team_id, variant_id, repeat)]
        elif method == CheckerMethod.EXPLOIT:
            flag_variant_id = self.exploit_variants[variant_id]
            flag, attack_info = self._flags[(related, team_id, flag_variant_id, repeat)]

        message = self._build_request(
            method=method,
            round_id=round_id,
            related_round_id=related,
            team_id=team_id,
            flag=flag,
            variant_id=variant_id,
            attack_info=attack_info,
            repeat=repeat,
        )
        start = time.monotonic()
        try:
            response = await (http or self._client).post(
                self.url,
                content=message.model_dump_json(),
                headers={"Content-Type": "application/json"},
                timeout=self.timeout + CLIENT_TIMEOUT_GRACE_S,
            )
            assert response.status_code == 200, response.text
            result = CheckerResultMessage.model_validate_json(response.text)
        except Exception as e:
            if strict:
                raise
            message_text = (
                TIMEOUT_MESSAGE
                if isinstance(e, httpx.TimeoutException)
                else f"{type(e).__name__}: {e}"
            )
            result = CheckerResultMessage(
                result=CheckerTaskResult.INTERNAL_ERROR, message=message_text
            )
        duration = time.monotonic() - start
        status = CheckerTaskResult(result.result)

        if method == CheckerMethod.PUTFLAG and status == CheckerTaskResult.OK:
            assert flag is not None
            self._flags[(related, team_id, variant_id, repeat)] = (
                flag,
                result.attack_info,
            )

        if method == CheckerMethod.EXPLOIT:
            if status == CheckerTaskResult.OK and result.flag != flag:
                if strict:
                    raise AssertionError(
                        f"exploit {variant_id} returned {result.flag}, expected {flag}"
                    )
                result = CheckerResultMessage(
                    result=CheckerTaskResult.MUMBLE,
                    message=f"exploit returned wrong flag {result.flag!r}",
                )
            elif strict and status != CheckerTaskResult.OK:
                assert result.message in ("No flags found", "Flag not found"), (
                    result.message
                )
        elif strict:
            assert status == CheckerTaskResult.OK, result.model_dump_json()

        return result, duration

    async def _scheduled_task(
        self,
        round_start: float,
        offset: float,
        method: CheckerMethod,
        *,
        round_id: int,
        related_round_id: int,
        variant_id: int,
        team_id: int,
        http: httpx.AsyncClient | None = None,
    ) -> None:
        delay = round_start + offset - time.monotonic()
        if delay > 0:
            await asyncio.sleep(delay)
        started = time.monotonic() - round_start
        result, duration = await self.task(
            method,
            round_id=round_id,
            related_round_id=related_round_id,
            variant_id=variant_id,
            team_id=team_id,
            strict=False,
            http=http,
        )
        self.add_log_entries(
            [
                LogEntry(
                    round_id,
                    related_round_id,
                    str(method),
                    variant_id,
                    team_id,
                    result_label(result),
                    started,
                    duration,
                )
            ]
        )

    async def _simulate_team(
        self,
        plan: RoundPlan,
        round_start: float,
        round_id: int,
        first_round_id: int,
        team_id: int,
    ) -> None:
        jobs = []
        # One HTTP session per team-run, like the gameserver's eno runner:
        # connection reuse is part of the load profile the checker sees.
        async with httpx.AsyncClient(limits=httpx.Limits(max_connections=None)) as http:
            for key, offset in plan.draw().items():
                related = round_id - key.related_round_offset
                # Past rounds before the game started have no flag to check.
                if related < first_round_id:
                    continue
                jobs.append(
                    self._scheduled_task(
                        round_start,
                        offset,
                        key.method,
                        round_id=round_id,
                        related_round_id=related,
                        variant_id=key.variant_id,
                        team_id=team_id,
                        http=http,
                    )
                )
            await asyncio.gather(*jobs)

    async def simulate_round(
        self,
        plan: RoundPlan,
        *,
        round_start: float,
        round_id: int,
        first_round_id: int,
        teams: int,
        exploiters: int,
        rng: random.Random,
    ) -> None:
        """One round of gameserver traffic: every team runs its own draw from
        the shared schedule pool, all anchored at `round_start`.

        Exploits are not gameserver traffic. With `exploiters`, each exploiter
        additionally runs every exploit variant once per round against a random
        team's flag from the previous round, at a uniformly random time.
        """
        assert self._connected, "Client is not connected (did you forget `async with`)?"
        jobs = [
            self._simulate_team(plan, round_start, round_id, first_round_id, team_id)
            for team_id in range(1, teams + 1)
        ]
        if round_id > first_round_id:
            latest_start = plan.m - plan.k
            for _ in range(exploiters):
                for variant_id in range(len(self.exploit_variants)):
                    jobs.append(
                        self._scheduled_task(
                            round_start,
                            rng.uniform(0, latest_start),
                            CheckerMethod.EXPLOIT,
                            round_id=round_id,
                            related_round_id=round_id - 1,
                            variant_id=variant_id,
                            team_id=rng.randint(1, teams),
                        )
                    )
        await asyncio.gather(*jobs)


async def run_sim(
    checker_address: str,
    checker_port: int,
    service_address: str,
    rounds: int | None,
    teams: int,
    exploiters: int,
    flag_regex: str,
    output: pathlib.Path | None,
    seed: int,
    round_time: int,
    eno: EnoConfig,
):
    url = f"http://{checker_address}:{checker_port}"
    rng: random.Random = Random(seed) if seed else SystemRandom()
    async with CheckerClient(
        url,
        service_address,
        output,
        flag_regex,
        eno.timeout,
        seed=seed,
        round_length=round_time,
    ) as client:
        print(client.display())
        plan = plan_round(
            eno,
            round_time,
            flag_variants=client.flag_variants,
            noise_variants=client.noise_variants,
            havoc_variants=client.havoc_variants,
            rng=rng,
        )
        print(f"\x1b[31;1mteams\x1b[0m:        {teams}")
        print(
            f"\x1b[31;1mrounds\x1b[0m:       {'unlimited' if rounds is None else rounds}"
        )
        print(
            f"\x1b[31;1mround-time\x1b[0m:   {round_time}s "
            f"(tasks run in the first {plan.m}s, {eno.checker_hold}s hold; "
            f"min {plan.min_round_length}s)"
        )
        print(
            f"\x1b[31;1mtasks\x1b[0m:        {len(plan.keys)} per team-round "
            f"(flags checked for {eno.check_past_rounds} past rounds), "
            f"{len(plan.keys) * teams} per round"
        )
        print(
            f"\x1b[31;1mconcurrency\x1b[0m:  {plan.c} per team ({plan.c_source}), "
            f"up to {plan.c * teams} at the checker; slot K={plan.k}s "
            f"for timeout {eno.timeout:g}s"
        )
        print(f"\x1b[31;1mexploiters\x1b[0m:   {exploiters}")

        first_round_id = random.randint(1, 1 << 30)
        next_start = time.monotonic()
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
        ) as progress:
            bar = progress.add_task("round", total=rounds)
            for index in itertools.count() if rounds is None else range(rounds):
                round_id = first_round_id + index
                round_start = next_start
                await client.simulate_round(
                    plan,
                    round_start=round_start,
                    round_id=round_id,
                    first_round_id=first_round_id,
                    teams=teams,
                    exploiters=exploiters,
                    rng=rng,
                )
                client.forget_flags(round_id - eno.check_past_rounds)
                progress.update(
                    bar,
                    advance=1,
                    description=" ".join(
                        f"{name}={count}"
                        for name, count in sorted(client.results.items())
                    ),
                )
                next_start = round_start + round_time
                lag = time.monotonic() - next_start
                if lag > 0:
                    progress.console.print(
                        f"round {index} overran its {round_time}s by {lag:.1f}s"
                    )
                    next_start = time.monotonic()
                else:
                    await asyncio.sleep(-lag)


async def run_chain(
    checker_address: str,
    checker_port: int,
    service_address: str,
    multiply: int,
    flag_regex: str,
    loop: bool,
    targets: list[str],
    timeout: float,
    auto: bool,
    seed: int,
):
    url = f"http://{checker_address}:{checker_port}"
    async with CheckerClient(
        url, service_address, None, flag_regex, timeout, seed=seed
    ) as client:
        print(client.display())

        seen = set()
        repeat_seq = 0
        resolved_targets: list[tuple[CheckerMethod, int, int]] = []
        targets = targets[::-1]
        while len(targets) > 0:
            target = targets[-1]
            if "-" not in target:
                method_name = target
                targets.pop()
                if method_name in {"putflag", "getflag"}:
                    for variant_id in reversed(range(client.flag_variants)):
                        targets.append(f"{method_name}-{variant_id}")
                elif method_name in {"putnoise", "getnoise"}:
                    for variant_id in reversed(range(client.noise_variants)):
                        targets.append(f"{method_name}-{variant_id}")
                elif method_name == "havoc":
                    for variant_id in reversed(range(client.havoc_variants)):
                        targets.append(f"{method_name}-{variant_id}")
                elif method_name == "exploit":
                    for variant_id in reversed(range(len(client.exploit_variants))):
                        targets.append(f"{method_name}-{variant_id}")
                elif method_name == "test":
                    for variant_id in reversed(range(client.test_variants)):
                        targets.append(f"{method_name}-{variant_id}")
                elif method_name == "all":
                    targets.append("exploit")
                    targets.append("havoc")
                    targets.append("getnoise")
                    targets.append("putnoise")
                    targets.append("getflag")
                    targets.append("putflag")
                else:
                    raise ValueError(f"Unknown method {method_name}")
                continue

            method_name, variant_str, *a = target.rsplit("-")
            variant_id = int(variant_str)

            # NOTE: Without --no-auto
            # `enochecker_cli run putflag-0 getflag-0`
            # will result in:
            #   putflag-0-0, putflag-0-1, getflag-0-1
            # instead of:
            #   putflag-0-0, getflag-0-0
            assert len(a) in (0, 1), f"Invalid target: {target}"
            if len(a) == 1:
                repeat_id = int(a[0])
            else:
                if auto and (method_name, variant_id, repeat_seq) in seen:
                    repeat_seq += 1
                repeat_id = repeat_seq

            if method_name == "getflag":
                if auto and ("putflag", variant_id, repeat_id) not in seen:
                    targets.append(f"putflag-{variant_id}-{repeat_id}")
                    continue
            elif method_name == "getnoise":
                if auto and ("putnoise", variant_id, repeat_id) not in seen:
                    targets.append(f"putnoise-{variant_id}")
                    continue
            elif method_name == "exploit":
                flag_variant = client.exploit_variants[variant_id]
                if auto and ("putflag", flag_variant, repeat_id) not in seen:
                    targets.append(f"putflag-{flag_variant}-{repeat_id}")
                    continue
            elif method_name not in TASK_TYPES:
                raise ValueError(f"Unknown method {method_name}")
            seen.add((method_name, variant_id, repeat_id))
            print(
                f"\x1b[31;1mcall\x1b[0m:         {method_name}-{variant_id}-{repeat_id}"
            )
            resolved_targets.append((CheckerMethod(method_name), variant_id, repeat_id))

            targets.pop()

        print(f"\x1b[31;1mtotal\x1b[0m:        {len(resolved_targets) * multiply}")

        round_id_base = random.randint(0, 10000000000)

        async def chain(round_id: int) -> None:
            for method, variant_id, repeat_id in resolved_targets:
                await client.task(
                    method, round_id=round_id, variant_id=variant_id, repeat=repeat_id
                )

        while True:
            await asyncio.gather(
                *[chain(round_id_base + round_id) for round_id in range(multiply)]
            )
            if not loop:
                break


def task_message_from_namespace(ns: argparse.Namespace) -> CheckerTaskMessage:
    task_chain_id = ns.task_chain_id
    method = CheckerMethod(ns.method)
    if not task_chain_id:
        option = None
        if method in (CheckerMethod.PUTFLAG, CheckerMethod.GETFLAG):
            option = "flag"
        elif method in (CheckerMethod.PUTNOISE, CheckerMethod.GETNOISE):
            option = "noise"
        elif method == CheckerMethod.HAVOC:
            option = "havoc"
        elif method == CheckerMethod.EXPLOIT:
            option = "exploit"
        elif method == CheckerMethod.TEST:
            option = "test"
        else:
            raise ValueError(f"Unexpected CheckerMethod: {method}")
        task_chain_id = (
            f"{option}_s0_r{ns.related_round_id}_t{ns.team_id}_i{ns.variant_id}"
        )

    flag_hash = None
    if method == CheckerMethod.EXPLOIT:
        flag_hash = hashlib.sha256(ns.flag.encode()).hexdigest()

    msg = CheckerTaskMessage(
        task_id=ns.task_id,
        method=method,
        address=ns.service_address,
        team_id=ns.team_id,
        team_name=ns.team_name,
        current_round_id=ns.current_round_id,
        related_round_id=ns.related_round_id,
        flag=ns.flag if method != CheckerMethod.EXPLOIT else None,
        variant_id=ns.variant_id,
        timeout=int(ns.timeout * 1000),
        round_length=ns.round_length,
        task_chain_id=task_chain_id,
        flag_regex=ns.flag_regex,
        flag_hash=flag_hash,
        attack_info=ns.attack_info,
        seed=ns.seed,
    )

    return msg


def dispatch_raw_task(
    checker_address: str, checker_port: int, task: CheckerTaskMessage
):
    msg = task.model_dump_json()

    result = requests.post(
        f"http://{checker_address}:{checker_port}",
        data=msg,
        headers={"content-type": "application/json"},
    )
    if result.ok:
        result_msg = CheckerResultMessage.model_validate_json(result.text)
        print(result_msg.result)
        if result_msg.metadata is not None:
            print(result_msg.metadata)
    else:
        print(result.status_code)
        print(result.text)


def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Your friendly checker script", allow_abbrev=True
    )

    parser.add_argument(
        "-a",
        "--checker-address",
        default=os.environ.get("ENOCHECKER_CHECKER_ADDRESS", "localhost"),
        help="The address on which the checker is listening",
    )
    parser.add_argument(
        "-n",
        "--checker-network",
        help="The name of the checker docker network to determine the IP from",
        default=os.environ.get("ENOCHECKER_CHECKER_NETWORK"),
    )
    parser.add_argument(
        "-p",
        "--checker-port",
        type=int,
        choices=range(1, 65536),
        default=int(os.environ.get("ENOCHECKER_CHECKER_PORT", "-1")),
        metavar="{1..65535}",
        help="The port on which the checker is listening",
    )
    parser.add_argument(
        "-A",
        "--service-address",
        help="The address on which the checker can reach the service",
        default=os.environ.get("ENOCHECKER_SERVICE_ADDRESS", ""),
    )
    parser.add_argument(
        "-N",
        "--service-network",
        help="The name of the service docker network to determine the IP from",
        default=os.environ.get("ENOCHECKER_SERVICE_NETWORK"),
    )
    parser.add_argument(
        "--flag-regex",
        type=str,
        help="Regular expression used for matching flags",
        default=r"ENO[a-zA-Z0-9+/]{48}",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help=f"Number of seconds to wait until a checker task completes "
        f"(default: {DEFAULT_TIMEOUT_S}, sim: {DEFAULT_SIM_TIMEOUT_S} like the gameserver)",
    )

    commands_group = parser.add_subparsers(dest="command", title="Commands")
    raw_parser = commands_group.add_parser(
        "raw", help="build and dispatch a single raw checker task"
    )
    run_parser = commands_group.add_parser("run", help="run checker task chains")
    sim_parser = commands_group.add_parser("sim", help="simulate checker load")

    raw_parser.add_argument(
        "--task-id",
        type=int,
        default=1,
        help="unique id for task",
    )
    raw_parser.add_argument(
        "--team-id",
        type=int,
        default=1,
        help="id of the target team",
    )
    raw_parser.add_argument(
        "--team-name",
        type=str,
        default="team1",
        help="name of the target team",
    )
    raw_parser.add_argument(
        "--current-round-id",
        type=int,
        default=1,
        help="id of the current round",
    )
    raw_parser.add_argument(
        "--related-round-id",
        type=int,
        default=1,
        help="id of the round in which database info was stored",
    )
    raw_parser.add_argument(
        "--flag",
        type=str,
        default="ENOFLAGENOFLAG=",
        help="flag for putflag/getflag or flag to find in exploit mode",
    )
    raw_parser.add_argument(
        "--variant-id",
        type=int,
        default=0,
        help="variantId for the method being called",
    )
    raw_parser.add_argument(
        "--round-length",
        type=int,
        default=300000,
        help="round length in milliseconds (default 300 000)",
    )
    raw_parser.add_argument(
        "--task-chain-id",
        type=str,
        default=None,
        help="unique id which must be identical for all related putflag/getflag calls and putnoise/getnoise calls",
    )
    raw_parser.add_argument(
        "--seed",
        type=str,
        default=None,
        help="seed the checker should use for random behaviour",
    )
    raw_parser.add_argument(
        "--attack-info",
        type=str,
        default=None,
        help="attack info returned by the corresponding putflag, used only when running the exploit method",
    )
    raw_parser.add_argument(
        "method", choices=TASK_TYPES, help="one of: {}".format(", ".join(TASK_TYPES))
    )

    run_parser.add_argument(
        "-m",
        "--multiply",
        type=int,
        default=1,
        help="number of chain copies to run concurrently",
    )
    run_parser.add_argument("--loop", action="store_true", help="run continuously")
    targets = sum([[t, f"{t}-N"] for t in TASK_TYPES], []) + ["all"]
    run_parser.add_argument(
        "targets", nargs="+", help="one of: {}".format(", ".join(targets))
    )
    run_parser.add_argument(
        "--auto",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="choose whether to automatically add required methods (default: yes)",
    )
    run_parser.add_argument(
        "-s", "--seed", type=int, default=0, help="seed for task generator"
    )

    sim_parser.add_argument(
        "-t",
        "--teams",
        "-m",
        "--multiply",
        dest="teams",
        type=int,
        default=1,
        help="number of teams the gameserver checks each round; each runs "
        "its own schedule draw (default: 1)",
    )
    sim_parser.add_argument(
        "--rounds",
        type=int,
        default=None,
        help="number of rounds to simulate (default: run until interrupted)",
    )
    sim_parser.add_argument(
        "--round-time",
        type=int,
        default=DEFAULT_SIM_ROUND_TIME_S,
        metavar="SECONDS",
        help=f"round length (default: {DEFAULT_SIM_ROUND_TIME_S})",
    )
    sim_parser.add_argument(
        "--check-past-rounds",
        type=int,
        default=EnoConfig.check_past_rounds,
        metavar="N",
        help="rounds after the one it was stored in that a flag keeps being "
        "checked with getflag; match the game's flag validity "
        f"(default: {EnoConfig.check_past_rounds})",
    )
    sim_parser.add_argument(
        "--checker-hold",
        type=int,
        default=EnoConfig.checker_hold,
        metavar="SECONDS",
        help="seconds at the end of each round in which no task runs "
        f"(default: {EnoConfig.checker_hold})",
    )
    sim_parser.add_argument(
        "--concurrency",
        type=int,
        default=None,
        metavar="C",
        help="max concurrent checker requests per team "
        "(default: --concurrency-factor times the minimum the round needs)",
    )
    sim_parser.add_argument(
        "--concurrency-factor",
        type=int,
        default=EnoConfig.concurrency_factor,
        metavar="F",
        help="headroom over the minimum per-team concurrency when "
        f"--concurrency is unset (default: {EnoConfig.concurrency_factor})",
    )
    sim_parser.add_argument(
        "--pool-size",
        type=int,
        default=EnoConfig.pool_size,
        help="number of precomputed schedules each draw picks from "
        f"(default: {EnoConfig.pool_size})",
    )
    sim_parser.add_argument(
        "--exploiters",
        type=int,
        default=0,
        help="additionally run every exploit variant this many times per "
        "round; not gameserver traffic (default: 0)",
    )
    sim_parser.add_argument(
        "--statistics",
        metavar="PATH",
        help="write one CSV row per task into this file",
        type=pathlib.Path,
    )
    sim_parser.add_argument(
        "-s", "--seed", type=int, default=0, help="seed for task ids and schedules"
    )

    args = parser.parse_args()
    if args.timeout is None:
        args.timeout = (
            DEFAULT_SIM_TIMEOUT_S if args.command == "sim" else DEFAULT_TIMEOUT_S
        )

    if args.service_network or args.checker_network:
        import docker

        client = docker.from_env()
        if args.service_network and not args.service_address:
            network = client.networks.get(args.service_network)
            args.service_address = network.attrs["IPAM"]["Config"][0]["Gateway"]

        if args.checker_network and not args.checker_address:
            network = client.networks.get(args.service_network)
            args.checker_address = network.attrs["IPAM"]["Config"][0]["Gateway"]

    if args.service_address == "":
        raise ValueError("Specify service address via -A or ENOCHECKER_SERVICE_ADDRESS")
    if args.checker_port == -1:
        raise ValueError("Specify checker port via -p or ENOCHECKER_CHECKER_PORT")

    if args.command == "raw":
        task = task_message_from_namespace(args)
        dispatch_raw_task(args.checker_address, args.checker_port, task)
    elif args.command == "run":
        asyncio.run(
            run_chain(
                checker_address=args.checker_address,
                checker_port=args.checker_port,
                service_address=args.service_address,
                multiply=args.multiply,
                flag_regex=args.flag_regex,
                loop=args.loop,
                targets=args.targets,
                timeout=args.timeout,
                auto=args.auto,
                seed=args.seed,
            )
        )
    elif args.command == "sim":
        try:
            asyncio.run(
                run_sim(
                    checker_address=args.checker_address,
                    checker_port=args.checker_port,
                    service_address=args.service_address,
                    rounds=args.rounds,
                    teams=args.teams,
                    exploiters=args.exploiters,
                    flag_regex=args.flag_regex,
                    output=args.statistics,
                    seed=args.seed,
                    round_time=args.round_time,
                    eno=EnoConfig(
                        check_past_rounds=args.check_past_rounds,
                        timeout=args.timeout,
                        checker_hold=args.checker_hold,
                        concurrency=args.concurrency,
                        concurrency_factor=args.concurrency_factor,
                        pool_size=args.pool_size,
                    ),
                )
            )
        except ScheduleError as e:
            sys.exit(f"error: {e}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
