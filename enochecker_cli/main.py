import argparse
import dataclasses
import hashlib
from collections import defaultdict
from io import TextIOWrapper
import random
import pathlib
import time
import types
import asyncio
import collections
import secrets
from typing_extensions import Self
import os
import jsons

from dotenv import load_dotenv
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

TASK_TYPES = [str(i) for i in CheckerMethod]


@dataclasses.dataclass
class LogEntry:
    round_id: int
    operation: str
    variant_id: int
    team: int | None
    time_taken: float
    attempt: int | None = None

    def to_csv(self) -> str:
        return f"{self.round_id},{self.operation},{self.variant_id},{self.attempt or ''},{self.team or ''},{self.time_taken}"


class CheckerClient:
    def __init__(
        self,
        url: str,
        service_address: str,
        output: pathlib.Path | None,
        flag_regex: str,
        timeout: int,
    ):
        self.output_path = output
        self.service_address = service_address
        self.flag_regex = flag_regex
        self.url = url.rstrip("/")
        if "://" not in self.url:
            self.url = "http://" + self.url

        self._id = 0
        self._client = httpx.AsyncClient()
        self._log: TextIOWrapper | None = None
        self._connected = False
        self._token = "loadtest-" + secrets.token_urlsafe(10)
        self._flags: dict[int, dict[int, tuple[str, str | None]]] = (
            collections.defaultdict(dict)
        )
        self._exploit_variants: dict[int, set] = defaultdict(lambda: set())
        self.timeout = timeout

        self.flag_variants = 0
        self.noise_variants = 0
        self.havoc_variants = 0
        self.exploit_variants = 0
        self.service_name = ""

    async def __aenter__(self) -> Self:
        await self._client.__aenter__()
        self._log = (
            open(self.output_path, "w").__enter__() if self.output_path else None
        )
        response = await self._client.get(f"{self.url}/service")
        if response.status_code != 200:
            raise RuntimeError("Failed to get /service from checker")
        metadata = jsons.loads(
            response.text,
            CheckerInfoMessage,
            key_transformer=jsons.KEY_TRANSFORMER_SNAKECASE,
        )
        self.flag_variants = metadata.flag_variants
        self.noise_variants = metadata.noise_variants
        self.havoc_variants = metadata.havoc_variants
        self.exploit_variants = metadata.exploit_variants
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

    async def _request(
        self, message: CheckerTaskMessage
    ) -> tuple[CheckerResultMessage, float]:
        assert self._connected, "Client is not connected (did you forget `async with`)?"
        json = jsons.dumps(
            message,
            use_enum_name=False,
            key_transformer=jsons.KEY_TRANSFORMER_CAMELCASE,
            strict=True,
        )
        start = time.monotonic()
        response = await self._client.post(
            self.url,
            content=json,
            headers={"Content-Type": "application/json"},
            timeout=self.timeout,
        )
        end = time.monotonic()
        assert response.status_code == 200, response.text
        result: CheckerResultMessage = jsons.loads(
            response.text,
            CheckerResultMessage,
            key_transformer=jsons.KEY_TRANSFORMER_SNAKECASE,
        )
        status = CheckerTaskResult(result.result)
        if message.method != CheckerMethod.EXPLOIT:
            assert status == CheckerTaskResult.OK, response.text
        return result, end - start

    def add_log_entries(self, entries: list[LogEntry]) -> None:
        assert self._connected, "Client is not connected (did you forget `async with`)?"
        if self._log:
            for entry in entries:
                self._log.write(entry.to_csv() + "\n")
            self._log.flush()

    def display(self) -> str:
        assert self._connected, "Client is not connected (did you forget `async with`)?"
        return "\n".join(
            [
                f"\x1b[1mservice\x1b[0m:      {self.service_name}",
                f"\x1b[32;1mflag stores\x1b[0m:  {self.flag_variants}",
                f"\x1b[33;1mnoise checks\x1b[0m: {self.noise_variants}",
                f"\x1b[33;1mhavoc checks\x1b[0m: {self.havoc_variants}",
                f"\x1b[31;1mexploits\x1b[0m:     {self.exploit_variants}",
            ]
        )

    def _build_request(
        self,
        *,
        method: CheckerMethod,
        round_id: int,
        flag: str | None,
        variant_id: int,
        attack_info: str | None,
    ) -> CheckerTaskMessage:
        prev_id, self._id = self._id, self._id + 1
        if method in (CheckerMethod.PUTFLAG, CheckerMethod.GETFLAG):
            chain_id = f"flag-{round_id}-{variant_id}-{self._token}"
        elif method in (CheckerMethod.PUTNOISE, CheckerMethod.GETNOISE):
            chain_id = f"noise-{round_id}-{variant_id}-{self._token}"
        else:
            prev_id, self._id = self._id, self._id + 1
            chain_id = f"unique-{prev_id}-{self._token}"
        return CheckerTaskMessage(
            task_id=prev_id,
            method=method,
            address=self.service_address,
            team_id=0,
            team_name="load_test_victim",
            current_round_id=round_id,
            related_round_id=round_id,
            flag=flag,
            variant_id=variant_id,
            timeout=self.timeout * 1000,
            round_length=self.timeout * 1000,
            task_chain_id=chain_id,
            flag_regex=self.flag_regex,
            flag_hash=hashlib.sha256(flag.encode()).hexdigest() if flag else None,
            attack_info=attack_info,
        )

    async def putflag(self, round_id: int, variant_id: int) -> LogEntry:
        flag = exrex.getone(self.flag_regex, limit=64)
        message = self._build_request(
            method=CheckerMethod.PUTFLAG,
            round_id=round_id,
            flag=flag,
            variant_id=variant_id,
            attack_info=None,
        )
        response, duration = await self._request(message)
        self._flags[round_id][variant_id] = (flag, response.attack_info)
        return LogEntry(round_id, "putflag", variant_id, None, duration)

    async def getflag(self, round_id: int, variant_id: int) -> LogEntry:
        flag, attack_info = self._flags[round_id][variant_id]
        message = self._build_request(
            method=CheckerMethod.GETFLAG,
            round_id=round_id,
            flag=flag,
            variant_id=variant_id,
            attack_info=attack_info,
        )
        _, duration = await self._request(message)
        return LogEntry(round_id, "getflag", variant_id, None, duration)

    async def putnoise(self, round_id: int, variant_id: int) -> LogEntry:
        message = self._build_request(
            method=CheckerMethod.PUTNOISE,
            round_id=round_id,
            flag=None,
            variant_id=variant_id,
            attack_info=None,
        )
        _, duration = await self._request(message)
        return LogEntry(round_id, "putnoise", variant_id, None, duration)

    async def getnoise(self, round_id: int, variant_id: int) -> LogEntry:
        message = self._build_request(
            method=CheckerMethod.GETNOISE,
            round_id=round_id,
            flag=None,
            variant_id=variant_id,
            attack_info=None,
        )
        _, duration = await self._request(message)
        return LogEntry(round_id, "getnoise", variant_id, None, duration)

    async def havoc(self, round_id: int, variant_id: int) -> LogEntry:
        message = self._build_request(
            method=CheckerMethod.HAVOC,
            round_id=round_id,
            flag=None,
            variant_id=variant_id,
            attack_info=None,
        )
        _, duration = await self._request(message)
        return LogEntry(round_id, "havoc", variant_id, None, duration)

    async def exploit(
        self, round_id: int, variant_id: int, source_team: int
    ) -> LogEntry:
        flag_ids = list(self._exploit_variants[variant_id])
        if flag_ids == []:
            assert self._connected, (
                "Client is not connected (did you forget `async with`)?"
            )
            flag_ids = list(range(self.flag_variants))

        for flag_id in flag_ids:
            flag, attack_info = self._flags[round_id][flag_id]
            message = self._build_request(
                method=CheckerMethod.EXPLOIT,
                round_id=round_id,
                flag=flag,
                variant_id=variant_id,
                attack_info=attack_info,
            )
            result, duration = await self._request(message)
            if CheckerTaskResult(result.result) == CheckerTaskResult.OK:
                if result.flag == flag:
                    self._exploit_variants[variant_id].add(flag_id)
            else:
                assert result.message == "Flag not found", result.message
            return LogEntry(
                round_id, "exploit", variant_id, source_team, duration, flag_id
            )
        assert False, f"No flag for any flag ID for exploit {variant_id}"

    async def simulate_round(
        self, round_id: int, multiplier: int, exploiters: int
    ) -> None:
        assert self._connected, "Client is not connected (did you forget `async with`)?"

        put: list[tuple] = [
            (self.putflag, variant_id) for variant_id in range(self.flag_variants)
        ] + [(self.putnoise, variant_id) for variant_id in range(self.noise_variants)]
        put = put * multiplier

        get: list[tuple] = (
            [(self.getflag, variant_id) for variant_id in range(self.flag_variants)]
            + [(self.getnoise, variant_id) for variant_id in range(self.noise_variants)]
            + [(self.havoc, variant_id) for variant_id in range(self.havoc_variants)]
        )
        get = get * multiplier
        get += [
            (self.exploit, variant_id, team)
            for variant_id in range(self.exploit_variants)
            for team in range(exploiters)
        ]

        self.add_log_entries(
            await asyncio.gather(*[op(round_id, *args) for op, *args in put])
        )
        self.add_log_entries(
            await asyncio.gather(*[op(round_id, *args) for op, *args in get])
        )


async def run_sim(
    checker_address: str,
    checker_port: int,
    service_address: str,
    rounds: int,
    exploiters: int,
    flag_regex: str,
    multiplier: int,
    output: pathlib.Path | None,
    timeout: int,
):
    url = f"http://{checker_address}:{checker_port}"
    async with CheckerClient(
        url, service_address, output, flag_regex, timeout
    ) as client:
        print(client.display())
        print(f"\x1b[31;1mrounds\x1b[0m:       {rounds}")
        print(f"\x1b[31;1mexploiters\x1b[0m:   {exploiters}")
        print(f"\x1b[31;1mmultiplier\x1b[0m:   {multiplier}")

        round_id_base = random.randint(0, 10000000000)
        with Progress(
            TextColumn("[progress.description]"), BarColumn(), MofNCompleteColumn()
        ) as progress:
            task = progress.add_task("Simulating..", total=rounds)
            for round_id in range(rounds):
                await client.simulate_round(
                    round_id_base + round_id, multiplier, exploiters
                )
                progress.update(task, advance=1)


async def run_chain(
    checker_address: str,
    checker_port: int,
    service_address: str,
    multiply: int,
    flag_regex: str,
    loop: bool,
    targets: list[str],
    timeout: int,
):
    url = f"http://{checker_address}:{checker_port}"
    async with CheckerClient(url, service_address, None, flag_regex, timeout) as client:
        print(client.display())

        used_targets = set()
        resolved_targets = []
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
                    for variant_id in reversed(range(client.exploit_variants)):
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

            method_name, variant_str = target.rsplit("-", 1)
            variant_id = int(variant_str)

            method: tuple
            if method_name == "putflag":
                method = (client.putflag, variant_id)
            elif method_name == "getflag":
                if ("putflag", variant_id) not in used_targets:
                    targets.append(f"putflag-{variant_id}")
                    continue
                method = (client.getflag, variant_id)
            elif method_name == "putnoise":
                method = (client.putnoise, variant_id)
            elif method_name == "getnoise":
                if ("putnoise", variant_id) not in used_targets:
                    targets.append(f"putnoise-{variant_id}")
                    continue
                method = (client.getnoise, variant_id)
            elif method_name == "havoc":
                method = (client.havoc, variant_id)
            elif method_name == "exploit":
                retry = False
                for flag_variant in reversed(range(client.flag_variants)):
                    if ("putflag", flag_variant) not in used_targets:
                        targets.append(f"putflag-{flag_variant}")
                        retry = True
                if retry:
                    continue
                method = (client.exploit, variant_id, 0)
            else:
                raise ValueError(f"Unknown method {method_name}")
            used_targets.add((method_name, variant_id))
            print(f"\x1b[31;1mcall\x1b[0m:         {method_name}-{variant_id}")
            resolved_targets.append(method)

            targets.pop()

        print(f"\x1b[31;1mtotal\x1b[0m:        {len(resolved_targets) * multiply}")

        round_id_base = random.randint(0, 10000000000)

        chains = []
        for round_id in range(multiply):
            round_id_ = round_id

            def gen():
                async def chain(round_id):
                    for method_fn, *args in resolved_targets:
                        await method_fn(round_id_base + round_id, *args)

                return chain(round_id_)

            chains.append(gen)

        while True:
            await asyncio.gather(*[gen() for gen in chains])
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
        timeout=ns.timeout * 1000,
        round_length=ns.round_length,
        task_chain_id=task_chain_id,
        flag_regex=ns.flag_regex,
        flag_hash=flag_hash,
        attack_info=ns.attack_info,
    )

    return msg


def dispatch_raw_task(
    checker_address: str, checker_port: int, task: CheckerTaskMessage
):
    msg = jsons.dumps(
        task,
        use_enum_name=False,
        key_transformer=jsons.KEY_TRANSFORMER_CAMELCASE,
        strict=True,
    )

    result = requests.post(
        f"http://{checker_address}:{checker_port}",
        data=msg,
        headers={"content-type": "application/json"},
    )
    if result.ok:
        result_msg = jsons.loads(result.text, CheckerResultMessage)
        print(result_msg.result)
    else:
        print(result.status_code)
        print(result.text)


def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Your friendly checker script", allow_abbrev=True
    )

    checker_address = os.environ.get("ENOCHECKER_CHECKER_ADDRESS") or ""
    parser.add_argument(
        "-a",
        "--checker-address",
        type=str,
        default=checker_address,
        help="The address on which checker is listening",
    )

    checker_port = int(os.environ.get("ENOCHECKER_CHECKER_PORT") or "-1")
    parser.add_argument(
        "-p",
        "--checker-port",
        type=int,
        default=checker_port,
        metavar="{1..65535}",
        help="The port on which the checker is listening",
    )

    service_address = os.environ.get("ENOCHECKER_SERVICE_ADDRESS") or ""
    parser.add_argument(
        "-A",
        "--service-address",
        type=str,
        default=service_address,
        help="The ip or address of the remote team to check",
    )

    parser.add_argument("--flag-regex", type=str, default=r"ENO[a-zA-Z0-9+/]{48}")

    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Number of seconds to wait until a checker tasks complete",
    )

    commands_group = parser.add_subparsers(dest="command", title="Commands")
    raw_parser = commands_group.add_parser(
        "raw", help="Build and dispatch a single raw checker task"
    )
    run_parser = commands_group.add_parser(
        "run", help="Run (multiple) checker task chains"
    )
    sim_parser = commands_group.add_parser("sim", help="Simulate checker load")

    raw_parser.add_argument(
        "--task-id",
        type=int,
        default=1,
        help="An unique id for this task.",
    )
    raw_parser.add_argument(
        "--team-id",
        type=int,
        default=1,
        help="The Team_id belonging to the specified Team",
    )
    raw_parser.add_argument(
        "--team-name",
        type=str,
        default="team1",
        help="The name of the target team to check",
    )
    raw_parser.add_argument(
        "--current-round-id",
        type=int,
        default=1,
        help="The round we are in right now",
    )
    raw_parser.add_argument(
        "--related-round-id",
        type=int,
        default=1,
        help="The round in which the flag or noise was stored when method is getflag/getnoise. Equal to current_round_id otherwise.",
    )
    raw_parser.add_argument(
        "--flag",
        type=str,
        default="ENOFLAGENOFLAG=",
        help="The flag for putflag/getflag or the flag to find in exploit mode",
    )
    raw_parser.add_argument(
        "--variant-id",
        type=int,
        default=0,
        help="The variantId for the method being called",
    )
    raw_parser.add_argument(
        "--round-length",
        type=int,
        default=300000,
        help="The round length in milliseconds (default 300 000)",
    )
    raw_parser.add_argument(
        "--task-chain-id",
        type=str,
        default=None,
        help="A unique Id which must be identical for all related putflag/getflag calls and putnoise/getnoise calls",
    )
    raw_parser.add_argument(
        "--attack-info",
        type=str,
        default=None,
        help="The attack info returned by the corresponding putflag, used only when running the exploit method",
    )
    raw_parser.add_argument(
        "method", choices=TASK_TYPES, help="One of: {}".format(", ".join(TASK_TYPES))
    )

    run_parser.add_argument(
        "-m",
        "--multiply",
        type=int,
        default=1,
        help="Number of chain copies to run concurrently",
    )
    run_parser.add_argument("--loop", action="store_true", help="Run continuously")
    targets = sum([[t, f"{t}-N"] for t in TASK_TYPES], []) + ["all"]
    run_parser.add_argument(
        "targets", nargs="+", help="One of: {}".format(", ".join(targets))
    )

    sim_parser.add_argument(
        "--exploiters",
        type=int,
        default=50,
        help="The number of exploiters to simulate",
    )
    sim_parser.add_argument(
        "-m",
        "--multiply",
        type=int,
        default=1,
        metavar="FACTOR",
        help="Multiplier for non-exploit traffic",
    )
    sim_parser.add_argument(
        "--rounds", type=int, default=1000, help="The number of rounds to simulate"
    )
    sim_parser.add_argument(
        "--statistics",
        metavar="PATH",
        help="Collect statistics into this file",
        type=pathlib.Path,
    )

    args = parser.parse_args()

    if args.service_address == "":
        raise ValueError("Specify service address via -A or ENOCHECKER_SERVICE_ADDRESS")
    if args.checker_address == "":
        raise ValueError("Specify checker address via -a or ENOCHECKER_CHECKER_ADDRESS")
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
            )
        )
    elif args.command == "sim":
        asyncio.run(
            run_sim(
                checker_address=args.checker_address,
                checker_port=args.checker_port,
                service_address=args.service_address,
                rounds=args.rounds,
                flag_regex=args.flag_regex,
                multiplier=args.multiply,
                exploiters=args.exploiters,
                output=args.statistics,
                timeout=args.timeout,
            )
        )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
