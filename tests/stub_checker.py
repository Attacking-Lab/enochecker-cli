"""In-process stand-in for an enochecker3 checker.

It keeps per-chain state the way a real checker does, so a getflag only
passes when it carries the flag and attack info its own putflag stored. It
also records every request it serves, for the test to check against.
"""

from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from enochecker_core import (
    CheckerInfoMessage,
    CheckerMethod,
    CheckerResultMessage,
    CheckerTaskMessage,
    CheckerTaskResult,
)


@dataclass(frozen=True)
class Served:
    received: float
    message: CheckerTaskMessage
    result: CheckerTaskResult


class StubChecker:
    def __init__(
        self,
        *,
        flag_variants: int = 2,
        noise_variants: int = 1,
        havoc_variants: int = 1,
        exploit_variants: tuple[int, ...] = (0,),
        havoc_delay_s: float = 0.0,
    ) -> None:
        self.info = CheckerInfoMessage(
            service_name="stub",
            flag_variants=flag_variants,
            noise_variants=noise_variants,
            havoc_variants=havoc_variants,
            exploit_variants=list(exploit_variants),
            test_variants=0,
        )
        self.havoc_delay_s = havoc_delay_s
        self.served: list[Served] = []
        self._flags: dict[str, tuple[str, str]] = {}
        self._noise: set[str] = set()
        self._lock = threading.Lock()
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._server.daemon_threads = True
        # A client that gave up on a slow task closes the socket under the
        # reply; that is the expected outcome here, not an error to print.
        self._server.handle_error = lambda request, client_address: None  # type: ignore[method-assign]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    def __enter__(self) -> StubChecker:
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._server.shutdown()
        self._server.server_close()

    def handle(self, message: CheckerTaskMessage) -> CheckerResultMessage:
        chain = message.task_chain_id
        match message.method:
            case CheckerMethod.PUTFLAG:
                assert message.flag is not None
                attack_info = f"attack-info-{chain}"
                with self._lock:
                    self._flags[chain] = (message.flag, attack_info)
                return CheckerResultMessage(
                    result=CheckerTaskResult.OK, attack_info=attack_info
                )
            case CheckerMethod.GETFLAG:
                with self._lock:
                    stored = self._flags.get(chain)
                if stored != (message.flag, message.attack_info):
                    return CheckerResultMessage(
                        result=CheckerTaskResult.MUMBLE, message="flag not found"
                    )
            case CheckerMethod.PUTNOISE:
                with self._lock:
                    self._noise.add(chain)
            case CheckerMethod.GETNOISE:
                with self._lock:
                    found = chain in self._noise
                if not found:
                    return CheckerResultMessage(
                        result=CheckerTaskResult.MUMBLE, message="noise not found"
                    )
            case CheckerMethod.HAVOC:
                time.sleep(self.havoc_delay_s)
            case CheckerMethod.EXPLOIT:
                with self._lock:
                    flags = [flag for flag, _ in self._flags.values()]
                for flag in flags:
                    if hashlib.sha256(flag.encode()).hexdigest() == message.flag_hash:
                        return CheckerResultMessage(
                            result=CheckerTaskResult.OK, flag=flag
                        )
                return CheckerResultMessage(
                    result=CheckerTaskResult.MUMBLE, message="Flag not found"
                )
        return CheckerResultMessage(result=CheckerTaskResult.OK)

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                pass

            def _reply(self, body: str) -> None:
                data = body.encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                self._reply(stub.info.model_dump_json(by_alias=True))

            def do_POST(self) -> None:
                received = time.monotonic()
                length = int(self.headers["Content-Length"])
                message = CheckerTaskMessage.model_validate_json(
                    self.rfile.read(length)
                )
                result = stub.handle(message)
                with stub._lock:
                    stub.served.append(Served(received, message, result.result))
                self._reply(result.model_dump_json(by_alias=True))

        return Handler
