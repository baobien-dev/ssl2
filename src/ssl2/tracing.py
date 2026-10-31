from dataclasses import dataclass
from enum import StrEnum
from time import monotonic
from types import TracebackType
from typing import override

from ssl2.value import Value


class Event(StrEnum):
    # what the ssl2 logger reports; a filter matches on these names
    RESOLVED = "resolved"
    CONNECTED = "connected"
    PROXY_STEP = "proxy.step"
    PROXY_TUNNELED = "proxy.tunneled"
    HANDSHAKE_DONE = "handshake.done"
    CLOSED = "closed"
    FAILED = "failed"


class Phase(StrEnum):
    # the timed steps of opening a connection
    RESOLVE = "resolve"
    CONNECT = "connect"
    PROXY = "proxy"
    HANDSHAKE = "handshake"


@dataclass(frozen=True, slots=True)
class Span(Value):
    name: str
    start: float
    end: float

    @property
    def duration(self) -> float:
        return self.end - self.start


class Timing:
    def __init__(self, trace: Trace, name: str) -> None:
        self._trace = trace
        self._name = name
        self._start = 0.0

    def __enter__(self) -> None:
        self._start = monotonic()

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._trace.record(Span(self._name, self._start, monotonic()))


class Trace:
    # the timed steps of one operation, on the monotonic clock, kept in the order they ended
    SECONDS_TO_MILLISECONDS = 1000

    def __init__(self) -> None:
        self.spans: list[Span] = []
        self.started = monotonic()

    def span(self, name: str) -> Timing:
        return Timing(self, name)

    def record(self, span: Span) -> None:
        self.spans.append(span)

    @override
    def __str__(self) -> str:
        return ", ".join(
            f"{span.name} {span.duration * self.SECONDS_TO_MILLISECONDS:.1f} ms"
            for span in self.spans
        )

    @property
    def total(self) -> float:
        return (
            max((span.end for span in self.spans), default=self.started) - self.started
        )
