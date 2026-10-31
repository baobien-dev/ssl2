import contextlib
import errno
import logging
import select
import socket
from collections import OrderedDict
from collections.abc import Buffer, Callable, Sequence
from dataclasses import dataclass
from enum import IntEnum
from threading import Lock
from typing import Protocol, Self, overload

from ssl2.client_hello import ClientHello
from ssl2.credentials import SigningChain, TrustStore
from ssl2.errors import (
    ConfigurationError,
    ProxyError,
    RaggedEOF,
    WantReadError,
    WantWriteError,
)
from ssl2.proxy import Proxy, ProxyScheme
from ssl2.registry import CipherSuite, NextProtocol, TLSVersion
from ssl2.tracing import Event, Phase, Trace
from ssl2.value import Value


class Limit(IntEnum):
    # one read from a transport, and the plaintext one call hands over
    RECEIVE = 65536
    SESSION_CACHE = 1024


@dataclass(frozen=True, slots=True)
class TLSClientConfiguration(Value):
    certificate_chain: SigningChain | None = None
    ciphers: Sequence[CipherSuite] | None = None
    inner_protocols: Sequence[NextProtocol | bytes] | None = None
    lowest_supported_version: TLSVersion | None = None
    highest_supported_version: TLSVersion | None = None
    trust_store: TrustStore | None = None
    client_hello: ClientHello | None = None
    verify_certificates: bool = True

    def __post_init__(self) -> None:
        described = (
            self.ciphers,
            self.inner_protocols,
            self.lowest_supported_version,
            self.highest_supported_version,
        )
        if self.client_hello is not None and any(value is not None for value in described):
            raise ConfigurationError("client_hello already describes the ciphers, inner protocols and versions")


@dataclass(frozen=True, slots=True)
class TLSServerConfiguration(Value):
    certificate_chain: Sequence[SigningChain] | None = None
    ciphers: Sequence[CipherSuite] | None = None
    inner_protocols: Sequence[NextProtocol | bytes] | None = None
    lowest_supported_version: TLSVersion | None = None
    highest_supported_version: TLSVersion | None = None
    trust_store: TrustStore | None = None


class TLSBuffer(Protocol):
    @overload
    def read(self, amount: int) -> bytes: ...

    @overload
    def read(self, amount: int, buffer: Buffer) -> int: ...

    def write(self, data: Buffer) -> int: ...

    def do_handshake(self) -> None: ...

    def cipher(self) -> CipherSuite | int | None: ...

    def negotiated_protocol(self) -> NextProtocol | bytes | None: ...

    @property
    def context(self) -> ClientContext | ServerContext: ...

    @property
    def negotiated_tls_version(self) -> TLSVersion | None: ...

    def shutdown(self) -> None: ...

    def process_incoming(self, data_from_network: bytes) -> None: ...

    def incoming_bytes_buffered(self) -> int: ...

    def process_outgoing(self, amount_bytes_for_network: int) -> bytes: ...

    def outgoing_bytes_buffered(self) -> int: ...

    def getpeercert(self) -> bytes | None: ...

    def getpeerchain(self) -> tuple[bytes, ...]: ...

    def attach(self, fileno: int, /) -> None: ...


class ClientContext(Protocol):
    def __init__(self, configuration: TLSClientConfiguration) -> None: ...

    @property
    def configuration(self) -> TLSClientConfiguration: ...

    def connect(self, address: tuple[str | None, int]) -> TLSSocket: ...

    def create_buffer(self, server_hostname: str) -> TLSBuffer: ...


class ServerContext(Protocol):
    def __init__(self, configuration: TLSServerConfiguration) -> None: ...

    @property
    def configuration(self) -> TLSServerConfiguration: ...

    def connect(self, address: tuple[str | None, int]) -> TLSSocket: ...

    def create_buffer(self) -> TLSBuffer: ...


@dataclass(frozen=True, slots=True)
class TLSImplementation[ClientContextT: ClientContext, ServerContextT: ServerContext](Value):
    client_context: type[ClientContextT]
    server_context: type[ServerContextT]
    validate_config: Callable[[TLSClientConfiguration | TLSServerConfiguration], None]


class SessionCache:
    # the sessions an engine recorded, newest last; a single use session is handed out once
    def __init__(self, limit: int = Limit.SESSION_CACHE) -> None:
        self._entries: OrderedDict[str, tuple[bytes, bool]] = OrderedDict()
        self._limit = limit
        self._lock = Lock()

    def store(self, key: str, session: bytes, *, single_use: bool) -> None:
        with self._lock:
            self._entries[key] = (session, single_use)
            self._entries.move_to_end(key)
            while len(self._entries) > self._limit:
                self._entries.popitem(last=False)

    def take(self, key: str) -> bytes | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            session, single_use = entry
            if single_use:
                del self._entries[key]
            return session

    def __len__(self) -> int:
        return len(self._entries)


class Transport(Protocol):
    def recv(self, bufsize: int, /) -> bytes: ...

    def send(self, data: Buffer, /) -> int: ...

    def close(self) -> None: ...

    def getsockname(self) -> tuple[str | None, int]: ...

    def getpeername(self) -> tuple[str | None, int]: ...

    def settimeout(self, value: float | None, /) -> None: ...

    def gettimeout(self) -> float | None: ...

    def fileno(self) -> int: ...


@dataclass(frozen=True, slots=True)
class Listening(Value):
    listener: socket.socket
    accept: Callable[[], TLSBuffer]


@dataclass(frozen=True, slots=True)
class Connected(Value):
    buffer: TLSBuffer
    transport: Transport
    # the socket the engine reads and writes itself; None when the records go through the transport here
    tcp_socket: socket.socket | None = None


class TLSSocket:
    logger = logging.getLogger("ssl2")

    def __init__(self, context: ClientContext | ServerContext, state: Listening | Connected) -> None:
        self._context = context
        self._state = state
        self._unsent = b""
        # the timeout of an attached socket lives here; the socket itself stays non-blocking for the engine
        self._timeout: float | None = None

    @classmethod
    def connect(
        cls,
        context: ClientContext,
        address: tuple[str, int],
        *,
        proxy: Proxy | None = None,
        timeout: float | None = None,
        proxy_context: ClientContext | None = None,
        server_hostname: str | None = None,
        trace: Trace | None = None,
    ) -> Self:
        trace = trace or Trace()
        buffer = context.create_buffer(address[0] if server_hostname is None else server_hostname)
        if proxy is None:
            with trace.span(Phase.CONNECT):
                tcp_socket = socket.create_connection(address, timeout=timeout)
            cls.logger.info("%s host=%s port=%d", Event.CONNECTED, address[0], address[1])
            return cls.open_socket(context, buffer, tcp_socket, trace)
        if proxy.scheme is ProxyScheme.HTTPS:
            hop = cls.connect(
                context if proxy_context is None else proxy_context,
                proxy.address,
                timeout=timeout,
                trace=trace,
            )
            try:
                leftover = cls._tunnel(proxy, address, hop, trace)
                return cls.open(context, buffer, hop, leftover, trace)
            except BaseException:
                hop.close()
                raise
        with trace.span(Phase.CONNECT):
            plain = socket.create_connection(proxy.address, timeout=timeout)
        cls.logger.info(
            "%s host=%s port=%d proxy=%s",
            Event.CONNECTED,
            proxy.host,
            proxy.port,
            proxy.scheme,
        )
        try:
            leftover = cls._tunnel(proxy, address, plain, trace)
            if leftover:
                return cls.open(context, buffer, plain, leftover, trace)
            return cls.open_socket(context, buffer, plain, trace)
        except BaseException:
            plain.close()
            raise

    @classmethod
    def open(
        cls,
        context: ClientContext | ServerContext,
        buffer: TLSBuffer,
        transport: Transport,
        leftover: bytes = b"",
        trace: Trace | None = None,
    ) -> Self:
        self = cls(context, Connected(buffer, transport))
        if leftover:
            buffer.process_incoming(leftover)
        self._handshake(trace or Trace())
        return self

    @classmethod
    def open_socket(
        cls,
        context: ClientContext | ServerContext,
        buffer: TLSBuffer,
        tcp_socket: socket.socket,
        trace: Trace | None = None,
    ) -> Self:
        buffer.attach(tcp_socket.fileno())
        self = cls(context, Connected(buffer, tcp_socket, tcp_socket))
        self._timeout = tcp_socket.gettimeout()
        # a zero timeout is the non-blocking mode the engine's own reads and writes need
        tcp_socket.settimeout(0)
        try:
            self._handshake(trace or Trace())
        except BaseException:
            tcp_socket.close()
            raise
        return self

    @classmethod
    def bind(cls, context: ServerContext, address: tuple[str | None, int]) -> Self:
        host, port = address
        family = socket.AF_INET6 if host and ":" in host else socket.AF_INET
        listener = socket.create_server((host or "", port), family=family)
        return cls(context, Listening(listener, context.create_buffer))

    @property
    def context(self) -> ClientContext | ServerContext:
        return self._context

    @property
    def buffer(self) -> TLSBuffer:
        return self._connected().buffer

    def recv(self, bufsize: int) -> bytes:
        buffer = self._connected().buffer
        try:
            return self._run(lambda: buffer.read(bufsize))
        except RaggedEOF:
            # the ssl module's default: a peer that drops TCP without close_notify reads as end of stream
            return b""

    def send(self, data: Buffer) -> int:
        buffer = self._connected().buffer
        return self._run(lambda: buffer.write(data))

    def close(self, *, force: bool = False) -> None:
        if isinstance(self._state, Listening):
            self._state.listener.close()
            return
        connection = self._state
        try:
            if force:
                self._shutdown_once(connection)
            else:
                self._run(connection.buffer.shutdown)
        except RaggedEOF, OSError:
            pass
        connection.transport.close()
        self.logger.info("%s", Event.CLOSED)

    def listen(self, backlog: int) -> None:
        self._listening().listener.listen(backlog)

    def accept(self) -> tuple[Self, tuple[str | None, int]]:
        listening = self._listening()
        accepted, peer = listening.listener.accept()
        return type(self).open_socket(self._context, listening.accept(), accepted), peer

    def getsockname(self) -> tuple[str | None, int]:
        return self._endpoint().getsockname()

    def getpeername(self) -> tuple[str | None, int]:
        return self._endpoint().getpeername()

    def getpeercert(self) -> bytes | None:
        return self._connected().buffer.getpeercert()

    def getpeerchain(self) -> tuple[bytes, ...]:
        return self._connected().buffer.getpeerchain()

    def cipher(self) -> CipherSuite | int | None:
        return self._connected().buffer.cipher()

    def negotiated_protocol(self) -> NextProtocol | bytes | None:
        return self._connected().buffer.negotiated_protocol()

    @property
    def negotiated_tls_version(self) -> TLSVersion | None:
        return self._connected().buffer.negotiated_tls_version

    def settimeout(self, value: float | None) -> None:
        if isinstance(self._state, Connected) and self._state.tcp_socket is not None:
            self._timeout = value
        else:
            self._endpoint().settimeout(value)

    def gettimeout(self) -> float | None:
        if isinstance(self._state, Connected) and self._state.tcp_socket is not None:
            return self._timeout
        return self._endpoint().gettimeout()

    def fileno(self) -> int:
        return self._endpoint().fileno()

    @classmethod
    def _tunnel(
        cls,
        proxy: Proxy,
        destination: tuple[str, int],
        transport: Transport,
        trace: Trace,
    ) -> bytes:
        # drives the proxy handshake over the transport; returns what arrived after the proxy's last reply
        host, port = destination
        with trace.span(Phase.PROXY):
            if (family := proxy.scheme.local_address_family) is not None:
                host = str(socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)[0][4][0])
            handshake = proxy.handshake((host, port))
            pending = bytearray()
            step = handshake.first()
            while step is not None:
                view = memoryview(step.request)
                while view:
                    view = view[transport.send(view) :]
                while not (end := step.reply_end(bytes(pending))):
                    piece = transport.recv(Limit.RECEIVE)
                    if not piece:
                        raise ProxyError("the proxy closed the connection during the tunnel handshake")
                    pending += piece
                reply = bytes(pending[:end])
                del pending[:end]
                cls.logger.debug(
                    "%s proxy=%s sent=%d received=%d",
                    Event.PROXY_STEP,
                    proxy.scheme,
                    len(step.request),
                    end,
                )
                step = handshake.next(reply)
        cls.logger.info(
            "%s proxy=%s host=%s port=%d",
            Event.PROXY_TUNNELED,
            proxy.scheme,
            host,
            port,
        )
        return bytes(pending)

    def _handshake(self, trace: Trace) -> None:
        buffer = self._connected().buffer
        try:
            with trace.span(Phase.HANDSHAKE):
                self._run(buffer.do_handshake)
        except Exception as error:
            self.logger.warning("%s step=handshake error=%s", Event.FAILED, error)
            raise
        self.logger.info(
            "%s version=%s cipher=%s protocol=%s",
            Event.HANDSHAKE_DONE,
            buffer.negotiated_tls_version,
            buffer.cipher(),
            buffer.negotiated_protocol(),
        )

    def _connected(self) -> Connected:
        if isinstance(self._state, Listening):
            raise OSError(errno.ENOTCONN, "the socket is listening, not connected")
        return self._state

    def _listening(self) -> Listening:
        if isinstance(self._state, Connected):
            raise OSError(errno.EINVAL, "the socket is connected, not listening")
        return self._state

    def _endpoint(self) -> Transport:
        return self._state.listener if isinstance(self._state, Listening) else self._state.transport

    def _run[ResultT](self, operation: Callable[[], ResultT]) -> ResultT:
        connection = self._connected()
        tcp_socket = connection.tcp_socket
        while True:
            try:
                result = operation()
            except WantReadError:
                if tcp_socket is None:
                    self._flush(connection)
                    self._fill(connection)
                elif self._timeout == 0:
                    raise
                else:
                    self._wait(tcp_socket, reading=True)
                continue
            except WantWriteError:
                if tcp_socket is None:
                    self._flush(connection)
                elif self._timeout == 0:
                    raise
                else:
                    self._wait(tcp_socket, reading=False)
                continue
            if tcp_socket is None:
                self._flush(connection)
            return result

    def _wait(self, tcp_socket: socket.socket, *, reading: bool) -> None:
        readable, writable, _ = select.select(
            [tcp_socket] if reading else [],
            [] if reading else [tcp_socket],
            [],
            self._timeout,
        )
        if not readable and not writable:
            raise TimeoutError("timed out")

    def _flush(self, connection: Connected) -> None:
        while self._unsent or connection.buffer.outgoing_bytes_buffered():
            if not self._unsent:
                self._unsent = connection.buffer.process_outgoing(Limit.RECEIVE)
            try:
                sent = connection.transport.send(self._unsent)
            except BlockingIOError:
                raise WantWriteError("the transport is not ready for writing") from None
            self._unsent = self._unsent[sent:]

    def _fill(self, connection: Connected) -> None:
        try:
            data = connection.transport.recv(Limit.RECEIVE)
        except BlockingIOError:
            raise WantReadError("the transport has no data yet") from None
        if not data:
            raise RaggedEOF("the transport closed before close_notify")
        connection.buffer.process_incoming(data)

    def _shutdown_once(self, connection: Connected) -> None:
        with contextlib.suppress(WantReadError, WantWriteError):
            connection.buffer.shutdown()
        if connection.tcp_socket is None:
            self._flush(connection)
