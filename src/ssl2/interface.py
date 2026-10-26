import errno
import select
import socket
from collections import OrderedDict
from collections.abc import Buffer, Callable, Sequence
from dataclasses import dataclass
from threading import Lock
from typing import Protocol, Self, overload

from ssl2.client_hello import ClientHello
from ssl2.credentials import SigningChain, TrustStore
from ssl2.errors import ConfigurationError, RaggedEOF, WantReadError, WantWriteError
from ssl2.parameters import CipherSuite, NextProtocol, TLSVersion
from ssl2.proxy import Proxy, ProxyError, ProxyScheme

RECEIVE_SIZE = 65536


@dataclass(frozen=True, slots=True)
class TLSClientConfiguration:
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
        if self.client_hello is not None and any(
            value is not None for value in described
        ):
            raise ConfigurationError(
                "client_hello already describes the ciphers, inner protocols and versions"
            )


@dataclass(frozen=True, slots=True)
class TLSServerConfiguration:
    certificate_chain: Sequence[SigningChain] | None = None
    ciphers: Sequence[CipherSuite] | None = None
    inner_protocols: Sequence[NextProtocol | bytes] | None = None
    lowest_supported_version: TLSVersion | None = None
    highest_supported_version: TLSVersion | None = None
    trust_store: TrustStore | None = None


class TLSBuffer(Protocol):
    @overload
    def read(self, amt: int) -> bytes: ...

    @overload
    def read(self, amt: int, buffer: Buffer) -> int: ...

    def write(self, buf: Buffer) -> int: ...

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
class TLSImplementation[ClientContextT: ClientContext, ServerContextT: ServerContext]:
    client_context: type[ClientContextT]
    server_context: type[ServerContextT]
    validate_config: Callable[[TLSClientConfiguration | TLSServerConfiguration], None]


class SessionCache:
    def __init__(self, limit: int = 1024) -> None:
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
class Listening:
    listener: socket.socket
    accept: Callable[[], TLSBuffer]


@dataclass(frozen=True, slots=True)
class Connected:
    buffer: TLSBuffer
    transport: Transport
    # the socket BoringSSL reads and writes itself; None when the records go through the transport in Python
    socket: socket.socket | None = None


class TLSSocket:
    def __init__(
        self, context: ClientContext | ServerContext, state: Listening | Connected
    ) -> None:
        self._context = context
        self._state = state
        self._unsent = b""
        # the timeout of an attached socket lives here: the socket itself stays non-blocking for BoringSSL
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
    ) -> Self:
        buffer = context.create_buffer(address[0])
        if proxy is None:
            return cls.open_socket(
                context, buffer, socket.create_connection(address, timeout=timeout)
            )
        if proxy.scheme is ProxyScheme.HTTPS:
            hop = cls.connect(
                context if proxy_context is None else proxy_context,
                (proxy.host, proxy.port),
                timeout=timeout,
            )
            try:
                return cls.open(context, buffer, hop, cls._tunnel(proxy, address, hop))
            except BaseException:
                hop.close()
                raise
        plain = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
        try:
            leftover = cls._tunnel(proxy, address, plain)
            if leftover:
                return cls.open(context, buffer, plain, leftover)
            return cls.open_socket(context, buffer, plain)
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
    ) -> Self:
        self = cls(context, Connected(buffer, transport))
        if leftover:
            buffer.process_incoming(leftover)
        self._run(buffer.do_handshake)
        return self

    @classmethod
    def open_socket(
        cls,
        context: ClientContext | ServerContext,
        buffer: TLSBuffer,
        sock: socket.socket,
    ) -> Self:
        buffer.attach(sock.fileno())
        self = cls(context, Connected(buffer, sock, sock))
        self._timeout = sock.gettimeout()
        sock.setblocking(False)
        try:
            self._run(buffer.do_handshake)
        except BaseException:
            sock.close()
            raise
        return self

    @classmethod
    def bind(cls, context: ServerContext, address: tuple[str | None, int]) -> Self:
        host, port = address
        family = socket.AF_INET6 if host and ":" in host else socket.AF_INET
        return cls(
            context,
            Listening(
                socket.create_server((host or "", port), family=family),
                context.create_buffer,
            ),
        )

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

    def send(self, bytes: Buffer) -> int:
        buffer = self._connected().buffer
        return self._run(lambda: buffer.write(bytes))

    def close(self, force: bool = False) -> None:
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

    def listen(self, backlog: int) -> None:
        self._listening().listener.listen(backlog)

    def accept(self) -> tuple[Self, tuple[str | None, int]]:
        listening = self._listening()
        accepted: tuple[socket.socket, tuple[str | None, int]] = (
            listening.listener.accept()
        )
        return type(self).open_socket(
            self._context, listening.accept(), accepted[0]
        ), accepted[1]

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
        if isinstance(self._state, Connected) and self._state.socket is not None:
            self._timeout = value
        else:
            self._endpoint().settimeout(value)

    def gettimeout(self) -> float | None:
        if isinstance(self._state, Connected) and self._state.socket is not None:
            return self._timeout
        return self._endpoint().gettimeout()

    def fileno(self) -> int:
        return self._endpoint().fileno()

    @classmethod
    def _tunnel(
        cls, proxy: Proxy, destination: tuple[str, int], transport: Transport
    ) -> bytes:
        host, port = destination
        if (family := proxy.scheme.local_address_family) is not None:
            host = str(
                socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)[0][4][0]
            )
        conversation = proxy.converse((host, port))
        pending = bytearray()
        step = next(conversation)
        while True:
            request, expected = step
            view = memoryview(request)
            while view:
                view = view[transport.send(view) :]
            while not (end := Proxy.reply_length(pending, expected)):
                piece = transport.recv(RECEIVE_SIZE)
                if not piece:
                    raise ProxyError(
                        "the proxy closed the connection during the tunnel handshake"
                    )
                pending += piece
            reply = bytes(pending[:end])
            del pending[:end]
            try:
                step = conversation.send(reply)
            except StopIteration:
                return bytes(pending)

    def _connected(self) -> Connected:
        if isinstance(self._state, Listening):
            raise OSError(errno.ENOTCONN, "the socket is listening, not connected")
        return self._state

    def _listening(self) -> Listening:
        if isinstance(self._state, Connected):
            raise OSError(errno.EINVAL, "the socket is connected, not listening")
        return self._state

    def _endpoint(self) -> Transport:
        return (
            self._state.listener
            if isinstance(self._state, Listening)
            else self._state.transport
        )

    def _run[ResultT](self, operation: Callable[[], ResultT]) -> ResultT:
        connection = self._connected()
        sock = connection.socket
        while True:
            try:
                result = operation()
            except WantReadError:
                if sock is None:
                    self._flush(connection)
                    self._fill(connection)
                elif self._timeout == 0:
                    raise
                else:
                    self._wait(sock, reading=True)
                continue
            except WantWriteError:
                if sock is None:
                    self._flush(connection)
                elif self._timeout == 0:
                    raise
                else:
                    self._wait(sock, reading=False)
                continue
            if sock is None:
                self._flush(connection)
            return result

    def _wait(self, sock: socket.socket, *, reading: bool) -> None:
        readable, writable, _ = select.select(
            [sock] if reading else [], [] if reading else [sock], [], self._timeout
        )
        if not readable and not writable:
            raise TimeoutError("timed out")

    def _flush(self, connection: Connected) -> None:
        while self._unsent or connection.buffer.outgoing_bytes_buffered():
            if not self._unsent:
                self._unsent = connection.buffer.process_outgoing(RECEIVE_SIZE)
            try:
                sent = connection.transport.send(self._unsent)
            except BlockingIOError:
                raise WantWriteError("the transport is not ready for writing") from None
            self._unsent = self._unsent[sent:]

    def _fill(self, connection: Connected) -> None:
        try:
            data = connection.transport.recv(RECEIVE_SIZE)
        except BlockingIOError:
            raise WantReadError("the transport has no data yet") from None
        if not data:
            raise RaggedEOF("the transport closed before close_notify")
        connection.buffer.process_incoming(data)

    def _shutdown_once(self, connection: Connected) -> None:
        try:
            connection.buffer.shutdown()
        except WantReadError, WantWriteError:
            pass
        if connection.socket is None:
            self._flush(connection)
