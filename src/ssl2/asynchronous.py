import asyncio
import ipaddress
import logging
import socket
import sys
from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum
from functools import partial
from typing import Protocol, Self

from ssl2.errors import ProxyError, RaggedEOF, WantReadError, WantWriteError
from ssl2.interface import ClientContext, Limit, ServerContext, TLSBuffer
from ssl2.proxy import Proxy, ProxyHandshake, ProxyScheme
from ssl2.registry import CipherSuite, NextProtocol, TLSVersion
from ssl2.tracing import Event, Phase, Trace
from ssl2.value import Value


class Seconds(IntEnum):
    SHUTDOWN = 5


class AsyncTransport(Protocol):
    async def read(self, limit: int, /) -> bytes: ...

    async def write(self, data: bytes, /) -> None: ...

    async def close(self) -> None: ...

    def getsockname(self) -> tuple[str | None, int]: ...

    def getpeername(self) -> tuple[str | None, int]: ...


class StreamTransport:
    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self._reader = reader
        self._writer = writer

    async def read(self, limit: int) -> bytes:
        return await self._reader.read(limit)

    async def write(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()

    async def close(self) -> None:
        self._writer.close()

    def getsockname(self) -> tuple[str | None, int]:
        return self._writer.get_extra_info("sockname")

    def getpeername(self) -> tuple[str | None, int]:
        return self._writer.get_extra_info("peername")


class SocketTransport:
    def __init__(self, tcp_socket: socket.socket) -> None:
        self._socket = tcp_socket
        self._loop = asyncio.get_running_loop()

    @classmethod
    async def connect(cls, address: tuple[str, int]) -> Self:
        # every address the name resolves to is tried in order; the last error is the one raised
        loop = asyncio.get_running_loop()
        host, port = address
        failure = OSError(f"{host}:{port} resolves to no address")
        for family, kind, protocol, _, resolved in await loop.getaddrinfo(
            host, port, type=socket.SOCK_STREAM
        ):
            tcp_socket = socket.socket(family, kind, protocol)
            # a zero timeout is the non-blocking mode the event loop works with
            tcp_socket.settimeout(0)
            tcp_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                await loop.sock_connect(tcp_socket, resolved)
            except OSError as error:
                tcp_socket.close()
                failure = error
                continue
            return cls(tcp_socket)
        raise failure

    @property
    def socket(self) -> socket.socket:
        return self._socket

    async def read(self, limit: int) -> bytes:
        return await self._loop.sock_recv(self._socket, limit)

    async def write(self, data: bytes) -> None:
        await self._loop.sock_sendall(self._socket, data)

    async def close(self) -> None:
        self._socket.close()

    def getsockname(self) -> tuple[str | None, int]:
        return self._socket.getsockname()

    def getpeername(self) -> tuple[str | None, int]:
        return self._socket.getpeername()


class Readiness:
    # waiting on a socket's readiness needs add_reader, which Windows' default event loop does not have
    @staticmethod
    def available(loop: asyncio.AbstractEventLoop) -> bool:
        if sys.platform == "win32":
            return not isinstance(loop, asyncio.ProactorEventLoop)
        return True


@dataclass(frozen=True, slots=True)
class Tunnel(Value):
    transport: AsyncTransport
    leftover: bytes
    # the TCP socket under the transport, when the engine can take it over; None behind a TLS hop
    tcp_socket: socket.socket | None


class TLSStream:
    logger = logging.getLogger("ssl2")

    def __init__(
        self,
        context: ClientContext | ServerContext,
        buffer: TLSBuffer,
        transport: AsyncTransport,
        tcp_socket: socket.socket | None = None,
    ) -> None:
        self._context = context
        self._buffer = buffer
        self._transport = transport
        # with a socket the engine reads and writes the kernel itself; without one the records go through the transport
        self._socket = tcp_socket
        self._loop = asyncio.get_running_loop()

    @classmethod
    async def connect(
        cls,
        context: ClientContext,
        address: tuple[str, int],
        *,
        proxy: Proxy | None = None,
        proxy_context: ClientContext | None = None,
        server_hostname: str | None = None,
        trace: Trace | None = None,
    ) -> Self:
        # a time limit is the caller's: async with asyncio.timeout(seconds) around the call
        trace = trace or Trace()
        tunnel = await cls.tunnel(
            context if proxy_context is None else proxy_context, address, proxy, trace
        )
        try:
            buffer = context.create_buffer(
                address[0] if server_hostname is None else server_hostname
            )
            if (
                tunnel.tcp_socket is not None
                and not tunnel.leftover
                and Readiness.available(asyncio.get_running_loop())
            ):
                return await cls.open_socket(context, buffer, tunnel.tcp_socket, trace)
            return await cls.open(
                context, buffer, tunnel.transport, tunnel.leftover, trace
            )
        except BaseException:
            await tunnel.transport.close()
            raise

    @classmethod
    async def tunnel(
        cls,
        context: ClientContext,
        address: tuple[str, int],
        proxy: Proxy | None,
        trace: Trace | None = None,
    ) -> Tunnel:
        trace = trace or Trace()
        if proxy is None:
            with trace.span(Phase.CONNECT):
                direct = await SocketTransport.connect(address)
            cls.logger.info(
                "%s host=%s port=%d", Event.CONNECTED, address[0], address[1]
            )
            return Tunnel(direct, b"", direct.socket)
        hop: AsyncTransport
        tcp_socket: socket.socket | None
        if proxy.scheme is ProxyScheme.HTTPS:
            hop = await cls.connect(context, proxy.address, trace=trace)
            tcp_socket = None
        else:
            with trace.span(Phase.CONNECT):
                plain = await SocketTransport.connect(proxy.address)
            cls.logger.info(
                "%s host=%s port=%d proxy=%s",
                Event.CONNECTED,
                proxy.host,
                proxy.port,
                proxy.scheme,
            )
            hop, tcp_socket = plain, plain.socket
        try:
            with trace.span(Phase.PROXY):
                leftover = await cls._tunnel(proxy, address, hop)
        except BaseException:
            await hop.close()
            raise
        return Tunnel(hop, leftover, tcp_socket)

    @classmethod
    async def open(
        cls,
        context: ClientContext | ServerContext,
        buffer: TLSBuffer,
        transport: AsyncTransport,
        leftover: bytes = b"",
        trace: Trace | None = None,
    ) -> Self:
        self = cls(context, buffer, transport)
        if leftover:
            buffer.process_incoming(leftover)
        await self._handshake(trace or Trace())
        return self

    @classmethod
    async def open_socket(
        cls,
        context: ClientContext | ServerContext,
        buffer: TLSBuffer,
        tcp_socket: socket.socket,
        trace: Trace | None = None,
    ) -> Self:
        buffer.attach(tcp_socket.fileno())
        self = cls(context, buffer, SocketTransport(tcp_socket), tcp_socket)
        await self._handshake(trace or Trace())
        return self

    @property
    def context(self) -> ClientContext | ServerContext:
        return self._context

    @property
    def buffer(self) -> TLSBuffer:
        return self._buffer

    async def read(self, limit: int) -> bytes:
        try:
            return await self._run(lambda: self._buffer.read(limit))
        except RaggedEOF:
            return b""

    async def write(self, data: bytes) -> None:
        while data:
            written = await self._run(partial(self._buffer.write, data))
            data = data[written:]

    async def close(self) -> None:
        try:
            async with asyncio.timeout(Seconds.SHUTDOWN):
                await self._run(self._buffer.shutdown)
        except TimeoutError, RaggedEOF, OSError:
            pass
        await self._transport.close()
        self.logger.info("%s", Event.CLOSED)

    def cipher(self) -> CipherSuite | int | None:
        return self._buffer.cipher()

    def negotiated_protocol(self) -> NextProtocol | bytes | None:
        return self._buffer.negotiated_protocol()

    @property
    def negotiated_tls_version(self) -> TLSVersion | None:
        return self._buffer.negotiated_tls_version

    def getpeercert(self) -> bytes | None:
        return self._buffer.getpeercert()

    def getpeerchain(self) -> tuple[bytes, ...]:
        return self._buffer.getpeerchain()

    def getsockname(self) -> tuple[str | None, int]:
        return self._transport.getsockname()

    def getpeername(self) -> tuple[str | None, int]:
        return self._transport.getpeername()

    @classmethod
    async def associate(
        cls, proxy: Proxy, transport: AsyncTransport
    ) -> tuple[str, int]:
        # a SOCKS5 UDP ASSOCIATE over the transport; the relay address is where datagrams go
        # RFC 1928 section 4: the client's address is unknown ahead of time, so the unspecified address is sent
        handshake = proxy.association((str(ipaddress.IPv4Address(0)), 0))
        await cls._converse(handshake, transport)
        if handshake.bound is None:
            raise ProxyError("the SOCKS5 proxy named no relay address")
        host, port = handshake.bound
        literal = ProxyHandshake.literal(host)
        # a relay that answers with the unspecified address means the proxy's own address
        relay = proxy.host if literal is not None and literal.is_unspecified else host
        return relay, port

    @classmethod
    async def _tunnel(
        cls, proxy: Proxy, destination: tuple[str, int], transport: AsyncTransport
    ) -> bytes:
        host, port = destination
        if (family := proxy.scheme.local_address_family) is not None:
            candidates = await asyncio.get_running_loop().getaddrinfo(
                host, port, family=family, type=socket.SOCK_STREAM
            )
            host = str(candidates[0][4][0])
        leftover = await cls._converse(proxy.handshake((host, port)), transport)
        cls.logger.info(
            "%s proxy=%s host=%s port=%d",
            Event.PROXY_TUNNELED,
            proxy.scheme,
            host,
            port,
        )
        return leftover

    @classmethod
    async def _converse(
        cls, handshake: ProxyHandshake, transport: AsyncTransport
    ) -> bytes:
        # drives a proxy handshake over the transport; returns what arrived after the proxy's last reply
        pending = bytearray()
        step = handshake.first()
        while step is not None:
            if step.request:
                await transport.write(step.request)
            while not (end := step.reply_end(bytes(pending))):
                piece = await transport.read(Limit.RECEIVE)
                if not piece:
                    raise ProxyError(
                        "the proxy closed the connection during the tunnel handshake"
                    )
                pending += piece
            reply = bytes(pending[:end])
            del pending[:end]
            cls.logger.debug(
                "%s proxy=%s sent=%d received=%d",
                Event.PROXY_STEP,
                handshake.proxy.scheme,
                len(step.request),
                end,
            )
            step = handshake.next(reply)
        return bytes(pending)

    async def _handshake(self, trace: Trace) -> None:
        try:
            with trace.span(Phase.HANDSHAKE):
                await self._run(self._buffer.do_handshake)
        except Exception as error:
            self.logger.warning("%s step=handshake error=%s", Event.FAILED, error)
            raise
        self.logger.info(
            "%s version=%s cipher=%s protocol=%s",
            Event.HANDSHAKE_DONE,
            self._buffer.negotiated_tls_version,
            self._buffer.cipher(),
            self._buffer.negotiated_protocol(),
        )

    async def _run[ResultT](self, operation: Callable[[], ResultT]) -> ResultT:
        while True:
            try:
                result = operation()
            except WantReadError:
                if self._socket is None:
                    await self._flush()
                    await self._fill()
                else:
                    await self._ready(self._loop.add_reader, self._loop.remove_reader)
                continue
            except WantWriteError:
                if self._socket is None:
                    await self._flush()
                else:
                    await self._ready(self._loop.add_writer, self._loop.remove_writer)
                continue
            if self._socket is None:
                await self._flush()
            return result

    async def _ready(
        self,
        watch: Callable[[int, Callable[[], None]], object],
        unwatch: Callable[[int], object],
    ) -> None:
        if self._socket is None:
            return
        fileno = self._socket.fileno()
        waiter: asyncio.Future[None] = self._loop.create_future()
        watch(fileno, lambda: None if waiter.done() else waiter.set_result(None))
        try:
            await waiter
        finally:
            unwatch(fileno)

    async def _flush(self) -> None:
        # everything buffered in one take: draining a memory BIO in small pieces moves the remainder each time
        while pending := self._buffer.outgoing_bytes_buffered():
            await self._transport.write(self._buffer.process_outgoing(pending))

    async def _fill(self) -> None:
        data = await self._transport.read(Limit.RECEIVE)
        if not data:
            raise RaggedEOF("the transport closed before close_notify")
        self._buffer.process_incoming(data)
