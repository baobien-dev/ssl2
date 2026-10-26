import asyncio
import socket
from collections.abc import Callable, Generator
from dataclasses import dataclass
from functools import partial
from typing import Protocol, Self, cast

from ssl2.errors import RaggedEOF, WantReadError, WantWriteError
from ssl2.interface import RECEIVE_SIZE, ClientContext, ServerContext, TLSBuffer
from ssl2.parameters import CipherSuite, NextProtocol, TLSVersion
from ssl2.proxy import Proxy, ProxyError, ProxyScheme

SHUTDOWN_TIMEOUT = 5.0


class AsyncTransport(Protocol):
    async def read(self, limit: int, /) -> bytes: ...

    async def write(self, data: bytes, /) -> None: ...

    async def close(self) -> None: ...


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


class SocketTransport:
    def __init__(self, sock: socket.socket) -> None:
        self._socket = sock
        self._loop = asyncio.get_running_loop()

    @classmethod
    async def connect(cls, address: tuple[str, int]) -> Self:
        loop = asyncio.get_running_loop()
        host, port = address
        failure = OSError(f"{host}:{port} resolves to no address")
        for family, kind, protocol, _, resolved in await loop.getaddrinfo(
            host, port, type=socket.SOCK_STREAM
        ):
            sock = socket.socket(family, kind, protocol)
            sock.setblocking(False)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                await loop.sock_connect(sock, resolved)
            except OSError as error:
                sock.close()
                failure = error
                continue
            return cls(sock)
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


@dataclass(frozen=True, slots=True)
class Tunnel:
    transport: AsyncTransport
    leftover: bytes
    # the TCP socket under the transport, when TLS can take it over; None behind a TLS hop
    socket: socket.socket | None


class TLSStream:
    def __init__(
        self,
        context: ClientContext | ServerContext,
        buffer: TLSBuffer,
        transport: AsyncTransport,
        sock: socket.socket | None = None,
    ) -> None:
        self._context = context
        self._buffer = buffer
        self._transport = transport
        # with a socket, BoringSSL reads and writes the kernel itself; without one the records go through the transport
        self._socket = sock
        self._loop = asyncio.get_running_loop()

    @classmethod
    async def connect(
        cls,
        context: ClientContext,
        address: tuple[str, int],
        *,
        proxy: Proxy | None = None,
        timeout: float | None = None,
        proxy_context: ClientContext | None = None,
        server_hostname: str | None = None,
    ) -> Self:
        async with asyncio.timeout(timeout):
            tunnel = await cls.tunnel(
                context if proxy_context is None else proxy_context, address, proxy
            )
            try:
                buffer = context.create_buffer(
                    address[0] if server_hostname is None else server_hostname
                )
                if tunnel.socket is not None and not tunnel.leftover:
                    return await cls.open_socket(context, buffer, tunnel.socket)
                return await cls.open(
                    context, buffer, tunnel.transport, tunnel.leftover
                )
            except BaseException:
                await tunnel.transport.close()
                raise

    @classmethod
    async def tunnel(
        cls, context: ClientContext, address: tuple[str, int], proxy: Proxy | None
    ) -> Tunnel:
        if proxy is None:
            direct = await SocketTransport.connect(address)
            return Tunnel(direct, b"", direct.socket)
        hop: AsyncTransport
        sock: socket.socket | None
        if proxy.scheme is ProxyScheme.HTTPS:
            hop = await cls.connect(context, (proxy.host, proxy.port))
            sock = None
        else:
            plain = await SocketTransport.connect((proxy.host, proxy.port))
            hop, sock = plain, plain.socket
        try:
            leftover = await cls._tunnel(proxy, address, hop)
        except BaseException:
            await hop.close()
            raise
        return Tunnel(hop, leftover, sock)

    @classmethod
    async def open(
        cls,
        context: ClientContext | ServerContext,
        buffer: TLSBuffer,
        transport: AsyncTransport,
        leftover: bytes = b"",
    ) -> Self:
        self = cls(context, buffer, transport)
        if leftover:
            buffer.process_incoming(leftover)
        await self._run(buffer.do_handshake)
        return self

    @classmethod
    async def open_socket(
        cls,
        context: ClientContext | ServerContext,
        buffer: TLSBuffer,
        sock: socket.socket,
    ) -> Self:
        buffer.attach(sock.fileno())
        self = cls(context, buffer, SocketTransport(sock), sock)
        await self._run(buffer.do_handshake)
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
            async with asyncio.timeout(SHUTDOWN_TIMEOUT):
                await self._run(self._buffer.shutdown)
        except TimeoutError, RaggedEOF, OSError:
            pass
        await self._transport.close()

    def cipher(self) -> CipherSuite | int | None:
        return self._buffer.cipher()

    def negotiated_protocol(self) -> NextProtocol | bytes | None:
        return self._buffer.negotiated_protocol()

    @property
    def negotiated_tls_version(self) -> TLSVersion | None:
        return self._buffer.negotiated_tls_version

    def getpeercert(self) -> bytes | None:
        return self._buffer.getpeercert()

    @classmethod
    async def associate(
        cls, proxy: Proxy, transport: AsyncTransport
    ) -> tuple[str, int]:
        _, (host, port) = await cls._converse(
            proxy.associate(("0.0.0.0", 0)), transport
        )
        return (proxy.host if host in ("0.0.0.0", "::") else host, port)

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
        leftover, _ = await cls._converse(proxy.converse((host, port)), transport)
        return leftover

    @staticmethod
    async def _converse[ResultT](
        conversation: Generator[tuple[bytes, int | bytes], bytes, ResultT],
        transport: AsyncTransport,
    ) -> tuple[bytes, ResultT]:
        pending = bytearray()
        step = next(conversation)
        while True:
            request, expected = step
            if request:
                await transport.write(request)
            while not (end := Proxy.reply_length(pending, expected)):
                piece = await transport.read(RECEIVE_SIZE)
                if not piece:
                    raise ProxyError(
                        "the proxy closed the connection during the tunnel handshake"
                    )
                pending += piece
            reply = bytes(pending[:end])
            del pending[:end]
            try:
                step = conversation.send(reply)
            except StopIteration as stop:
                return bytes(pending), cast(ResultT, stop.value)

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
        # one take of everything buffered: draining a memory BIO in small pieces moves the remainder each time
        while pending := self._buffer.outgoing_bytes_buffered():
            await self._transport.write(self._buffer.process_outgoing(pending))

    async def _fill(self) -> None:
        data = await self._transport.read(RECEIVE_SIZE)
        if not data:
            raise RaggedEOF("the transport closed before close_notify")
        self._buffer.process_incoming(data)
