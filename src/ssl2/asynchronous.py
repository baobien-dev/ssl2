import asyncio
import socket
from collections.abc import Callable, Generator
from functools import partial
from typing import Final, Protocol, Self, cast, final

from ssl2.errors import RaggedEOF, WantReadError, WantWriteError
from ssl2.interface import RECEIVE_SIZE, ClientContext, ServerContext, TLSBuffer
from ssl2.parameters import CipherSuite, NextProtocol, TLSVersion
from ssl2.proxy import Proxy, ProxyError, ProxyScheme

SHUTDOWN_TIMEOUT: Final = 5.0


class AsyncTransport(Protocol):
    async def read(self, limit: int, /) -> bytes: ...

    async def write(self, data: bytes, /) -> None: ...

    async def close(self) -> None: ...


@final
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


@final
class TLSStream:
    def __init__(
        self,
        context: ClientContext | ServerContext,
        buffer: TLSBuffer,
        transport: AsyncTransport,
    ) -> None:
        self._context = context
        self._buffer = buffer
        self._transport = transport

    @classmethod
    async def connect(
        cls,
        context: ClientContext,
        address: tuple[str, int],
        *,
        proxy: Proxy | None = None,
        timeout: float | None = None,
    ) -> Self:
        async with asyncio.timeout(timeout):
            transport, leftover = await cls.tunnel(context, address, proxy)
            try:
                return await cls.open(
                    context, context.create_buffer(address[0]), transport, leftover
                )
            except BaseException:
                await transport.close()
                raise

    @classmethod
    async def tunnel(
        cls, context: ClientContext, address: tuple[str, int], proxy: Proxy | None
    ) -> tuple[AsyncTransport, bytes]:
        if proxy is None:
            return StreamTransport(*await asyncio.open_connection(*address)), b""
        transport: AsyncTransport
        if proxy.scheme is ProxyScheme.HTTPS:
            transport = await cls.connect(context, (proxy.host, proxy.port))
        else:
            transport = StreamTransport(
                *await asyncio.open_connection(proxy.host, proxy.port)
            )
        try:
            return transport, await cls._tunnel(proxy, address, transport)
        except BaseException:
            await transport.close()
            raise

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
        view = memoryview(data)
        while view:
            written = await self._run(partial(self._buffer.write, view))
            view = view[written:]

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
                await self._flush()
                await self._fill()
                continue
            except WantWriteError:
                await self._flush()
                continue
            await self._flush()
            return result

    async def _flush(self) -> None:
        # one take of everything buffered: draining a memory BIO in small pieces moves the remainder each time
        while pending := self._buffer.outgoing_bytes_buffered():
            await self._transport.write(self._buffer.process_outgoing(pending))

    async def _fill(self) -> None:
        data = await self._transport.read(RECEIVE_SIZE)
        if not data:
            raise RaggedEOF("the transport closed before close_notify")
        self._buffer.process_incoming(data)
