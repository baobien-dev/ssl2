import base64
import ipaddress
import socket
import struct
from collections.abc import Generator
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import Self
from urllib.parse import unquote, urlsplit

type Conversation = Generator[tuple[bytes, int | bytes], bytes, object]
type Association = Generator[tuple[bytes, int | bytes], bytes, tuple[str, int]]

REPLY_LIMIT = 65536
USERNAME_PASSWORD_VERSION = 0x01
SOCKS4A_NAME_FOLLOWS = bytes((0, 0, 0, 1))


class ProxyError(ConnectionError):
    pass


class ProxyScheme(StrEnum):
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS4A = "socks4a"
    SOCKS5 = "socks5"
    SOCKS5H = "socks5h"

    @property
    def default_port(self) -> int:
        match self:
            case ProxyScheme.HTTP:
                return 80
            case ProxyScheme.HTTPS:
                return 443
            case _:
                return 1080

    @property
    def local_address_family(self) -> socket.AddressFamily | None:
        match self:
            case ProxyScheme.SOCKS4:
                return socket.AF_INET
            case ProxyScheme.SOCKS5:
                return socket.AF_UNSPEC
            case _:
                return None


class SocksVersion(IntEnum):
    SOCKS4 = 0x04
    SOCKS5 = 0x05


class SocksCommand(IntEnum):
    CONNECT = 0x01
    UDP_ASSOCIATE = 0x03


class Socks4Reply(IntEnum):
    GRANTED = 0x5A
    REJECTED = 0x5B
    IDENTD_UNREACHABLE = 0x5C
    IDENTD_MISMATCH = 0x5D


class Socks5Method(IntEnum):
    NO_AUTHENTICATION = 0x00
    USERNAME_PASSWORD = 0x02
    NO_ACCEPTABLE = 0xFF


class Socks5AddressType(IntEnum):
    IPV4 = 0x01
    DOMAIN_NAME = 0x03
    IPV6 = 0x04


class Socks5Reply(IntEnum):
    SUCCEEDED = 0x00
    GENERAL_FAILURE = 0x01
    CONNECTION_NOT_ALLOWED = 0x02
    NETWORK_UNREACHABLE = 0x03
    HOST_UNREACHABLE = 0x04
    CONNECTION_REFUSED = 0x05
    TTL_EXPIRED = 0x06
    COMMAND_NOT_SUPPORTED = 0x07
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08


@dataclass(frozen=True, slots=True)
class ProxyCredentials:
    username: str
    password: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class Proxy:
    scheme: ProxyScheme
    host: str
    port: int
    credentials: ProxyCredentials | None = None

    @classmethod
    def parse(cls, url: str) -> Self:
        parts = urlsplit(url)
        scheme = ProxyScheme(parts.scheme.lower())
        if not parts.hostname:
            raise ValueError("a proxy URL needs a host")
        credentials = None
        if parts.username is not None:
            credentials = ProxyCredentials(
                unquote(parts.username), unquote(parts.password or "")
            )
        return cls(
            scheme=scheme,
            host=parts.hostname,
            port=parts.port or scheme.default_port,
            credentials=credentials,
        )

    def converse(self, destination: tuple[str, int]) -> Conversation:
        match self.scheme:
            case ProxyScheme.HTTP | ProxyScheme.HTTPS:
                return self._connect(destination)
            case ProxyScheme.SOCKS4 | ProxyScheme.SOCKS4A:
                return self._socks4(destination)
            case ProxyScheme.SOCKS5 | ProxyScheme.SOCKS5H:
                return self._socks5(destination, SocksCommand.CONNECT)

    def associate(self, local: tuple[str, int]) -> Association:
        if self.scheme not in (ProxyScheme.SOCKS5, ProxyScheme.SOCKS5H):
            raise ProxyError(f"UDP ASSOCIATE needs a SOCKS5 proxy, not {self.scheme}")
        return self._socks5(local, SocksCommand.UDP_ASSOCIATE)

    def udp_header(self, destination: tuple[str, int]) -> bytes:
        host, port = destination
        return bytes(3) + self._socks5_address(host) + struct.pack("!H", port)

    @staticmethod
    def udp_payload(datagram: bytes) -> bytes:
        if len(datagram) < 4 or datagram[:3] != bytes(3):
            raise ProxyError(
                "the SOCKS5 relay sent a fragmented or truncated UDP datagram"
            )
        match datagram[3]:
            case Socks5AddressType.IPV4:
                start = 10
            case Socks5AddressType.IPV6:
                start = 22
            case Socks5AddressType.DOMAIN_NAME:
                start = 7 + datagram[4]
            case _:
                raise ProxyError(
                    f"the SOCKS5 relay sent an address of unknown type {datagram[3]:#04x}"
                )
        return datagram[start:]

    @staticmethod
    def reply_length(buffered: bytearray, expected: int | bytes) -> int:
        if len(buffered) > REPLY_LIMIT:
            raise ProxyError("the proxy reply exceeds 64 KiB")
        if isinstance(expected, int):
            return expected if len(buffered) >= expected else 0
        position = buffered.find(expected)
        return 0 if position < 0 else position + len(expected)

    def _connect(self, destination: tuple[str, int]) -> Conversation:
        host, port = destination
        authority = (
            f"[{host}]:{port}"
            if ":" in host
            else f"{host.encode('idna').decode('ascii')}:{port}"
        )
        lines = [f"CONNECT {authority} HTTP/1.1", f"Host: {authority}"]
        if self.credentials is not None:
            token = base64.b64encode(
                f"{self.credentials.username}:{self.credentials.password}".encode()
            ).decode("ascii")
            lines.append(f"Proxy-Authorization: Basic {token}")
        head = yield ("\r\n".join(lines).encode("ascii") + b"\r\n\r\n", b"\r\n\r\n")
        status_line = head.split(b"\r\n", 1)[0].decode("ascii", "replace")
        fields = status_line.split(" ", 2)
        if len(fields) < 2 or not fields[1].isdigit():
            raise ProxyError(f"malformed CONNECT response: {status_line!r}")
        if not 200 <= int(fields[1]) < 300:
            raise ProxyError(f"the proxy refused CONNECT: {status_line}")

    def _socks4(self, destination: tuple[str, int]) -> Conversation:
        host, port = destination
        if self.credentials is not None and self.credentials.password:
            raise ProxyError("SOCKS4 has no password field")
        user = (
            self.credentials.username if self.credentials is not None else ""
        ).encode()
        literal = self._literal(host)
        if literal is None and self.scheme is not ProxyScheme.SOCKS4A:
            raise ProxyError("SOCKS4 needs a resolved IPv4 destination")
        if literal is None:
            address, trailer = SOCKS4A_NAME_FOLLOWS, host.encode("idna") + b"\x00"
        elif literal.version == 4:
            address, trailer = literal.packed, b""
        else:
            raise ProxyError("SOCKS4 reaches IPv4 destinations only")
        request = (
            bytes((SocksVersion.SOCKS4, SocksCommand.CONNECT))
            + struct.pack("!H", port)
            + address
        )
        reply = yield (request + user + b"\x00" + trailer, 8)
        if reply[1] != Socks4Reply.GRANTED:
            raise ProxyError(
                f"SOCKS4 CONNECT failed: {self._name(Socks4Reply, reply[1])}"
            )

    def _socks5(
        self, destination: tuple[str, int], command: SocksCommand
    ) -> Association:
        host, port = destination
        methods = [Socks5Method.NO_AUTHENTICATION]
        if self.credentials is not None:
            methods.append(Socks5Method.USERNAME_PASSWORD)
        version, method = yield (
            bytes((SocksVersion.SOCKS5, len(methods), *methods)),
            2,
        )
        if version != SocksVersion.SOCKS5:
            raise ProxyError("the SOCKS5 proxy answered with another protocol version")
        if method == Socks5Method.USERNAME_PASSWORD:
            if self.credentials is None:
                raise ProxyError("the SOCKS5 proxy requires a username and password")
            username, password = (
                self.credentials.username.encode(),
                self.credentials.password.encode(),
            )
            if len(username) > 255 or len(password) > 255:
                raise ProxyError(
                    "SOCKS5 limits the username and the password to 255 bytes each"
                )
            request = (
                bytes((USERNAME_PASSWORD_VERSION, len(username)))
                + username
                + bytes((len(password),))
                + password
            )
            _, status = yield (request, 2)
            if status != 0:
                raise ProxyError("the SOCKS5 proxy rejected the username and password")
        elif method != Socks5Method.NO_AUTHENTICATION:
            raise ProxyError(
                f"the SOCKS5 proxy accepts none of the offered authentication methods: {self._name(Socks5Method, method)}"
            )
        request = (
            bytes((SocksVersion.SOCKS5, command, 0))
            + self._socks5_address(host)
            + struct.pack("!H", port)
        )
        version, reply, _, address_type = yield (request, 4)
        if version != SocksVersion.SOCKS5:
            raise ProxyError("the SOCKS5 proxy answered with another protocol version")
        if reply != Socks5Reply.SUCCEEDED:
            raise ProxyError(
                f"SOCKS5 {command.name} failed: {self._name(Socks5Reply, reply)}"
            )
        match address_type:
            case Socks5AddressType.IPV4:
                length = 4
            case Socks5AddressType.IPV6:
                length = 16
            case Socks5AddressType.DOMAIN_NAME:
                length = (yield (b"", 1))[0]
            case _:
                raise ProxyError(
                    f"SOCKS5 proxy bound to an address of unknown type {address_type:#04x}"
                )
        bound = yield (b"", length + 2)
        if address_type == Socks5AddressType.DOMAIN_NAME:
            bound_host = bound[:length].decode("idna")
        else:
            bound_host = str(ipaddress.ip_address(bound[:length]))
        return bound_host, int.from_bytes(bound[length:], "big")

    def _socks5_address(self, host: str) -> bytes:
        literal = self._literal(host)
        if literal is None and self.scheme is not ProxyScheme.SOCKS5H:
            raise ProxyError("SOCKS5 needs a resolved destination address")
        if literal is None:
            name = host.encode("idna")
            if len(name) > 255:
                raise ProxyError("SOCKS5 limits domain names to 255 bytes")
            return bytes((Socks5AddressType.DOMAIN_NAME, len(name))) + name
        address_type = (
            Socks5AddressType.IPV4 if literal.version == 4 else Socks5AddressType.IPV6
        )
        return bytes((address_type,)) + literal.packed

    @staticmethod
    def _literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        try:
            return ipaddress.ip_address(host)
        except ValueError:
            return None

    @staticmethod
    def _name(registry: type[IntEnum], code: int) -> str:
        return registry(code).name if code in registry else f"{code:#04x}"
