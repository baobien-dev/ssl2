import base64
import ipaddress
import socket
import struct
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from http import HTTPStatus
from typing import Self, override
from urllib.parse import unquote, urlsplit

from ssl2.errors import ParseError, ProxyError
from ssl2.value import Value


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
                return Port.HTTP
            case ProxyScheme.HTTPS:
                return Port.HTTPS
            case _:
                return Port.SOCKS

    @property
    def local_address_family(self) -> socket.AddressFamily | None:
        # socks4 and socks5 carry an address, so the name is resolved here; the others let the proxy resolve it
        match self:
            case ProxyScheme.SOCKS4:
                return socket.AF_INET
            case ProxyScheme.SOCKS5:
                return socket.AF_UNSPEC
            case _:
                return None


class Port(IntEnum):
    HTTP = 80
    HTTPS = 443
    SOCKS = 1080


class Limit(IntEnum):
    REPLY = 65536
    NAME = 255
    CREDENTIAL = 255


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


class Width(IntEnum):
    # RFC 1928 and RFC 1929 field and reply sizes
    SOCKS4_REPLY = 8
    METHOD_SELECTION = 2
    AUTHENTICATION_REPLY = 2
    REPLY_HEAD = 4
    DOMAIN_LENGTH = 1
    IPV4 = 4
    IPV6 = 16
    PORT = 2
    UDP_RESERVED = 2
    UDP_FRAGMENT = 1


class UsernamePassword(IntEnum):
    VERSION = 0x01
    SUCCESS = 0x00


@dataclass(frozen=True, slots=True)
class ProxyCredentials(Value):
    username: str
    password: str = ""

    @property
    def basic(self) -> str:
        token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode("ascii")
        return f"Basic {token}"


@dataclass(frozen=True, slots=True)
class Length(Value):
    count: int


@dataclass(frozen=True, slots=True)
class Terminator(Value):
    marker: bytes


@dataclass(frozen=True, slots=True)
class Step(Value):
    # one exchange of a proxy handshake: send the request, then wait for a reply of the expected shape
    request: bytes
    expected: Length | Terminator

    def reply_end(self, buffered: bytes) -> int:
        # where the reply ends inside what has arrived, or 0 while it is incomplete
        if len(buffered) > Limit.REPLY:
            raise ProxyError(f"the proxy reply exceeds {Limit.REPLY} bytes")
        match self.expected:
            case Length(count):
                return count if len(buffered) >= count else 0
            case Terminator(marker):
                position = buffered.find(marker)
                return 0 if position < 0 else position + len(marker)


@dataclass(frozen=True, slots=True, kw_only=True)
class Proxy(Value):
    scheme: ProxyScheme
    host: str
    port: int
    credentials: ProxyCredentials | None = None

    @classmethod
    def parse(cls, url: str) -> Self:
        parts = urlsplit(url)
        try:
            scheme = ProxyScheme(parts.scheme.lower())
        except ValueError:
            raise ParseError(f"{parts.scheme!r} is not a proxy scheme") from None
        if not parts.hostname:
            raise ParseError(f"the proxy URL {url!r} names no host")
        credentials = None
        if parts.username is not None:
            credentials = ProxyCredentials(unquote(parts.username), unquote(parts.password or ""))
        return cls(
            scheme=scheme,
            host=parts.hostname,
            port=parts.port or scheme.default_port,
            credentials=credentials,
        )

    @property
    def address(self) -> tuple[str, int]:
        return self.host, self.port

    def handshake(self, destination: tuple[str, int]) -> ProxyHandshake:
        match self.scheme:
            case ProxyScheme.HTTP | ProxyScheme.HTTPS:
                return ConnectHandshake(self, destination)
            case ProxyScheme.SOCKS4 | ProxyScheme.SOCKS4A:
                return Socks4Handshake(self, destination)
            case ProxyScheme.SOCKS5 | ProxyScheme.SOCKS5H:
                return Socks5Handshake(self, destination, SocksCommand.CONNECT)

    def association(self, local: tuple[str, int]) -> Socks5Handshake:
        if self.scheme not in (ProxyScheme.SOCKS5, ProxyScheme.SOCKS5H):
            raise ProxyError(f"UDP ASSOCIATE needs a SOCKS5 proxy, not {self.scheme}")
        return Socks5Handshake(self, local, SocksCommand.UDP_ASSOCIATE)


class ProxyHandshake:
    def __init__(self, proxy: Proxy, destination: tuple[str, int]) -> None:
        self.proxy = proxy
        self.destination = destination
        self.bound: tuple[str, int] | None = None

    def first(self) -> Step:
        raise NotImplementedError

    def next(self, reply: bytes) -> Step | None:
        raise NotImplementedError

    @staticmethod
    def literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        try:
            return ipaddress.ip_address(host)
        except ValueError:
            return None

    @staticmethod
    def reply_name(registry: type[IntEnum], code: int) -> str:
        return registry(code).name if code in registry else f"{code:#04x}"


class ConnectHandshake(ProxyHandshake):
    # RFC 9110 section 9.3.6: CONNECT host:port, the tunnel is open on a 2xx answer
    LINE_END = b"\r\n"
    HEAD_END = b"\r\n\r\n"

    @override
    def first(self) -> Step:
        host, port = self.destination
        authority = f"[{host}]:{port}" if ":" in host else f"{host.encode('idna').decode('ascii')}:{port}"
        lines = [f"CONNECT {authority} HTTP/1.1", f"Host: {authority}"]
        if self.proxy.credentials is not None:
            lines.append(f"Proxy-Authorization: {self.proxy.credentials.basic}")
        request = self.LINE_END.join(line.encode("ascii") for line in lines) + self.HEAD_END
        return Step(request, Terminator(self.HEAD_END))

    @override
    def next(self, reply: bytes) -> Step | None:
        status_line = reply.split(self.LINE_END, 1)[0].decode("ascii", "replace")
        _, _, rest = status_line.partition(" ")
        code, _, _ = rest.partition(" ")
        if not (code.isascii() and code.isdigit()):
            raise ProxyError(f"malformed CONNECT response: {status_line!r}")
        if not HTTPStatus.OK <= int(code) < HTTPStatus.MULTIPLE_CHOICES:
            raise ProxyError(f"the proxy refused CONNECT: {status_line}")
        return None


class Socks4Handshake(ProxyHandshake):
    # the SOCKS4 protocol and the SOCKS4A extension that sends a name after a 0.0.0.x address
    NAME_FOLLOWS = bytes((0, 0, 0, 1))
    TERMINATOR = b"\x00"

    @override
    def first(self) -> Step:
        host, port = self.destination
        credentials = self.proxy.credentials
        if credentials is not None and credentials.password:
            raise ProxyError("SOCKS4 has no password field")
        user = (credentials.username if credentials is not None else "").encode()
        literal = self.literal(host)
        if literal is None:
            if self.proxy.scheme is not ProxyScheme.SOCKS4A:
                raise ProxyError("SOCKS4 needs a resolved IPv4 destination")
            address, trailer = self.NAME_FOLLOWS, host.encode("idna") + self.TERMINATOR
        elif isinstance(literal, ipaddress.IPv4Address):
            address, trailer = literal.packed, b""
        else:
            raise ProxyError("SOCKS4 reaches IPv4 destinations only")
        request = (
            bytes((SocksVersion.SOCKS4, SocksCommand.CONNECT))
            + struct.pack("!H", port)
            + address
            + user
            + self.TERMINATOR
            + trailer
        )
        return Step(request, Length(Width.SOCKS4_REPLY))

    @override
    def next(self, reply: bytes) -> Step | None:
        if reply[1] != Socks4Reply.GRANTED:
            raise ProxyError(f"SOCKS4 CONNECT failed: {self.reply_name(Socks4Reply, reply[1])}")
        return None


class Socks5State(StrEnum):
    GREETING = "greeting"
    AUTHENTICATION = "authentication"
    REQUEST = "request"
    ADDRESS_LENGTH = "address_length"
    ADDRESS = "address"
    DONE = "done"


class Socks5Handshake(ProxyHandshake):
    # RFC 1928 with RFC 1929 username and password authentication, for CONNECT and UDP ASSOCIATE
    def __init__(self, proxy: Proxy, destination: tuple[str, int], command: SocksCommand) -> None:
        super().__init__(proxy, destination)
        self.command = command
        self._state = Socks5State.GREETING
        self._address_type = Socks5AddressType.IPV4
        self._address_length = 0

    @override
    def first(self) -> Step:
        methods = [Socks5Method.NO_AUTHENTICATION]
        if self.proxy.credentials is not None:
            methods.append(Socks5Method.USERNAME_PASSWORD)
        request = bytes((SocksVersion.SOCKS5, len(methods), *methods))
        return Step(request, Length(Width.METHOD_SELECTION))

    @override
    def next(self, reply: bytes) -> Step | None:
        match self._state:
            case Socks5State.GREETING:
                return self._on_method(reply)
            case Socks5State.AUTHENTICATION:
                return self._on_authentication(reply)
            case Socks5State.REQUEST:
                return self._on_reply_head(reply)
            case Socks5State.ADDRESS_LENGTH:
                self._address_length = reply[0]
                self._state = Socks5State.ADDRESS
                return Step(b"", Length(self._address_length + Width.PORT))
            case Socks5State.ADDRESS:
                self._on_address(reply)
                return None
            case Socks5State.DONE:
                raise ProxyError("the SOCKS5 handshake is already complete")

    def _on_method(self, reply: bytes) -> Step:
        version, method = reply
        if version != SocksVersion.SOCKS5:
            raise ProxyError("the SOCKS5 proxy answered with another protocol version")
        if method == Socks5Method.USERNAME_PASSWORD:
            if self.proxy.credentials is None:
                raise ProxyError("the SOCKS5 proxy requires a username and password")
            username = self.proxy.credentials.username.encode()
            password = self.proxy.credentials.password.encode()
            if len(username) > Limit.CREDENTIAL or len(password) > Limit.CREDENTIAL:
                raise ProxyError(f"SOCKS5 limits the username and the password to {Limit.CREDENTIAL} bytes each")
            self._state = Socks5State.AUTHENTICATION
            request = bytes((UsernamePassword.VERSION, len(username))) + username + bytes((len(password),)) + password
            return Step(request, Length(Width.AUTHENTICATION_REPLY))
        if method != Socks5Method.NO_AUTHENTICATION:
            raise ProxyError(
                f"the SOCKS5 proxy accepts none of the offered authentication methods: {self.reply_name(Socks5Method, method)}"
            )
        return self._request()

    def _on_authentication(self, reply: bytes) -> Step:
        if reply[1] != UsernamePassword.SUCCESS:
            raise ProxyError("the SOCKS5 proxy rejected the username and password")
        return self._request()

    def _request(self) -> Step:
        host, port = self.destination
        self._state = Socks5State.REQUEST
        request = (
            bytes((SocksVersion.SOCKS5, self.command, 0))
            + Socks5Address.encode(host, names_allowed=self.proxy.scheme is ProxyScheme.SOCKS5H)
            + struct.pack("!H", port)
        )
        return Step(request, Length(Width.REPLY_HEAD))

    def _on_reply_head(self, reply: bytes) -> Step:
        version, code, _, address_type = reply
        if version != SocksVersion.SOCKS5:
            raise ProxyError("the SOCKS5 proxy answered with another protocol version")
        if code != Socks5Reply.SUCCEEDED:
            raise ProxyError(f"SOCKS5 {self.command.name} failed: {self.reply_name(Socks5Reply, code)}")
        match address_type:
            case Socks5AddressType.IPV4:
                self._address_type, self._address_length = (
                    Socks5AddressType.IPV4,
                    Width.IPV4,
                )
            case Socks5AddressType.IPV6:
                self._address_type, self._address_length = (
                    Socks5AddressType.IPV6,
                    Width.IPV6,
                )
            case Socks5AddressType.DOMAIN_NAME:
                self._address_type = Socks5AddressType.DOMAIN_NAME
                self._state = Socks5State.ADDRESS_LENGTH
                return Step(b"", Length(Width.DOMAIN_LENGTH))
            case _:
                raise ProxyError(f"the SOCKS5 proxy bound an address of unknown type {address_type:#04x}")
        self._state = Socks5State.ADDRESS
        return Step(b"", Length(self._address_length + Width.PORT))

    def _on_address(self, reply: bytes) -> None:
        address, port = reply[: self._address_length], reply[self._address_length :]
        if self._address_type is Socks5AddressType.DOMAIN_NAME:
            host = address.decode("idna")
        else:
            host = str(ipaddress.ip_address(address))
        self.bound = (host, int.from_bytes(port, "big"))
        self._state = Socks5State.DONE


class Socks5Address:
    @staticmethod
    def encode(host: str, *, names_allowed: bool) -> bytes:
        literal = ProxyHandshake.literal(host)
        if literal is None:
            if not names_allowed:
                raise ProxyError("SOCKS5 needs a resolved destination address")
            name = host.encode("idna")
            if len(name) > Limit.NAME:
                raise ProxyError(f"SOCKS5 limits domain names to {Limit.NAME} bytes")
            return bytes((Socks5AddressType.DOMAIN_NAME, len(name))) + name
        address_type = Socks5AddressType.IPV4 if isinstance(literal, ipaddress.IPv4Address) else Socks5AddressType.IPV6
        return bytes((address_type,)) + literal.packed


class Socks5Datagram:
    # RFC 1928 section 7: a UDP datagram through the relay carries a header naming its destination
    HEADER_START = bytes(Width.UDP_RESERVED + Width.UDP_FRAGMENT)

    @classmethod
    def wrap(cls, destination: tuple[str, int], payload: bytes) -> bytes:
        host, port = destination
        return cls.HEADER_START + Socks5Address.encode(host, names_allowed=True) + struct.pack("!H", port) + payload

    @classmethod
    def unwrap(cls, datagram: bytes) -> bytes:
        header = len(cls.HEADER_START)
        if len(datagram) <= header or datagram[:header] != cls.HEADER_START:
            raise ProxyError("the SOCKS5 relay sent a fragmented or truncated UDP datagram")
        match datagram[header]:
            case Socks5AddressType.IPV4:
                start = header + 1 + Width.IPV4 + Width.PORT
            case Socks5AddressType.IPV6:
                start = header + 1 + Width.IPV6 + Width.PORT
            case Socks5AddressType.DOMAIN_NAME:
                start = header + 1 + Width.DOMAIN_LENGTH + datagram[header + 1] + Width.PORT
            case _:
                raise ProxyError(f"the SOCKS5 relay sent an address of unknown type {datagram[header]:#04x}")
        return datagram[start:]
