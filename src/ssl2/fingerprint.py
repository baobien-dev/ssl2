import hashlib
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import Self

from ssl2.client_hello import ClientHello, ClientHelloBuilder
from ssl2.errors import ParseError
from ssl2.registry import (
    CipherSuite,
    CodePoint,
    ECPointFormat,
    ExtensionType,
    Http2SettingIdentifier,
    NamedGroup,
    ProtocolVersion,
    SignatureScheme,
)
from ssl2.value import Value


class JA3Shape(IntEnum):
    FIELDS = 5


@dataclass(frozen=True, slots=True)
class JA3(Value):
    version: ProtocolVersion
    cipher_suites: tuple[CipherSuite, ...]
    extensions: tuple[ExtensionType, ...]
    supported_groups: tuple[NamedGroup, ...]
    ec_point_formats: tuple[ECPointFormat, ...]

    @classmethod
    def of(cls, client_hello: ClientHello) -> Self:
        return cls(
            client_hello.legacy_version,
            client_hello.cipher_suites,
            client_hello.extensions,
            client_hello.supported_groups,
            client_hello.ec_point_formats,
        )

    @classmethod
    def parse(cls, text: str) -> Self:
        fields = text.split(",")
        if len(fields) != JA3Shape.FIELDS:
            raise ParseError(f"JA3 text has {JA3Shape.FIELDS} comma separated fields, not {len(fields)}")
        version, cipher_suites, extensions, supported_groups, ec_point_formats = fields
        return cls(
            ProtocolVersion(int(version)),
            cls._values(CipherSuite, cipher_suites),
            cls._values(ExtensionType, extensions),
            cls._values(NamedGroup, supported_groups),
            cls._values(ECPointFormat, ec_point_formats),
        )

    def builder(self) -> ClientHelloBuilder:
        # the fields JA3 does not carry, such as key shares, signature schemes and ALPN, go in before build()
        return (
            ClientHelloBuilder()
            .legacy_version(self.version)
            .cipher_suites(*self.cipher_suites)
            .extensions(*self.extensions)
            .supported_groups(*self.supported_groups)
            .ec_point_formats(*self.ec_point_formats)
        )

    @property
    def text(self) -> str:
        return ",".join(
            (
                str(int(self.version)),
                self._join(self.cipher_suites),
                self._join(self.extensions),
                self._join(self.supported_groups),
                self._join(self.ec_point_formats),
            )
        )

    @property
    def digest(self) -> str:
        return hashlib.md5(self.text.encode(), usedforsecurity=False).hexdigest()

    @staticmethod
    def _join(values: tuple[CodePoint, ...]) -> str:
        return "-".join(str(int(value)) for value in values)

    @staticmethod
    def _values[CodePointT: CodePoint](registry: type[CodePointT], text: str) -> tuple[CodePointT, ...]:
        return tuple(registry(int(value)) for value in text.split("-") if value)


class JA4Transport(StrEnum):
    TCP = "t"
    QUIC = "q"
    DTLS = "d"


class JA4Version(StrEnum):
    TLS_1_3 = "13"
    TLS_1_2 = "12"
    TLS_1_1 = "11"
    TLS_1_0 = "10"
    SSL_3_0 = "s3"
    DTLS_1_0 = "d1"
    DTLS_1_2 = "d2"
    DTLS_1_3 = "d3"
    UNKNOWN = "00"

    @classmethod
    def of(cls, version: ProtocolVersion) -> JA4Version:
        match version:
            case ProtocolVersion.TLS_1_3:
                return cls.TLS_1_3
            case ProtocolVersion.TLS_1_2:
                return cls.TLS_1_2
            case ProtocolVersion.TLS_1_1:
                return cls.TLS_1_1
            case ProtocolVersion.TLS_1_0:
                return cls.TLS_1_0
            case ProtocolVersion.SSL_3_0:
                return cls.SSL_3_0
            case ProtocolVersion.DTLS_1_0:
                return cls.DTLS_1_0
            case ProtocolVersion.DTLS_1_2:
                return cls.DTLS_1_2
            case ProtocolVersion.DTLS_1_3:
                return cls.DTLS_1_3
            case _:
                return cls.UNKNOWN


class JA4ServerName(StrEnum):
    DOMAIN = "d"
    IP = "i"


class JA4Shape(IntEnum):
    PREFIX = 10
    COUNT_LIMIT = 99
    HASH = 12
    SECTIONS = 3
    SECTIONS_WITH_SIGNATURES = 4


@dataclass(frozen=True, slots=True)
class JA4(Value):
    transport: JA4Transport
    version: JA4Version
    server_name_indicated: bool
    cipher_count: int
    extension_count: int
    application_protocol_code: str
    cipher_suites: tuple[CipherSuite, ...]
    extensions: tuple[ExtensionType, ...]
    signature_algorithms: tuple[SignatureScheme, ...]

    # JA4 hashes the extensions without these two, whose values change per connection
    UNHASHED_EXTENSIONS = frozenset(
        {
            ExtensionType.server_name,
            ExtensionType.application_layer_protocol_negotiation,
        }
    )
    NO_PROTOCOL_CODE = "00"

    @classmethod
    def of(cls, client_hello: ClientHello, transport: JA4Transport = JA4Transport.TCP) -> Self:
        return cls(
            transport,
            JA4Version.of(client_hello.highest_version),
            client_hello.offers(ExtensionType.server_name),
            len(client_hello.cipher_suites),
            len(client_hello.extensions),
            cls._protocol_code(client_hello.application_protocols),
            client_hello.cipher_suites,
            client_hello.extensions,
            client_hello.signature_algorithms,
        )

    @classmethod
    def parse(cls, text: str) -> Self:
        # the raw and original forms parse back; the hashed form holds no list to read
        sections = text.split("_")
        if len(sections) not in (JA4Shape.SECTIONS, JA4Shape.SECTIONS_WITH_SIGNATURES):
            raise ParseError(
                f"JA4 text has {JA4Shape.SECTIONS} or {JA4Shape.SECTIONS_WITH_SIGNATURES} underscore separated sections, not {len(sections)}"
            )
        prefix = sections[0]
        if len(prefix) != JA4Shape.PREFIX:
            raise ParseError(f"the JA4 prefix is {JA4Shape.PREFIX} characters, not {len(prefix)}")
        if any(cls._is_hash(section) for section in sections[1 : JA4Shape.SECTIONS]):
            raise ParseError("hashed JA4 carries no cipher or extension lists; parse the raw or original form")
        signature_algorithms = (
            cls._values(SignatureScheme, sections[JA4Shape.SECTIONS])
            if len(sections) == JA4Shape.SECTIONS_WITH_SIGNATURES
            else ()
        )
        transport, version, server_name, counts, protocol_code = (
            prefix[0],
            prefix[1:3],
            prefix[3],
            prefix[4:8],
            prefix[8:10],
        )
        return cls(
            JA4Transport(transport),
            JA4Version(version),
            JA4ServerName(server_name) is JA4ServerName.DOMAIN,
            int(counts[:2]),
            int(counts[2:]),
            protocol_code,
            cls._values(CipherSuite, sections[1]),
            cls._values(ExtensionType, sections[2]),
            signature_algorithms,
        )

    @property
    def prefix(self) -> str:
        server_name = JA4ServerName.DOMAIN if self.server_name_indicated else JA4ServerName.IP
        ciphers = min(self.cipher_count, JA4Shape.COUNT_LIMIT)
        extensions = min(self.extension_count, JA4Shape.COUNT_LIMIT)
        return (
            f"{self.transport}{self.version}{server_name}{ciphers:02d}{extensions:02d}{self.application_protocol_code}"
        )

    @property
    def text(self) -> str:
        return "_".join(
            (
                self.prefix,
                self._hash(self._sorted_ciphers),
                self._hash(self._sorted_extensions),
            )
        )

    @property
    def raw(self) -> str:
        return f"{self.prefix}_{self._sorted_ciphers}_{self._sorted_extensions}"

    @property
    def original(self) -> str:
        return "_".join(
            (
                self.prefix,
                self._join(self.cipher_suites),
                self._with_signature_algorithms(self._join(self.extensions)),
            )
        )

    @property
    def _sorted_ciphers(self) -> str:
        return ",".join(sorted(cipher.hex for cipher in self.cipher_suites))

    @property
    def _sorted_extensions(self) -> str:
        kept = sorted(extension.hex for extension in self.extensions if extension not in self.UNHASHED_EXTENSIONS)
        return self._with_signature_algorithms(",".join(kept))

    def _with_signature_algorithms(self, extensions: str) -> str:
        if not extensions or not self.signature_algorithms:
            return extensions
        return f"{extensions}_{self._join(self.signature_algorithms)}"

    @staticmethod
    def _join(values: tuple[CodePoint, ...]) -> str:
        return ",".join(value.hex for value in values)

    @staticmethod
    def _values[CodePointT: CodePoint](registry: type[CodePointT], text: str) -> tuple[CodePointT, ...]:
        return tuple(registry(int(value, 16)) for value in text.split(",") if value)

    @staticmethod
    def _hash(section: str) -> str:
        if not section:
            return "0" * JA4Shape.HASH
        return hashlib.sha256(section.encode()).hexdigest()[: JA4Shape.HASH]

    @staticmethod
    def _is_hash(section: str) -> bool:
        return len(section) == JA4Shape.HASH and "," not in section

    @classmethod
    def _protocol_code(cls, protocols: tuple[bytes, ...]) -> str:
        # the first and last character of the first ALPN value; a character that is not alphanumeric
        # is replaced by the first, respectively last, hex digit of its byte
        if not protocols or not protocols[0]:
            return cls.NO_PROTOCOL_CODE
        first, last = protocols[0][0], protocols[0][-1]
        if bytes((first,)).isalnum() and bytes((last,)).isalnum():
            return chr(first) + chr(last)
        return f"{first:02x}"[0] + f"{last:02x}"[1]


class PseudoHeader(StrEnum):
    METHOD = "m"
    AUTHORITY = "a"
    SCHEME = "s"
    PATH = "p"


@dataclass(frozen=True, slots=True)
class Http2Setting(Value):
    identifier: Http2SettingIdentifier
    value: int

    @classmethod
    def parse(cls, text: str) -> Self:
        identifier, separator, value = text.partition(":")
        if not separator:
            raise ParseError(f"an HTTP/2 setting is written identifier:value, not {text!r}")
        return cls(Http2SettingIdentifier(int(identifier)), int(value))

    @property
    def text(self) -> str:
        return f"{int(self.identifier)}:{self.value}"


class PriorityShape(IntEnum):
    FIELDS = 4


@dataclass(frozen=True, slots=True)
class Http2Priority(Value):
    stream_id: int
    exclusive: bool
    dependency: int
    weight: int

    @classmethod
    def parse(cls, text: str) -> Self:
        fields = text.split(":")
        if len(fields) != PriorityShape.FIELDS:
            raise ParseError(f"an HTTP/2 priority is written stream:exclusive:dependency:weight, not {text!r}")
        stream_id, exclusive, dependency, weight = fields
        return cls(int(stream_id), bool(int(exclusive)), int(dependency), int(weight))

    @property
    def text(self) -> str:
        return f"{self.stream_id}:{int(self.exclusive)}:{self.dependency}:{self.weight}"


class AkamaiShape(IntEnum):
    PARTS = 4


@dataclass(frozen=True, slots=True)
class AkamaiFingerprint(Value):
    settings: tuple[Http2Setting, ...]
    window_update: int
    priorities: tuple[Http2Priority, ...]
    pseudo_header_order: tuple[PseudoHeader, ...]

    NO_PRIORITIES = "0"

    @classmethod
    def parse(cls, text: str) -> Self:
        parts = text.split("|")
        if len(parts) != AkamaiShape.PARTS:
            raise ParseError(f"an Akamai fingerprint has {AkamaiShape.PARTS} pipe separated parts, not {len(parts)}")
        settings, window_update, priorities, order = parts
        return cls(
            tuple(Http2Setting.parse(item) for item in settings.split(";") if item),
            int(window_update),
            ()
            if priorities == cls.NO_PRIORITIES
            else tuple(Http2Priority.parse(item) for item in priorities.split(",")),
            tuple(PseudoHeader(letter) for letter in order.split(",") if letter),
        )

    @property
    def text(self) -> str:
        priorities = ",".join(priority.text for priority in self.priorities) or self.NO_PRIORITIES
        return "|".join(
            (
                ";".join(setting.text for setting in self.settings),
                str(self.window_update),
                priorities,
                ",".join(header.value for header in self.pseudo_header_order),
            )
        )

    @property
    def digest(self) -> str:
        return hashlib.md5(self.text.encode(), usedforsecurity=False).hexdigest()
