import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Self

from ssl2.client_hello import ClientHello, ClientHelloBuilder
from ssl2.parameters import (
    CipherSuite,
    CodePoint,
    ECPointFormat,
    ExtensionType,
    Http2SettingIdentifier,
    NamedGroup,
    ProtocolVersion,
    SignatureScheme,
)

JA4_HASH_LENGTH: Final = 12
JA4_UNHASHED_EXTENSIONS: Final = frozenset(
    {ExtensionType.server_name, ExtensionType.application_layer_protocol_negotiation}
)


@dataclass(frozen=True, slots=True)
class JA3:
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
        if len(fields) != 5:
            raise ValueError("JA3 text needs five comma separated fields")
        version, cipher_suites, extensions, supported_groups, ec_point_formats = fields
        return cls(
            ProtocolVersion(int(version)),
            cls._values(CipherSuite, cipher_suites),
            cls._values(ExtensionType, extensions),
            cls._values(NamedGroup, supported_groups),
            cls._values(ECPointFormat, ec_point_formats),
        )

    def builder(self) -> ClientHelloBuilder:
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
        fields = (
            self.cipher_suites,
            self.extensions,
            self.supported_groups,
            self.ec_point_formats,
        )
        return ",".join(
            (str(int(self.version)), *(self._join(field) for field in fields))
        )

    @property
    def digest(self) -> str:
        return hashlib.md5(self.text.encode(), usedforsecurity=False).hexdigest()

    @staticmethod
    def _join(values: tuple[CodePoint, ...]) -> str:
        return "-".join(str(int(value)) for value in values)

    @staticmethod
    def _values[CodePointT: CodePoint](
        registry: type[CodePointT], text: str
    ) -> tuple[CodePointT, ...]:
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


@dataclass(frozen=True, slots=True)
class JA4:
    transport: JA4Transport
    version: JA4Version
    server_name_indicated: bool
    cipher_count: int
    extension_count: int
    application_protocol_code: str
    cipher_suites: tuple[CipherSuite, ...]
    extensions: tuple[ExtensionType, ...]
    signature_algorithms: tuple[SignatureScheme, ...]

    @classmethod
    def of(
        cls, client_hello: ClientHello, transport: JA4Transport = JA4Transport.TCP
    ) -> Self:
        return cls(
            transport,
            JA4Version.__members__.get(
                client_hello.highest_version.name, JA4Version.UNKNOWN
            ),
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
        sections = text.split("_")
        if len(sections) not in (3, 4):
            raise ValueError(
                "JA4 text needs three or four underscore separated sections"
            )
        prefix = sections[0]
        if len(prefix) != 10:
            raise ValueError("the JA4 prefix is ten characters")
        if any(cls._is_hash(section) for section in sections[1:3]):
            raise ValueError(
                "hashed JA4 carries no cipher or extension lists; parse the raw or original form"
            )
        signature_algorithms = (
            cls._values(SignatureScheme, sections[3]) if len(sections) == 4 else ()
        )
        return cls(
            JA4Transport(prefix[0]),
            JA4Version(prefix[1:3]),
            prefix[3] == "d",
            int(prefix[4:6]),
            int(prefix[6:8]),
            prefix[8:10],
            cls._values(CipherSuite, sections[1]),
            cls._values(ExtensionType, sections[2]),
            signature_algorithms,
        )

    @property
    def prefix(self) -> str:
        server_name = "d" if self.server_name_indicated else "i"
        counts = f"{min(self.cipher_count, 99):02d}{min(self.extension_count, 99):02d}"
        return f"{self.transport}{self.version}{server_name}{counts}{self.application_protocol_code}"

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
        kept = sorted(
            extension.hex
            for extension in self.extensions
            if extension not in JA4_UNHASHED_EXTENSIONS
        )
        return self._with_signature_algorithms(",".join(kept))

    def _with_signature_algorithms(self, extensions: str) -> str:
        if not extensions or not self.signature_algorithms:
            return extensions
        return extensions + "_" + self._join(self.signature_algorithms)

    @staticmethod
    def _join(values: tuple[CodePoint, ...]) -> str:
        return ",".join(value.hex for value in values)

    @staticmethod
    def _values[CodePointT: CodePoint](
        registry: type[CodePointT], text: str
    ) -> tuple[CodePointT, ...]:
        return tuple(registry(int(value, 16)) for value in text.split(",") if value)

    @staticmethod
    def _hash(section: str) -> str:
        if not section:
            return "0" * JA4_HASH_LENGTH
        return hashlib.sha256(section.encode()).hexdigest()[:JA4_HASH_LENGTH]

    @staticmethod
    def _is_hash(section: str) -> bool:
        return len(section) == JA4_HASH_LENGTH and "," not in section

    @staticmethod
    def _protocol_code(protocols: tuple[bytes, ...]) -> str:
        if not protocols or not protocols[0]:
            return "00"
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
class Http2Setting:
    identifier: Http2SettingIdentifier
    value: int

    @property
    def text(self) -> str:
        return f"{int(self.identifier)}:{self.value}"


@dataclass(frozen=True, slots=True)
class Http2Priority:
    stream_id: int
    exclusive: bool
    dependency: int
    weight: int

    @property
    def text(self) -> str:
        return f"{self.stream_id}:{int(self.exclusive)}:{self.dependency}:{self.weight}"


@dataclass(frozen=True, slots=True)
class AkamaiFingerprint:
    settings: tuple[Http2Setting, ...]
    window_update: int
    priorities: tuple[Http2Priority, ...]
    pseudo_header_order: tuple[PseudoHeader, ...]

    @classmethod
    def parse(cls, text: str) -> Self:
        parts = text.split("|")
        if len(parts) != 4:
            raise ValueError("Akamai fingerprint text needs four pipe separated parts")
        settings, window_update, priorities, order = parts
        return cls(
            tuple(cls._setting(item) for item in settings.split(";") if item),
            int(window_update),
            ()
            if priorities == "0"
            else tuple(cls._priority(item) for item in priorities.split(",")),
            tuple(PseudoHeader(letter) for letter in order.split(",") if letter),
        )

    @property
    def text(self) -> str:
        priorities = ",".join(priority.text for priority in self.priorities) or "0"
        settings = ";".join(setting.text for setting in self.settings)
        return "|".join(
            (
                settings,
                str(self.window_update),
                priorities,
                ",".join(header.value for header in self.pseudo_header_order),
            )
        )

    @property
    def digest(self) -> str:
        return hashlib.md5(self.text.encode(), usedforsecurity=False).hexdigest()

    @staticmethod
    def _setting(item: str) -> Http2Setting:
        identifier, value = item.split(":")
        return Http2Setting(Http2SettingIdentifier(int(identifier)), int(value))

    @staticmethod
    def _priority(item: str) -> Http2Priority:
        stream_id, exclusive, dependency, weight = item.split(":")
        return Http2Priority(
            int(stream_id), bool(int(exclusive)), int(dependency), int(weight)
        )
