from dataclasses import dataclass
from enum import IntEnum
from typing import Self

from ssl2.errors import ConfigurationError, ParseError
from ssl2.registry import (
    CertificateCompressionAlgorithm,
    CipherSuite,
    CodePoint,
    ContentType,
    ECPointFormat,
    ExtensionType,
    HandshakeType,
    NamedGroup,
    NextProtocol,
    ProtocolVersion,
    PskKeyExchangeMode,
    SignatureScheme,
)
from ssl2.value import Value


class Width(IntEnum):
    # byte widths of the record layer, the handshake header and the ClientHello body, RFC 8446 sections 4.1.2 and 5.1
    RECORD_VERSION = 2
    RECORD_LENGTH = 2
    HANDSHAKE_TYPE = 1
    HANDSHAKE_LENGTH = 3
    LEGACY_VERSION = 2
    RANDOM = 32
    SESSION_ID_LENGTH = 1
    CIPHER_SUITES_LENGTH = 2
    CIPHER_SUITE = 2
    COMPRESSION_METHODS_LENGTH = 1
    EXTENSIONS_LENGTH = 2
    EXTENSION_TYPE = 2
    EXTENSION_LENGTH = 2
    # the extension bodies this parser reads
    VERSIONS_LENGTH = 1
    VERSION = 2
    GROUPS_LENGTH = 2
    GROUP = 2
    POINT_FORMATS_LENGTH = 1
    POINT_FORMAT = 1
    SIGNATURE_SCHEMES_LENGTH = 2
    SIGNATURE_SCHEME = 2
    PROTOCOL_NAMES_LENGTH = 2
    PROTOCOL_NAME_LENGTH = 1
    KEY_SHARES_LENGTH = 2
    KEY_EXCHANGE_LENGTH = 2
    PSK_MODES_LENGTH = 1
    PSK_MODE = 1
    COMPRESSION_ALGORITHMS_LENGTH = 1
    COMPRESSION_ALGORITHM = 2
    RECORD_SIZE_LIMIT = 2
    TRUST_ANCHORS_LENGTH = 2
    TRUST_ANCHOR_LENGTH = 1


class Base128(IntEnum):
    # the arcs of a trust anchor identifier, seven bits per byte with the high bit saying another byte follows
    PAYLOAD = 0x7F
    CONTINUES = 0x80
    SHIFT = 7


@dataclass(frozen=True, slots=True, kw_only=True)
class ClientHello(Value):
    legacy_version: ProtocolVersion = ProtocolVersion.TLS_1_2
    supported_versions: tuple[ProtocolVersion, ...] = (ProtocolVersion.TLS_1_2,)
    cipher_suites: tuple[CipherSuite, ...]
    extensions: tuple[ExtensionType, ...]
    supported_groups: tuple[NamedGroup, ...] = ()
    key_share_groups: tuple[NamedGroup, ...] = ()
    ec_point_formats: tuple[ECPointFormat, ...] = ()
    signature_algorithms: tuple[SignatureScheme, ...] = ()
    application_protocols: tuple[bytes, ...] = ()
    application_settings: tuple[bytes, ...] = ()
    certificate_compression_algorithms: tuple[CertificateCompressionAlgorithm, ...] = ()
    psk_key_exchange_modes: tuple[PskKeyExchangeMode, ...] = ()
    delegated_credential_schemes: tuple[SignatureScheme, ...] = ()
    record_size_limit: int | None = None
    trust_anchor_ids: tuple[str, ...] = ()
    grease: bool = False
    permute_extensions: bool = False

    def __post_init__(self) -> None:
        if len(set(self.extensions)) != len(self.extensions):
            raise ConfigurationError("extensions must not repeat")
        if len(set(self.supported_versions)) != len(self.supported_versions):
            raise ConfigurationError("supported_versions must not repeat")
        for name, members in self._code_point_lists():
            if any(member.is_grease for member in members):
                raise ConfigurationError(f"{name} holds a GREASE value; set grease=True and the engine adds them")
        for extension, payload in self._payloads():
            if bool(payload) != self.offers(extension):
                raise ConfigurationError(f"{extension.name} needs its payload and its extension together")
        settings_offered = self.offers(ExtensionType.application_settings) + self.offers(
            ExtensionType.application_settings_old
        )
        if settings_offered != bool(self.application_settings):
            raise ConfigurationError(
                "application_settings needs exactly one of the two application_settings extensions"
            )
        if not self._is_subsequence(self.key_share_groups, self.supported_groups):
            raise ConfigurationError("key_share_groups must follow the order of supported_groups")
        if not self.offers(ExtensionType.supported_versions) and self.supported_versions != (self.legacy_version,):
            raise ConfigurationError("without the supported_versions extension only the legacy version is offered")

    def offers(self, extension: ExtensionType) -> bool:
        return extension in self.extensions

    @property
    def highest_version(self) -> ProtocolVersion:
        return max(self.supported_versions)

    @property
    def lowest_version(self) -> ProtocolVersion:
        return min(self.supported_versions)

    def _code_point_lists(self) -> tuple[tuple[str, tuple[CodePoint, ...]], ...]:
        return (
            ("supported_versions", self.supported_versions),
            ("cipher_suites", self.cipher_suites),
            ("extensions", self.extensions),
            ("supported_groups", self.supported_groups),
            ("key_share_groups", self.key_share_groups),
            ("signature_algorithms", self.signature_algorithms),
            ("psk_key_exchange_modes", self.psk_key_exchange_modes),
        )

    def _payloads(self) -> tuple[tuple[ExtensionType, object], ...]:
        return (
            (ExtensionType.supported_groups, self.supported_groups),
            (ExtensionType.key_share, self.key_share_groups),
            (ExtensionType.ec_point_formats, self.ec_point_formats),
            (ExtensionType.signature_algorithms, self.signature_algorithms),
            (
                ExtensionType.application_layer_protocol_negotiation,
                self.application_protocols,
            ),
            (
                ExtensionType.compress_certificate,
                self.certificate_compression_algorithms,
            ),
            (ExtensionType.psk_key_exchange_modes, self.psk_key_exchange_modes),
            (ExtensionType.delegated_credential, self.delegated_credential_schemes),
            (ExtensionType.record_size_limit, self.record_size_limit),
            (ExtensionType.trust_anchors, self.trust_anchor_ids),
        )

    @staticmethod
    def _is_subsequence(part: tuple[NamedGroup, ...], whole: tuple[NamedGroup, ...]) -> bool:
        position = 0
        for group in whole:
            if position < len(part) and part[position] == group:
                position += 1
        return position == len(part)


class TrustAnchorIdentifier:
    # draft-ietf-tls-trust-anchor-ids: a relative object identifier, dotted in the model, base 128 arcs on the wire
    @staticmethod
    def encode(dotted: str) -> bytes:
        wire = bytearray()
        for arc in dotted.split("."):
            number = int(arc)
            groups = [number & Base128.PAYLOAD]
            number >>= Base128.SHIFT
            while number:
                groups.append(Base128.CONTINUES | (number & Base128.PAYLOAD))
                number >>= Base128.SHIFT
            wire += bytes(reversed(groups))
        return bytes(wire)

    @staticmethod
    def decode(wire: bytes) -> str:
        arcs: list[int] = []
        number = 0
        open_arc = False
        for byte in wire:
            number = (number << Base128.SHIFT) | (byte & Base128.PAYLOAD)
            open_arc = bool(byte & Base128.CONTINUES)
            if not open_arc:
                arcs.append(number)
                number = 0
        if open_arc or not arcs:
            raise ParseError("malformed trust anchor identifier")
        return ".".join(str(arc) for arc in arcs)


class ClientHelloBuilder:
    def __init__(self) -> None:
        self._legacy_version = ProtocolVersion.TLS_1_2
        self._supported_versions: tuple[ProtocolVersion, ...] = (ProtocolVersion.TLS_1_2,)
        self._cipher_suites: tuple[CipherSuite, ...] = ()
        self._extensions: tuple[ExtensionType, ...] = ()
        self._supported_groups: tuple[NamedGroup, ...] = ()
        self._key_share_groups: tuple[NamedGroup, ...] = ()
        self._ec_point_formats: tuple[ECPointFormat, ...] = ()
        self._signature_algorithms: tuple[SignatureScheme, ...] = ()
        self._application_protocols: tuple[bytes, ...] = ()
        self._application_settings: tuple[bytes, ...] = ()
        self._certificate_compression_algorithms: tuple[CertificateCompressionAlgorithm, ...] = ()
        self._psk_key_exchange_modes: tuple[PskKeyExchangeMode, ...] = ()
        self._delegated_credential_schemes: tuple[SignatureScheme, ...] = ()
        self._record_size_limit: int | None = None
        self._trust_anchor_ids: tuple[str, ...] = ()
        self._grease = False
        self._permute_extensions = False

    def legacy_version(self, version: ProtocolVersion | int) -> Self:
        self._legacy_version = ProtocolVersion(version)
        return self

    def supported_versions(self, *versions: ProtocolVersion | int) -> Self:
        self._supported_versions = tuple(ProtocolVersion(version) for version in versions)
        return self

    def cipher_suites(self, *suites: CipherSuite | int) -> Self:
        self._cipher_suites = tuple(CipherSuite(suite) for suite in suites)
        return self

    def extensions(self, *types: ExtensionType | int) -> Self:
        self._extensions = tuple(ExtensionType(extension) for extension in types)
        return self

    def supported_groups(self, *groups: NamedGroup | int) -> Self:
        self._supported_groups = tuple(NamedGroup(group) for group in groups)
        return self

    def key_shares(self, *groups: NamedGroup | int) -> Self:
        self._key_share_groups = tuple(NamedGroup(group) for group in groups)
        return self

    def ec_point_formats(self, *formats: ECPointFormat | int) -> Self:
        self._ec_point_formats = tuple(ECPointFormat(point_format) for point_format in formats)
        return self

    def signature_algorithms(self, *schemes: SignatureScheme | int) -> Self:
        self._signature_algorithms = tuple(SignatureScheme(scheme) for scheme in schemes)
        return self

    def application_protocols(self, *protocols: NextProtocol | bytes) -> Self:
        self._application_protocols = self._protocol_bytes(protocols)
        return self

    def application_settings(self, *protocols: NextProtocol | bytes) -> Self:
        self._application_settings = self._protocol_bytes(protocols)
        return self

    def certificate_compression(self, *algorithms: CertificateCompressionAlgorithm | int) -> Self:
        self._certificate_compression_algorithms = tuple(
            CertificateCompressionAlgorithm(algorithm) for algorithm in algorithms
        )
        return self

    def psk_key_exchange_modes(self, *modes: PskKeyExchangeMode | int) -> Self:
        self._psk_key_exchange_modes = tuple(PskKeyExchangeMode(mode) for mode in modes)
        return self

    def delegated_credentials(self, *schemes: SignatureScheme | int) -> Self:
        self._delegated_credential_schemes = tuple(SignatureScheme(scheme) for scheme in schemes)
        return self

    def record_size_limit(self, limit: int | None) -> Self:
        self._record_size_limit = limit
        return self

    def trust_anchor_ids(self, *identifiers: str) -> Self:
        self._trust_anchor_ids = identifiers
        return self

    def grease(self, *, enabled: bool = True) -> Self:
        self._grease = enabled
        return self

    def permute_extensions(self, *, enabled: bool = True) -> Self:
        self._permute_extensions = enabled
        return self

    def build(self) -> ClientHello:
        return ClientHello(
            legacy_version=self._legacy_version,
            supported_versions=self._supported_versions,
            cipher_suites=self._cipher_suites,
            extensions=self._extensions,
            supported_groups=self._supported_groups,
            key_share_groups=self._key_share_groups,
            ec_point_formats=self._ec_point_formats,
            signature_algorithms=self._signature_algorithms,
            application_protocols=self._application_protocols,
            application_settings=self._application_settings,
            certificate_compression_algorithms=self._certificate_compression_algorithms,
            psk_key_exchange_modes=self._psk_key_exchange_modes,
            delegated_credential_schemes=self._delegated_credential_schemes,
            record_size_limit=self._record_size_limit,
            trust_anchor_ids=self._trust_anchor_ids,
            grease=self._grease,
            permute_extensions=self._permute_extensions,
        )

    @staticmethod
    def _protocol_bytes(
        protocols: tuple[NextProtocol | bytes, ...],
    ) -> tuple[bytes, ...]:
        return tuple(protocol.value if isinstance(protocol, NextProtocol) else protocol for protocol in protocols)


class WireReader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._position = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self._position

    def take(self, length: int) -> bytes:
        if length > self.remaining:
            raise ParseError(f"the ClientHello ends {length - self.remaining} bytes early at offset {self._position}")
        chunk = self._data[self._position : self._position + length]
        self._position += length
        return chunk

    def integer(self, width: Width) -> int:
        return int.from_bytes(self.take(width), "big")

    def vector(self, length_width: Width) -> bytes:
        return self.take(self.integer(length_width))

    def integers(self, length_width: Width, item_width: Width) -> tuple[int, ...]:
        body = self.vector(length_width)
        if len(body) % item_width:
            raise ParseError(f"a vector of {len(body)} bytes does not hold items of {item_width} bytes")
        return tuple(
            int.from_bytes(body[offset : offset + item_width], "big") for offset in range(0, len(body), item_width)
        )

    def strings(self, length_width: Width, item_length_width: Width) -> tuple[bytes, ...]:
        inner = WireReader(self.vector(length_width))
        items: list[bytes] = []
        while inner.remaining:
            items.append(inner.vector(item_length_width))
        return tuple(items)


class ClientHelloParser:
    def __init__(self) -> None:
        self._legacy_version = ProtocolVersion.TLS_1_2
        self._supported_versions: tuple[ProtocolVersion, ...] = ()
        self._cipher_suites: tuple[CipherSuite, ...] = ()
        self._extensions: list[ExtensionType] = []
        self._supported_groups: tuple[NamedGroup, ...] = ()
        self._key_share_groups: tuple[NamedGroup, ...] = ()
        self._ec_point_formats: tuple[ECPointFormat, ...] = ()
        self._signature_algorithms: tuple[SignatureScheme, ...] = ()
        self._application_protocols: tuple[bytes, ...] = ()
        self._application_settings: tuple[bytes, ...] = ()
        self._certificate_compression_algorithms: tuple[CertificateCompressionAlgorithm, ...] = ()
        self._psk_key_exchange_modes: tuple[PskKeyExchangeMode, ...] = ()
        self._delegated_credential_schemes: tuple[SignatureScheme, ...] = ()
        self._record_size_limit: int | None = None
        self._trust_anchor_ids: tuple[str, ...] = ()
        self._grease = False

    @classmethod
    def parse(cls, data: bytes) -> ClientHello:
        # a TLS record holding the handshake message, several records, or the bare message
        if not data:
            raise ParseError("an empty ClientHello")
        if data[0] == ContentType.handshake:
            data = cls._unwrap_records(data)
        reader = WireReader(data)
        if reader.integer(Width.HANDSHAKE_TYPE) != HandshakeType.client_hello:
            raise ParseError(f"handshake type {data[0]:#04x} is not a ClientHello")
        parser = cls()
        parser._read_body(WireReader(reader.vector(Width.HANDSHAKE_LENGTH)))
        return parser._model()

    @staticmethod
    def _unwrap_records(data: bytes) -> bytes:
        reader = WireReader(data)
        message = bytearray()
        while reader.remaining:
            content_type = reader.integer(Width.HANDSHAKE_TYPE)
            reader.take(Width.RECORD_VERSION)
            fragment = reader.vector(Width.RECORD_LENGTH)
            if content_type != ContentType.handshake:
                raise ParseError(f"record type {content_type:#04x} is not a handshake record")
            message += fragment
            header = Width.HANDSHAKE_TYPE + Width.HANDSHAKE_LENGTH
            if len(message) >= header and len(message) >= header + int.from_bytes(
                message[Width.HANDSHAKE_TYPE : header], "big"
            ):
                break
        return bytes(message)

    def _read_body(self, body: WireReader) -> None:
        self._legacy_version = ProtocolVersion(body.integer(Width.LEGACY_VERSION))
        self._supported_versions = (self._legacy_version,)
        body.take(Width.RANDOM)
        body.vector(Width.SESSION_ID_LENGTH)
        self._cipher_suites = self._typed(CipherSuite, body.integers(Width.CIPHER_SUITES_LENGTH, Width.CIPHER_SUITE))
        body.vector(Width.COMPRESSION_METHODS_LENGTH)
        if not body.remaining:
            return
        block = WireReader(body.vector(Width.EXTENSIONS_LENGTH))
        while block.remaining:
            extension_type = ExtensionType(block.integer(Width.EXTENSION_TYPE))
            payload = WireReader(block.vector(Width.EXTENSION_LENGTH))
            if extension_type.is_grease:
                self._grease = True
                continue
            self._extensions.append(extension_type)
            self._read_payload(extension_type, payload)

    def _read_payload(self, extension_type: ExtensionType, payload: WireReader) -> None:
        match extension_type:
            case ExtensionType.supported_versions:
                self._supported_versions = self._typed(
                    ProtocolVersion,
                    payload.integers(Width.VERSIONS_LENGTH, Width.VERSION),
                )
            case ExtensionType.supported_groups:
                self._supported_groups = self._typed(NamedGroup, payload.integers(Width.GROUPS_LENGTH, Width.GROUP))
            case ExtensionType.ec_point_formats:
                self._ec_point_formats = self._typed(
                    ECPointFormat,
                    payload.integers(Width.POINT_FORMATS_LENGTH, Width.POINT_FORMAT),
                )
            case ExtensionType.signature_algorithms:
                self._signature_algorithms = self._typed(
                    SignatureScheme,
                    payload.integers(Width.SIGNATURE_SCHEMES_LENGTH, Width.SIGNATURE_SCHEME),
                )
            case ExtensionType.application_layer_protocol_negotiation:
                self._application_protocols = payload.strings(Width.PROTOCOL_NAMES_LENGTH, Width.PROTOCOL_NAME_LENGTH)
            case ExtensionType.application_settings | ExtensionType.application_settings_old:
                self._application_settings = payload.strings(Width.PROTOCOL_NAMES_LENGTH, Width.PROTOCOL_NAME_LENGTH)
            case ExtensionType.key_share:
                shares = WireReader(payload.vector(Width.KEY_SHARES_LENGTH))
                groups: list[int] = []
                while shares.remaining:
                    groups.append(shares.integer(Width.GROUP))
                    shares.vector(Width.KEY_EXCHANGE_LENGTH)
                self._key_share_groups = self._typed(NamedGroup, tuple(groups))
            case ExtensionType.psk_key_exchange_modes:
                self._psk_key_exchange_modes = self._typed(
                    PskKeyExchangeMode,
                    payload.integers(Width.PSK_MODES_LENGTH, Width.PSK_MODE),
                )
            case ExtensionType.compress_certificate:
                self._certificate_compression_algorithms = self._typed(
                    CertificateCompressionAlgorithm,
                    payload.integers(Width.COMPRESSION_ALGORITHMS_LENGTH, Width.COMPRESSION_ALGORITHM),
                )
            case ExtensionType.delegated_credential:
                self._delegated_credential_schemes = self._typed(
                    SignatureScheme,
                    payload.integers(Width.SIGNATURE_SCHEMES_LENGTH, Width.SIGNATURE_SCHEME),
                )
            case ExtensionType.record_size_limit:
                self._record_size_limit = payload.integer(Width.RECORD_SIZE_LIMIT)
            case ExtensionType.trust_anchors:
                self._trust_anchor_ids = tuple(
                    TrustAnchorIdentifier.decode(identifier)
                    for identifier in payload.strings(Width.TRUST_ANCHORS_LENGTH, Width.TRUST_ANCHOR_LENGTH)
                )
            case _:
                # the other extensions carry no field of the model; their presence and order is what counts
                pass

    def _typed[CodePointT: CodePoint](
        self, registry: type[CodePointT], values: tuple[int, ...]
    ) -> tuple[CodePointT, ...]:
        members = tuple(registry(value) for value in values)
        kept = tuple(member for member in members if not member.is_grease)
        self._grease = self._grease or len(kept) != len(members)
        return kept

    def _model(self) -> ClientHello:
        return ClientHello(
            legacy_version=self._legacy_version,
            supported_versions=self._supported_versions,
            cipher_suites=self._cipher_suites,
            extensions=tuple(self._extensions),
            supported_groups=self._supported_groups,
            key_share_groups=self._key_share_groups,
            ec_point_formats=self._ec_point_formats,
            signature_algorithms=self._signature_algorithms,
            application_protocols=self._application_protocols,
            application_settings=self._application_settings,
            certificate_compression_algorithms=self._certificate_compression_algorithms,
            psk_key_exchange_modes=self._psk_key_exchange_modes,
            delegated_credential_schemes=self._delegated_credential_schemes,
            record_size_limit=self._record_size_limit,
            trust_anchor_ids=self._trust_anchor_ids,
            grease=self._grease,
        )
