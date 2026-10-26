from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import Self

from ssl2.parameters import (
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


@dataclass(frozen=True, slots=True, kw_only=True)
class ClientHello:
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
            raise ValueError("extensions must not repeat")
        if len(set(self.supported_versions)) != len(self.supported_versions):
            raise ValueError("supported_versions must not repeat")
        payloads: tuple[tuple[object, ExtensionType], ...] = (
            (self.supported_groups, ExtensionType.supported_groups),
            (self.key_share_groups, ExtensionType.key_share),
            (self.ec_point_formats, ExtensionType.ec_point_formats),
            (self.signature_algorithms, ExtensionType.signature_algorithms),
            (
                self.application_protocols,
                ExtensionType.application_layer_protocol_negotiation,
            ),
            (
                self.certificate_compression_algorithms,
                ExtensionType.compress_certificate,
            ),
            (self.psk_key_exchange_modes, ExtensionType.psk_key_exchange_modes),
            (self.delegated_credential_schemes, ExtensionType.delegated_credential),
            (self.record_size_limit, ExtensionType.record_size_limit),
            (self.trust_anchor_ids, ExtensionType.trust_anchors),
        )
        for value, extension in payloads:
            if bool(value) != self.offers(extension):
                raise ValueError(
                    f"{extension.name} needs its payload and its extension together"
                )
        settings = {
            ExtensionType.application_settings,
            ExtensionType.application_settings_old,
        }
        if len(settings & set(self.extensions)) != bool(self.application_settings):
            raise ValueError(
                "application_settings needs exactly one application_settings extension codepoint"
            )
        if not self._is_subsequence(self.key_share_groups, self.supported_groups):
            raise ValueError(
                "key_share_groups must follow the order of supported_groups"
            )
        if not self.offers(
            ExtensionType.supported_versions
        ) and self.supported_versions != (self.legacy_version,):
            raise ValueError(
                "without the supported_versions extension only the legacy version is offered"
            )

    def offers(self, extension: ExtensionType) -> bool:
        return extension in self.extensions

    @property
    def highest_version(self) -> ProtocolVersion:
        return max(self.supported_versions)

    @property
    def lowest_version(self) -> ProtocolVersion:
        return min(self.supported_versions)

    @staticmethod
    def _is_subsequence(
        part: tuple[NamedGroup, ...], whole: tuple[NamedGroup, ...]
    ) -> bool:
        position = 0
        for group in whole:
            if position < len(part) and part[position] == group:
                position += 1
        return position == len(part)


EMPTY_CLIENT_HELLO = ClientHello(cipher_suites=(), extensions=())
# the trust anchor identifiers Chrome 155 requests: its root store, in the dotted form of draft-ietf-tls-trust-anchor-ids
CHROME_TRUST_ANCHOR_IDS = (
    "44947.2.1",
    "44947.2.6",
    "44947.2.13",
    "44947.2.14",
    "44947.2.15",
    "44947.2.18",
    "44947.2.19",
    "44947.2.20",
    "52580.200109.1.7",
    "52580.200109.1.8",
    "52580.200109.1.9",
    "52580.200109.1.10",
    "52580.200109.1.11",
    "52580.200109.1.12",
    "52580.200109.1.13",
    "52580.200109.1.18",
    "52580.200109.1.19",
    "11129.9.1",
    "11129.9.4",
    "11129.9.5",
    "11129.9.6",
    "11129.9.7",
    "11129.9.8",
    "11129.9.10",
    "11129.9.11",
    "11129.9.12",
    "11129.9.13",
    "11129.9.15",
)


class TrustAnchorIdentifier:
    # draft-ietf-tls-trust-anchor-ids: a relative object identifier, dotted in the model and base-128 arcs on the wire
    @staticmethod
    def encode(dotted: str) -> bytes:
        wire = bytearray()
        for arc in dotted.split("."):
            number = int(arc)
            groups = [number & 0x7F]
            number >>= 7
            while number:
                groups.append(0x80 | (number & 0x7F))
                number >>= 7
            wire += bytes(reversed(groups))
        return bytes(wire)

    @staticmethod
    def decode(wire: bytes) -> str:
        arcs: list[int] = []
        number = 0
        open_arc = False
        for byte in wire:
            number = (number << 7) | (byte & 0x7F)
            open_arc = bool(byte & 0x80)
            if not open_arc:
                arcs.append(number)
                number = 0
        if open_arc or not arcs:
            raise ValueError("malformed trust anchor identifier")
        return ".".join(str(arc) for arc in arcs)


class ClientHelloBuilder:
    def __init__(self) -> None:
        self._fields: dict[str, object] = {}

    def legacy_version(self, version: ProtocolVersion | int) -> Self:
        return self._set("legacy_version", ProtocolVersion(version))

    def supported_versions(self, *versions: ProtocolVersion | int) -> Self:
        return self._set(
            "supported_versions",
            tuple(ProtocolVersion(version) for version in versions),
        )

    def cipher_suites(self, *suites: CipherSuite | int) -> Self:
        return self._set("cipher_suites", tuple(CipherSuite(suite) for suite in suites))

    def extensions(self, *types: ExtensionType | int) -> Self:
        return self._set("extensions", tuple(ExtensionType(type) for type in types))

    def supported_groups(self, *groups: NamedGroup | int) -> Self:
        return self._set(
            "supported_groups", tuple(NamedGroup(group) for group in groups)
        )

    def key_shares(self, *groups: NamedGroup | int) -> Self:
        return self._set(
            "key_share_groups", tuple(NamedGroup(group) for group in groups)
        )

    def ec_point_formats(self, *formats: ECPointFormat | int) -> Self:
        return self._set(
            "ec_point_formats", tuple(ECPointFormat(format) for format in formats)
        )

    def signature_algorithms(self, *schemes: SignatureScheme | int) -> Self:
        return self._set(
            "signature_algorithms", tuple(SignatureScheme(scheme) for scheme in schemes)
        )

    def application_protocols(self, *protocols: NextProtocol | bytes) -> Self:
        return self._set("application_protocols", self._protocol_bytes(protocols))

    def application_settings(self, *protocols: NextProtocol | bytes) -> Self:
        return self._set("application_settings", self._protocol_bytes(protocols))

    def certificate_compression(
        self, *algorithms: CertificateCompressionAlgorithm | int
    ) -> Self:
        algorithms_typed = tuple(
            CertificateCompressionAlgorithm(algorithm) for algorithm in algorithms
        )
        return self._set("certificate_compression_algorithms", algorithms_typed)

    def psk_key_exchange_modes(self, *modes: PskKeyExchangeMode | int) -> Self:
        return self._set(
            "psk_key_exchange_modes", tuple(PskKeyExchangeMode(mode) for mode in modes)
        )

    def delegated_credentials(self, *schemes: SignatureScheme | int) -> Self:
        return self._set(
            "delegated_credential_schemes",
            tuple(SignatureScheme(scheme) for scheme in schemes),
        )

    def record_size_limit(self, limit: int | None) -> Self:
        return self._set("record_size_limit", limit)

    def trust_anchor_ids(self, *identifiers: str) -> Self:
        return self._set("trust_anchor_ids", identifiers)

    def grease(self, enabled: bool = True) -> Self:
        return self._set("grease", enabled)

    def permute_extensions(self, enabled: bool = True) -> Self:
        return self._set("permute_extensions", enabled)

    def build(self) -> ClientHello:
        return replace(EMPTY_CLIENT_HELLO, **self._fields)

    def _set(self, name: str, value: object) -> Self:
        self._fields[name] = value
        return self

    @staticmethod
    def _protocol_bytes(protocols: Iterable[NextProtocol | bytes]) -> tuple[bytes, ...]:
        return tuple(
            protocol.value if isinstance(protocol, NextProtocol) else protocol
            for protocol in protocols
        )


class ByteReader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._position = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self._position

    def take(self, length: int) -> bytes:
        if length > self.remaining:
            raise ValueError("truncated ClientHello")
        chunk = self._data[self._position : self._position + length]
        self._position += length
        return chunk

    def integer(self, width: int) -> int:
        return int.from_bytes(self.take(width), "big")

    def vector(self, length_width: int) -> bytes:
        return self.take(self.integer(length_width))

    def integers(self, length_width: int, item_width: int) -> tuple[int, ...]:
        body = self.vector(length_width)
        if len(body) % item_width:
            raise ValueError("malformed vector length")
        return tuple(
            int.from_bytes(body[offset : offset + item_width], "big")
            for offset in range(0, len(body), item_width)
        )

    def strings(self, length_width: int, item_length_width: int) -> tuple[bytes, ...]:
        inner = ByteReader(self.vector(length_width))
        items: list[bytes] = []
        while inner.remaining:
            items.append(inner.vector(item_length_width))
        return tuple(items)


class ClientHelloParser:
    def __init__(self) -> None:
        self._fields: dict[str, object] = {}
        self._grease = False

    @classmethod
    def parse(cls, data: bytes) -> ClientHello:
        if not data:
            raise ValueError("empty ClientHello")
        if data[0] == ContentType.handshake:
            data = cls._unwrap_records(data)
        reader = ByteReader(data)
        if reader.integer(1) != HandshakeType.client_hello:
            raise ValueError("not a ClientHello")
        parser = cls()
        parser._read_body(ByteReader(reader.vector(3)))
        return replace(EMPTY_CLIENT_HELLO, **parser._fields, grease=parser._grease)

    @staticmethod
    def _unwrap_records(data: bytes) -> bytes:
        reader = ByteReader(data)
        message = bytearray()
        while reader.remaining:
            content_type = reader.integer(1)
            reader.take(2)
            fragment = reader.vector(2)
            if content_type != ContentType.handshake:
                raise ValueError("record is not a handshake record")
            message += fragment
            if len(message) >= 4 and len(message) >= 4 + int.from_bytes(
                message[1:4], "big"
            ):
                break
        return bytes(message)

    def _read_body(self, body: ByteReader) -> None:
        legacy_version = ProtocolVersion(body.integer(2))
        body.take(32)
        body.vector(1)
        self._fields["legacy_version"] = legacy_version
        self._fields["supported_versions"] = (legacy_version,)
        self._fields["cipher_suites"] = self._typed(CipherSuite, body.integers(2, 2))
        body.vector(1)
        extensions: list[ExtensionType] = []
        if body.remaining:
            block = ByteReader(body.vector(2))
            while block.remaining:
                extension_type = ExtensionType(block.integer(2))
                payload = ByteReader(block.vector(2))
                if extension_type.is_grease:
                    self._grease = True
                    continue
                extensions.append(extension_type)
                self._read_payload(extension_type, payload)
        self._fields["extensions"] = tuple(extensions)

    def _read_payload(self, extension_type: ExtensionType, payload: ByteReader) -> None:
        match extension_type:
            case ExtensionType.supported_versions:
                self._fields["supported_versions"] = self._typed(
                    ProtocolVersion, payload.integers(1, 2)
                )
            case ExtensionType.supported_groups:
                self._fields["supported_groups"] = self._typed(
                    NamedGroup, payload.integers(2, 2)
                )
            case ExtensionType.ec_point_formats:
                self._fields["ec_point_formats"] = self._typed(
                    ECPointFormat, payload.integers(1, 1)
                )
            case ExtensionType.signature_algorithms:
                self._fields["signature_algorithms"] = self._typed(
                    SignatureScheme, payload.integers(2, 2)
                )
            case ExtensionType.application_layer_protocol_negotiation:
                self._fields["application_protocols"] = payload.strings(2, 1)
            case (
                ExtensionType.application_settings
                | ExtensionType.application_settings_old
            ):
                self._fields["application_settings"] = payload.strings(2, 1)
            case ExtensionType.key_share:
                shares = ByteReader(payload.vector(2))
                groups: list[int] = []
                while shares.remaining:
                    groups.append(shares.integer(2))
                    shares.vector(2)
                self._fields["key_share_groups"] = self._typed(
                    NamedGroup, tuple(groups)
                )
            case ExtensionType.psk_key_exchange_modes:
                self._fields["psk_key_exchange_modes"] = self._typed(
                    PskKeyExchangeMode, payload.integers(1, 1)
                )
            case ExtensionType.compress_certificate:
                self._fields["certificate_compression_algorithms"] = self._typed(
                    CertificateCompressionAlgorithm, payload.integers(1, 2)
                )
            case ExtensionType.delegated_credential:
                self._fields["delegated_credential_schemes"] = self._typed(
                    SignatureScheme, payload.integers(2, 2)
                )
            case ExtensionType.record_size_limit:
                self._fields["record_size_limit"] = payload.integer(2)
            case ExtensionType.trust_anchors:
                self._fields["trust_anchor_ids"] = tuple(
                    TrustAnchorIdentifier.decode(identifier)
                    for identifier in payload.strings(2, 1)
                )
            case _:
                pass

    def _typed[CodePointT: CodePoint](
        self, registry: type[CodePointT], values: tuple[int, ...]
    ) -> tuple[CodePointT, ...]:
        members = tuple(registry(value) for value in values)
        kept = tuple(member for member in members if not member.is_grease)
        self._grease |= len(kept) != len(members)
        return kept
