import csv
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from http import HTTPStatus
from http.client import HTTPSConnection
from io import StringIO
from pathlib import Path
from typing import ClassVar


class Host(StrEnum):
    IANA = "www.iana.org"
    GITHUB_API = "api.github.com"
    GITHUB_RAW = "raw.githubusercontent.com"


class Column(StrEnum):
    VALUE = "Value"
    DESCRIPTION = "Description"
    EXTENSION_NAME = "Extension Name"
    ALGORITHM_NUMBER = "Algorithm Number"
    CODE = "Code"
    NAME = "Name"
    PROTOCOL = "Protocol"
    SEQUENCE = "Identification Sequence"


@dataclass(frozen=True, slots=True)
class Registry:
    class_name: str
    path: str
    value_column: Column
    name_column: Column
    two_byte_grease: bool = False
    one_byte_grease: bool = False
    strip_prefix: str = ""


class Download:
    @staticmethod
    def text(host: Host, path: str) -> str:
        connection = HTTPSConnection(host)
        try:
            connection.request("GET", path, headers={"User-Agent": "ssl2 tools/generate_registry"})
            response = connection.getresponse()
            body = response.read()
        finally:
            connection.close()
        if response.status != HTTPStatus.OK:
            raise RuntimeError(f"https://{host}{path} answered {response.status}")
        return body.decode()


class RegistryGenerator:
    IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    PAIR = re.compile(r"0x([0-9A-Fa-f]{2}),0x([0-9A-Fa-f]{2})")
    HEX = re.compile(r"0x([0-9A-Fa-f]+)")
    DECIMAL = re.compile(r"\d+")
    PARENTHESIZED_WORD = re.compile(r"\s*\((\w+)\)$")
    PARENTHESIZED = re.compile(r"\s*\(.*\)$")
    BORINGSSL_EXTENSION = re.compile(r"#define TLSEXT_TYPE_(\w+) (0x[0-9a-fA-F]+|\d+)")
    ALPN_BYTE = re.compile(r"0x[0-9A-Fa-f]{2}")
    NOT_IDENTIFIER = re.compile(r"[^A-Za-z0-9]")
    # RFC 8701 section 2: the reserved values, both bytes equal with a low nibble of 0xA, and the eight one-byte values
    TWO_BYTE_GREASE = tuple(0x0A0A + 0x1010 * step for step in range(16))
    ONE_BYTE_GREASE = (0x0B, 0x2A, 0x49, 0x68, 0x87, 0xA6, 0xC5, 0xE4)
    BORINGSSL_RENAMES: ClassVar[dict[str, str]] = {"next_proto_neg": "next_protocol_negotiation"}
    ALPN_RENAMES: ClassVar[dict[bytes, str]] = {
        b"http/1.1": "HTTP1",
        b"stun.turn": "TURN",
        b"stun.nat-discovery": "STUN",
    }
    ONE_BYTE_MAXIMUM = 0xFF
    TLS_PARAMETERS = "/assignments/tls-parameters/"
    EXTENSION_VALUES = "/assignments/tls-extensiontype-values/"
    ALPN_PATH = EXTENSION_VALUES + "alpn-protocol-ids.csv"
    BORINGSSL_HEAD = "/repos/google/boringssl/commits/main"
    REGISTRIES = (
        Registry(
            "ContentType",
            TLS_PARAMETERS + "tls-parameters-5.csv",
            Column.VALUE,
            Column.DESCRIPTION,
        ),
        Registry(
            "HandshakeType",
            TLS_PARAMETERS + "tls-parameters-7.csv",
            Column.VALUE,
            Column.DESCRIPTION,
        ),
        Registry(
            "CipherSuite",
            TLS_PARAMETERS + "tls-parameters-4.csv",
            Column.VALUE,
            Column.DESCRIPTION,
            two_byte_grease=True,
        ),
        Registry(
            "ExtensionType",
            EXTENSION_VALUES + "tls-extensiontype-values-1.csv",
            Column.VALUE,
            Column.EXTENSION_NAME,
            two_byte_grease=True,
        ),
        Registry(
            "NamedGroup",
            TLS_PARAMETERS + "tls-parameters-8.csv",
            Column.VALUE,
            Column.DESCRIPTION,
            two_byte_grease=True,
        ),
        Registry(
            "SignatureScheme",
            TLS_PARAMETERS + "tls-signaturescheme.csv",
            Column.VALUE,
            Column.DESCRIPTION,
            two_byte_grease=True,
        ),
        Registry(
            "ECPointFormat",
            TLS_PARAMETERS + "tls-parameters-9.csv",
            Column.VALUE,
            Column.DESCRIPTION,
        ),
        Registry(
            "PskKeyExchangeMode",
            TLS_PARAMETERS + "tls-pskkeyexchangemode.csv",
            Column.VALUE,
            Column.DESCRIPTION,
            one_byte_grease=True,
        ),
        Registry(
            "CertificateCompressionAlgorithm",
            EXTENSION_VALUES + "tls-certificate-compression-algorithm-ids.csv",
            Column.ALGORITHM_NUMBER,
            Column.DESCRIPTION,
        ),
        Registry(
            "Http2SettingIdentifier",
            "/assignments/http2-parameters/settings.csv",
            Column.CODE,
            Column.NAME,
            strip_prefix="SETTINGS_",
        ),
    )

    def __init__(self) -> None:
        self.output = Path(__file__).resolve().parents[1] / "src" / "ssl2" / "registry.py"
        self.boringssl_commit = str(json.loads(Download.text(Host.GITHUB_API, self.BORINGSSL_HEAD))["sha"])

    def run(self) -> None:
        lines = self.header() + self.preamble()
        counts: dict[str, int] = {}
        for registry in self.REGISTRIES:
            members = self.members(registry)
            if registry.class_name == "ExtensionType":
                self.merge_boringssl_extensions(members)
            lines += self.enum_lines(registry.class_name, members)
            counts[registry.class_name] = len(members)
        protocols = self.alpn_members()
        lines += ["", "", "class NextProtocol(Enum):"]
        lines += [f'    {label} = b"{identifier.decode("ascii")}"' for identifier, label in protocols.items()]
        counts["NextProtocol"] = len(protocols)
        self.output.write_text("\n".join(lines) + "\n")
        print(self.output, " ".join(f"{name}={count}" for name, count in counts.items()))

    def header(self) -> list[str]:
        today = datetime.now(UTC).date().isoformat()
        return [
            f"# Generated by tools/generate_registry.py from the IANA TLS registries downloaded {today}",
            f"# and BoringSSL include/openssl/tls1.h at {self.boringssl_commit[:8]}. Regenerate rather than edit.",
        ]

    def preamble(self) -> list[str]:
        two_byte = ", ".join(f"{value:#06x}" for value in self.TWO_BYTE_GREASE[:3])
        lines = [
            "from enum import Enum, StrEnum",
            "from typing import Self, override",
            "",
            "",
            "class Octets(int, Enum):",
            "    # the largest value a code point of that width can hold",
            "    ONE = 0xFF",
            "    TWO = 0xFFFF",
            "",
            "",
            "class Prefix(StrEnum):",
            '    GREASE = "GREASE_"',
            '    UNASSIGNED = "unassigned_"',
            "",
            "",
            "class CodePoint(int, Enum):",
            "    @classmethod",
            "    @override",
            "    def _missing_(cls, value: object) -> Self | None:",
            "        if not isinstance(value, int) or value < 0 or value > Octets.TWO:",
            "            return None",
            "        member = int.__new__(cls, value)",
            '        member._name_ = f"{Prefix.UNASSIGNED}{value:#06x}"',
            "        member._value_ = value",
            "        return member",
            "",
            "    @property",
            "    def is_assigned(self) -> bool:",
            "        return self.name in type(self).__members__ and not self.is_grease",
            "",
            "    @property",
            "    def is_grease(self) -> bool:",
            f"        # RFC 8701 reserves {two_byte} and so on, and eight one-byte values, for sending unknown code points",
            "        return self.name.startswith(Prefix.GREASE)",
            "",
            "    @property",
            "    def hex(self) -> str:",
            '        return f"{int(self):04x}"',
            "",
            "",
            "class TLSVersion(Enum):",
            '    MINIMUM_SUPPORTED = "MINIMUM_SUPPORTED"',
            '    TLSv1_0 = "TLSv1.0"',
            '    TLSv1_1 = "TLSv1.1"',
            '    TLSv1_2 = "TLSv1.2"',
            '    TLSv1_3 = "TLSv1.3"',
            '    MAXIMUM_SUPPORTED = "MAXIMUM_SUPPORTED"',
            "",
            "",
            "class ProtocolVersion(CodePoint):",
            "    SSL_3_0 = 0x0300",
            "    TLS_1_0 = 0x0301",
            "    TLS_1_1 = 0x0302",
            "    TLS_1_2 = 0x0303",
            "    TLS_1_3 = 0x0304",
            "    DTLS_1_0 = 0xFEFF",
            "    DTLS_1_2 = 0xFEFD",
            "    DTLS_1_3 = 0xFEFC",
        ]
        lines += [f"    GREASE_{value:04X} = 0x{value:04X}" for value in self.TWO_BYTE_GREASE]
        lines += [
            "",
            "    @classmethod",
            "    def of(cls, version: TLSVersion) -> ProtocolVersion | None:",
            "        match version:",
            "            case TLSVersion.TLSv1_0:",
            "                return cls.TLS_1_0",
            "            case TLSVersion.TLSv1_1:",
            "                return cls.TLS_1_1",
            "            case TLSVersion.TLSv1_2:",
            "                return cls.TLS_1_2",
            "            case TLSVersion.TLSv1_3:",
            "                return cls.TLS_1_3",
            "            case _:",
            "                return None",
            "",
            "    @property",
            "    def tls_version(self) -> TLSVersion | None:",
            "        match self:",
            "            case ProtocolVersion.TLS_1_0:",
            "                return TLSVersion.TLSv1_0",
            "            case ProtocolVersion.TLS_1_1:",
            "                return TLSVersion.TLSv1_1",
            "            case ProtocolVersion.TLS_1_2:",
            "                return TLSVersion.TLSv1_2",
            "            case ProtocolVersion.TLS_1_3:",
            "                return TLSVersion.TLSv1_3",
            "            case _:",
            "                return None",
            "",
            "",
            "class ServerNameType(CodePoint):",
            "    host_name = 0",
        ]
        return lines

    @staticmethod
    def rows(path: str) -> list[dict[str, str]]:
        return list(csv.DictReader(StringIO(Download.text(Host.IANA, path))))

    def value_of(self, text: str) -> int | None:
        text = text.strip()
        if match := self.PAIR.fullmatch(text):
            return int(match[1] + match[2], 16)
        if match := self.HEX.fullmatch(text):
            return int(match[1], 16)
        if self.DECIMAL.fullmatch(text):
            return int(text)
        return None

    def members(self, registry: Registry) -> dict[int, str]:
        result: dict[int, str] = {}
        for row in self.rows(registry.path):
            value = self.value_of(row[registry.value_column])
            label = row[registry.name_column].strip()
            if value is None or not label or label.startswith(("Unassigned", "Reserved")):
                continue
            label = self.PARENTHESIZED_WORD.sub(r"_\1", label)
            label = self.PARENTHESIZED.sub("", label).removesuffix("_RESERVED").removeprefix(registry.strip_prefix)
            if not self.IDENTIFIER.fullmatch(label):
                raise ValueError(f"{registry.path}: {label!r} is not an identifier")
            if value in result:
                raise ValueError(f"{registry.path}: {value:#x} is both {result[value]} and {label}")
            result[value] = label
        grease = (
            self.TWO_BYTE_GREASE
            if registry.two_byte_grease
            else self.ONE_BYTE_GREASE
            if registry.one_byte_grease
            else ()
        )
        width = 4 if registry.two_byte_grease else 2
        for value in grease:
            if value in result:
                raise ValueError(f"{registry.path}: GREASE value {value:#x} is assigned to {result[value]}")
            result[value] = f"GREASE_{value:0{width}X}"
        return result

    def merge_boringssl_extensions(self, extensions: dict[int, str]) -> None:
        text = Download.text(
            Host.GITHUB_RAW,
            f"/google/boringssl/{self.boringssl_commit}/include/openssl/tls1.h",
        )
        for match in self.BORINGSSL_EXTENSION.finditer(text):
            value = int(match[2], 0)
            if value not in extensions:
                extensions[value] = self.BORINGSSL_RENAMES.get(match[1], match[1])

    def alpn_members(self) -> dict[bytes, str]:
        result: dict[bytes, str] = {}
        for row in self.rows(self.ALPN_PATH):
            if row[Column.PROTOCOL].strip().startswith("Reserved"):
                continue
            sequence = row[Column.SEQUENCE].split("(")[0]
            identifier = bytes(int(token, 16) for token in self.ALPN_BYTE.findall(sequence))
            label = (
                self.ALPN_RENAMES.get(identifier) or self.NOT_IDENTIFIER.sub("_", identifier.decode("ascii")).upper()
            )
            if not self.IDENTIFIER.fullmatch(label):
                raise ValueError(f"ALPN identifier {identifier!r} gives no identifier")
            result[identifier] = label
        return result

    @staticmethod
    def enum_lines(class_name: str, members: dict[int, str]) -> list[str]:
        lines = ["", "", f"class {class_name}(CodePoint):"]
        two_bytes = max(members) > RegistryGenerator.ONE_BYTE_MAXIMUM
        for value in sorted(members):
            literal = f"0x{value:04X}" if two_bytes else str(value)
            lines.append(f"    {members[value]} = {literal}")
        return lines


if __name__ == "__main__":
    RegistryGenerator().run()
