import base64
import ctypes
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntFlag, StrEnum
from pathlib import Path
from typing import Self

from ssl2.errors import ConfigurationError
from ssl2.value import Value


@dataclass(frozen=True, slots=True)
class Credential(Value):
    buffer: bytes | None = None
    path: Path | None = None
    id: bytes | None = None

    @classmethod
    def from_buffer(cls, buffer: bytes) -> Self:
        return cls(buffer=buffer)

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> Self:
        return cls(path=Path(path))

    @classmethod
    def from_id(cls, identifier: bytes) -> Self:
        return cls(id=identifier)


@dataclass(frozen=True, slots=True)
class Certificate(Credential):
    pass


@dataclass(frozen=True, slots=True)
class PrivateKey(Credential):
    pass


@dataclass(frozen=True, slots=True)
class TrustStore(Credential):
    @classmethod
    def system(cls) -> Self:
        return SystemTrustStore.locate(cls)


@dataclass(frozen=True, slots=True)
class SigningChain(Value):
    leaf: tuple[Certificate, PrivateKey | None]
    chain: Sequence[Certificate] | None = None


class CertificateEncoding(IntFlag):
    # the dwCertEncodingType of a CERT_CONTEXT
    X509_ASN = 0x00000001


class WindowsStoreName(StrEnum):
    ROOT = "ROOT"
    CA = "CA"


class CertificateContext(ctypes.Structure):
    # the leading fields of CERT_CONTEXT, the rest is not read
    _fields_ = (
        ("encoding_type", ctypes.c_uint32),
        ("encoded", ctypes.POINTER(ctypes.c_ubyte)),
        ("encoded_length", ctypes.c_uint32),
    )


class WindowsCertificateStore:
    PEM_BEGIN = b"-----BEGIN CERTIFICATE-----\n"
    PEM_END = b"-----END CERTIFICATE-----\n"

    @classmethod
    def bundle(cls) -> bytes:
        if sys.platform != "win32":
            raise ConfigurationError(
                f"the Windows certificate stores are not on {sys.platform}"
            )
        crypt32 = ctypes.WinDLL("crypt32.dll")
        crypt32.CertOpenSystemStoreW.restype = ctypes.c_void_p
        crypt32.CertOpenSystemStoreW.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p)
        crypt32.CertEnumCertificatesInStore.restype = ctypes.POINTER(CertificateContext)
        crypt32.CertEnumCertificatesInStore.argtypes = (
            ctypes.c_void_p,
            ctypes.c_void_p,
        )
        crypt32.CertCloseStore.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
        chunks: list[bytes] = []
        for name in WindowsStoreName:
            store = crypt32.CertOpenSystemStoreW(None, name)
            if store is None:
                raise ConfigurationError(
                    f"cannot open the Windows {name} certificate store"
                )
            context = crypt32.CertEnumCertificatesInStore(store, None)
            while context:
                entry = context.contents
                if entry.encoding_type & CertificateEncoding.X509_ASN and entry.encoded:
                    der = ctypes.string_at(entry.encoded, entry.encoded_length)
                    chunks.append(cls.PEM_BEGIN + base64.encodebytes(der) + cls.PEM_END)
                context = crypt32.CertEnumCertificatesInStore(store, context)
            crypt32.CertCloseStore(store, 0)
        return b"".join(chunks)


class SystemTrustStore:
    # where each platform keeps its root certificates; the first path that exists is the store
    LINUX_PATHS = (
        Path("/etc/ssl/certs/ca-certificates.crt"),
        Path("/etc/pki/tls/certs/ca-bundle.crt"),
        Path("/etc/ssl/ca-bundle.pem"),
        Path("/etc/pki/tls/cacert.pem"),
        Path("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"),
        Path("/etc/ssl/cert.pem"),
        Path("/etc/ssl/certs"),
        Path("/etc/pki/tls/certs"),
    )
    ANDROID_PATHS = (
        Path("/data/data/com.termux/files/usr/etc/tls/cert.pem"),
        Path("/system/etc/security/cacerts"),
    )
    DARWIN_PATHS = (Path("/etc/ssl/cert.pem"), Path("/private/etc/ssl/cert.pem"))

    @classmethod
    def locate[TrustStoreT: TrustStore](cls, store: type[TrustStoreT]) -> TrustStoreT:
        if sys.platform == "win32":
            return store(buffer=WindowsCertificateStore.bundle())
        if sys.platform == "ios":
            raise ConfigurationError(
                "iOS keeps no file of root certificates; ship a bundle with the app and pass TrustStore.from_file"
            )
        if sys.platform == "darwin":
            candidates = cls.DARWIN_PATHS
        else:
            candidates = cls.ANDROID_PATHS + cls.LINUX_PATHS
        for candidate in candidates:
            if candidate.exists():
                return store(path=candidate)
        searched = ", ".join(str(candidate) for candidate in candidates)
        raise ConfigurationError(f"no system trust store at {searched}")
