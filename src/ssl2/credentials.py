import base64
import ctypes
import os
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from ssl2.errors import ConfigurationError

LINUX_CANDIDATES = (
    Path("/etc/ssl/certs/ca-certificates.crt"),
    Path("/etc/pki/tls/certs/ca-bundle.crt"),
    Path("/etc/ssl/ca-bundle.pem"),
    Path("/etc/pki/tls/cacert.pem"),
    Path("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"),
    Path("/etc/ssl/cert.pem"),
    Path("/etc/ssl/certs"),
    Path("/etc/pki/tls/certs"),
    Path("/system/etc/security/cacerts"),
)
DARWIN_CANDIDATES = (
    Path("/etc/ssl/cert.pem"),
    Path("/private/etc/ssl/cert.pem"),
)
X509_ASN_ENCODING = 0x00000001


@dataclass(frozen=True, slots=True)
class Credential:
    buffer: bytes | None = None
    path: str | os.PathLike[str] | None = None
    id: bytes | None = None

    @classmethod
    def from_buffer(cls, buffer: bytes) -> Self:
        return cls(buffer=buffer)

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> Self:
        return cls(path=path)

    @classmethod
    def from_id(cls, id: bytes) -> Self:
        return cls(id=id)


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
        for variable in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
            if variable in os.environ:
                return cls(path=os.environ[variable])
        if sys.platform == "win32":
            return cls(buffer=cls._windows_bundle(ctypes.WinDLL("crypt32.dll")))
        candidates = DARWIN_CANDIDATES if sys.platform == "darwin" else LINUX_CANDIDATES
        for candidate in candidates:
            if candidate.exists():
                return cls(path=candidate)
        raise ConfigurationError(f"no system trust store found on {sys.platform}")

    @staticmethod
    def _crypt32(
        dll: ctypes.CDLL,
    ) -> tuple[
        Callable[[None, str], int | None],
        Callable[[int, int | None], int | None],
        Callable[[int, int], int],
    ]:
        dll.CertOpenSystemStoreW.restype = ctypes.c_void_p
        dll.CertOpenSystemStoreW.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p)
        dll.CertEnumCertificatesInStore.restype = ctypes.c_void_p
        dll.CertEnumCertificatesInStore.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
        dll.CertCloseStore.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
        return (
            dll.CertOpenSystemStoreW,
            dll.CertEnumCertificatesInStore,
            dll.CertCloseStore,
        )

    @classmethod
    def _windows_bundle(cls, dll: ctypes.CDLL) -> bytes:
        open_store, enumerate_store, close_store = cls._crypt32(dll)
        # CERT_CONTEXT starts with a u32 encoding type, a pointer to the DER bytes and their u32 length, each at pointer alignment
        pointer = ctypes.sizeof(ctypes.c_void_p)
        chunks: list[bytes] = []
        for name in ("ROOT", "CA"):
            store = open_store(None, name)
            if store is None:
                raise ConfigurationError(
                    f"cannot open the Windows {name} certificate store"
                )
            context = enumerate_store(store, None)
            while context is not None:
                encoding_type = ctypes.c_uint32.from_address(context).value
                encoded = ctypes.c_void_p.from_address(context + pointer).value
                length = ctypes.c_uint32.from_address(context + 2 * pointer).value
                if encoding_type & X509_ASN_ENCODING and encoded is not None:
                    der = ctypes.string_at(encoded, length)
                    chunks.append(
                        b"-----BEGIN CERTIFICATE-----\n"
                        + base64.encodebytes(der)
                        + b"-----END CERTIFICATE-----\n"
                    )
                context = enumerate_store(store, context)
            close_store(store, 0)
        return b"".join(chunks)


@dataclass(frozen=True, slots=True)
class SigningChain:
    leaf: tuple[Certificate, PrivateKey | None]
    chain: Sequence[Certificate] | None = None
