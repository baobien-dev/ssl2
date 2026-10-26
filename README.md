# ssl2

TLS interface for Python 3.14 after PEP 748, plus what a real client needs around it: typed IANA registries, a ClientHello model with a builder and a wire parser, JA3, JA4 and Akamai fingerprints, proxies, a blocking socket and an asyncio stream that run on any PEP 748 `TLSBuffer`, a session cache and the system trust store. Pure Python, no dependencies. The engine is a separate package, for example `boring-ssl2`.

```text
uv add ssl2
```

## ClientHello model and fingerprints

```python
from ssl2 import (
    JA3,
    JA4,
    CertificateCompressionAlgorithm,
    CipherSuite,
    ClientHelloBuilder,
    ECPointFormat,
    ExtensionType,
    NamedGroup,
    NextProtocol,
    ProtocolVersion,
    PskKeyExchangeMode,
    SignatureScheme,
)

chrome = (
    ClientHelloBuilder()
    .supported_versions(ProtocolVersion.TLS_1_3, ProtocolVersion.TLS_1_2)
    .cipher_suites(
        CipherSuite.TLS_AES_128_GCM_SHA256,
        CipherSuite.TLS_AES_256_GCM_SHA384,
        CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
    )
    .extensions(
        ExtensionType.server_name,
        ExtensionType.extended_main_secret,
        ExtensionType.renegotiation_info,
        ExtensionType.supported_groups,
        ExtensionType.ec_point_formats,
        ExtensionType.session_ticket,
        ExtensionType.application_layer_protocol_negotiation,
        ExtensionType.status_request,
        ExtensionType.signature_algorithms,
        ExtensionType.signed_certificate_timestamp,
        ExtensionType.key_share,
        ExtensionType.psk_key_exchange_modes,
        ExtensionType.supported_versions,
        ExtensionType.compress_certificate,
        ExtensionType.application_settings_old,
        ExtensionType.encrypted_client_hello,
    )
    .supported_groups(NamedGroup.X25519MLKEM768, NamedGroup.x25519, NamedGroup.secp256r1, NamedGroup.secp384r1)
    .key_shares(NamedGroup.X25519MLKEM768, NamedGroup.x25519)
    .ec_point_formats(ECPointFormat.uncompressed)
    .signature_algorithms(
        SignatureScheme.ecdsa_secp256r1_sha256,
        SignatureScheme.rsa_pss_rsae_sha256,
        SignatureScheme.rsa_pkcs1_sha256,
        SignatureScheme.ecdsa_secp384r1_sha384,
        SignatureScheme.rsa_pss_rsae_sha384,
        SignatureScheme.rsa_pkcs1_sha384,
        SignatureScheme.rsa_pss_rsae_sha512,
        SignatureScheme.rsa_pkcs1_sha512,
    )
    .application_protocols(NextProtocol.H2, NextProtocol.HTTP1)
    .application_settings(NextProtocol.H2)
    .certificate_compression(CertificateCompressionAlgorithm.brotli)
    .psk_key_exchange_modes(PskKeyExchangeMode.psk_dhe_ke)
    .grease()
    .build()
)
print(JA4.of(chrome).text)  # t13d1516h2_8daaf6152771_02713d6af862
print(JA3.of(chrome).digest)  # 5549240a5133e94d2053bfbc454228ef
```

Every setter also takes the code point itself, so `.extensions(0, 23, 65281)` and `.cipher_suites(0x1301)` mean the same thing; that is how a captured fingerprint arrives. Unassigned and GREASE code points still parse:

```python
from ssl2 import CipherSuite, ExtensionType

print(ExtensionType(17613).name, CipherSuite(0x1A1A).name, CipherSuite(0x1A1A).is_grease)  # application_settings unassigned_0x1a1a True
```

The parser reads a ClientHello from the TLS record or the bare handshake message, strips GREASE and sets `grease`:

```python
from ssl2 import ClientHelloParser

hello = ClientHelloParser.parse(client_hello_bytes)
print(hello.grease, hello.cipher_suites, hello.key_share_groups)
```

Fingerprint text forms parse back, except the hashed JA4 form:

```python
from ssl2 import JA4, AkamaiFingerprint

ja4 = JA4.of(chrome)
print(ja4.raw)  # t13d1516h2_002f,0035,...,cca9_0005,000a,...,ff01_0403,0804,...
print(JA4.parse(ja4.raw).text == ja4.text, JA4.parse(ja4.original).text == ja4.text)  # True True
akamai = AkamaiFingerprint.parse("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p")
print(akamai.digest)  # 52d84b11737d980aef856699f885ca86
print(JA3.parse(JA3.of(chrome).text) == JA3.of(chrome))  # True
```

`JA3.builder()` starts a `ClientHelloBuilder` from the JA3 fields; the payloads JA3 does not carry, such as signature schemes, key shares and ALPN, go in before `build()`.

`.trust_anchor_ids("44947.2.1", ...)` lists the trust anchor identifiers of draft-ietf-tls-trust-anchor-ids in dotted form, which the parser reads back from the wire. `CHROME_TRUST_ANCHOR_IDS` is the 28 Chrome 155 requests, and `TrustAnchorIdentifier.encode` and `.decode` move between the dotted form and the wire bytes.

## Configuration, credentials, trust

```python
from ssl2 import Certificate, PrivateKey, SigningChain, TLSClientConfiguration, TLSServerConfiguration, TLSVersion, TrustStore

client = TLSClientConfiguration(trust_store=TrustStore.system(), lowest_supported_version=TLSVersion.TLSv1_3)
pinned = TLSClientConfiguration(trust_store=TrustStore.from_file("ca.pem"), client_hello=chrome)
server = TLSServerConfiguration(certificate_chain=(SigningChain((Certificate.from_file("server.pem"), PrivateKey.from_file("server.key"))),))
print(TrustStore.system())  # TrustStore(buffer=None, path=PosixPath('/etc/ssl/certs/ca-certificates.crt'), id=None)
```

`TrustStore.system()` honors `SSL_CERT_FILE` and `SSL_CERT_DIR`, then the usual Linux and macOS bundles, and reads the ROOT and CA stores through crypt32 on Windows.

## Proxies

```python
from ssl2 import Proxy

proxy = Proxy.parse("socks5h://user:secret@proxy.example:1080")  # http, https, socks4, socks4a, socks5, socks5h
print(proxy.scheme, proxy.host, proxy.port, proxy.credentials)
```

`socks4` and `socks5` resolve the destination locally, `socks4a`, `socks5h` and the HTTP schemes let the proxy resolve it, and an `https` proxy carries TLS inside TLS with the same client context. A refusal raises `ProxyError` with the proxy's reason.

## Sockets and streams on any engine

```python
import asyncio

from ssl2 import TLSSocket, TLSStream

connection = TLSSocket.connect(context, ("www.python.org", 443), proxy=None, timeout=10)
connection.send(b"HEAD / HTTP/1.1\r\nHost: www.python.org\r\nConnection: close\r\n\r\n")
print(connection.recv(4096).split(b"\r\n", 1)[0], connection.negotiated_tls_version, connection.cipher())
connection.close()


async def main() -> None:
    stream = await TLSStream.connect(context, ("www.python.org", 443), timeout=10)
    await stream.write(b"HEAD / HTTP/1.1\r\nHost: www.python.org\r\nConnection: close\r\n\r\n")
    print((await stream.read(4096)).split(b"\r\n", 1)[0], stream.negotiated_protocol())
    await stream.close()


asyncio.run(main())
```

`context` is an engine's `ClientContext`. A peer that drops TCP without close_notify reads as `b""`, the same default the `ssl` module has. On a direct connection, and behind an HTTP or SOCKS proxy, both hand the TCP socket to the engine through `TLSBuffer.attach`, so records move between the kernel and the TLS state without a stop in Python; behind an HTTPS proxy, or over any other `AsyncTransport`, the records go through the buffer's memory BIOs instead. A socket timeout applies to every wait.

## Writing an engine

An engine implements `ClientContext`, `ServerContext` and `TLSBuffer` from `ssl2.interface` and exposes `TLSImplementation(ClientContext, ServerContext, validate_config)`. `TLSSocket` and `TLSStream` drive any such `TLSBuffer`, through its memory BIOs or, when the buffer implements `attach(fileno)`, by handing it the socket; `getpeerchain()` returns the certificates the peer sent, leaf first. `SessionCache` stores what the engine records.
