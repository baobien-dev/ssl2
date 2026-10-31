# Changelog

All notable changes to ssl2. The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

The library was written again from the ground up. What a program sees:

### Changed

- Every value is a typed object: `str()` shows its fields and `dict()` turns it into a mapping. A code point prints as its name, `CipherSuite.TLS_AES_128_GCM_SHA256`, not as a number.
- The registries come from the IANA files of 2026-10-31. A GREASE value is a named member, `CipherSuite(0x1A1A).name == "GREASE_1A1A"`, in every registry RFC 8701 covers, versions and PSK modes included.
- The model refuses what cannot be sent with `ConfigurationError`; text and bytes that do not parse raise `ParseError`, a `ValueError` too. A code point given as its number becomes the member.
- `EarlyDataRejected` is `EarlyDataRejectedError`; `ProxyError` lives in `ssl2.errors`.
- A proxy handshake is a state machine: `proxy.handshake(destination)` gives `Step`s with the bytes to send and the shape of the reply; `Socks5Datagram` wraps and unwraps relay datagrams.
- `TLSStream.connect` has no `timeout=`; the caller's `asyncio.timeout` is the limit. On Windows' default event loop the records go through the memory BIOs, since that loop cannot watch a socket.
- `TrustStore.system()` reads no environment variable. It knows the Linux, Termux, Android and macOS paths and the Windows stores, and tells an iOS app to pass its own bundle.

### Added

- `legacy_padding` on `ClientHello` for clients that pad a hello of 256 to 511 bytes to 512, as Android did before late 2026.
- `Trace` and `trace=` on `TLSSocket.connect` and `TLSStream.connect`: the timed steps of a connection, printable.
- The `ssl2` logger reports connections, proxy steps, handshakes and closes.
- `Value`, the base of every typed object.
- `tools/generate_registry.py` downloads the IANA registries and BoringSSL's `tls1.h` and writes `registry.py`.

## [2.2.0] - 2026-10-27

- `AsyncTransport` and `TLSStream` answer `getsockname` and `getpeername`.

## [2.1.0] - 2026-10-27

- `server_hostname=` on `connect`, for SNI and verification when the address is not the name.

## [2.0.1] - 2026-10-27

- `proxy_context=` on `connect`, so the TLS hop to an https proxy can offer only http/1.1.

## [2.0.0] - 2026-10-27

- No Chrome trust anchor list; the caller passes its own ids.

## [1.2.0] - 2026-10-26

- The socket handed to the engine, the peer's chain, trust anchor ids in the ClientHello.

## [1.1.0] - 2026-10-26

- The ClientHello and HTTP/3 Chrome 155 sends over QUIC.

## [1.0.1] - 2026-10-26

- Requires Python 3.14, not the 3.14.8 patch release.

## [1.0.0] - 2026-10-26

- PEP 748 TLS interface.
