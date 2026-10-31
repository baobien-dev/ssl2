# Changelog

All notable changes to ssl2. The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
