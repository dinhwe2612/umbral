# Umbral Proxy Re-encryption

A Rust implementation of the Umbral threshold proxy re-encryption scheme with Go bindings.

## Overview

Umbral is a threshold proxy re-encryption scheme that allows Alice (the data owner) to delegate decryption rights to Bob for any ciphertext intended to her, through a re-encryption process performed by a set of semi-trusted proxies or Ursulas.

## Components

- **umbral-pre**: Core Rust implementation
- **umbral-pre-cgo**: Go bindings for integration with Go applications

## Quick Start

### Go Integration

```bash
go get github.com/dinhwe2612/umbral/umbral-pre-cgo
```

See the [Go bindings documentation](umbral-pre-cgo/README.md) for detailed usage examples.

## License

GPL-3.0-only
