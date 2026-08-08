# Changelog

All notable changes to FastVault will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-07

### Added
- **Core Domain (`fastvault-core`)**: Modular secrets model, types, zeroize memory protection, policy engine.
- **Crypto Engine (`fastvault-crypto`)**: Argon2id KDF, AES-256-GCM AEAD, key hierarchy with DEK re-wrapping, versioned binary vault header.
- **Storage Engine (`fastvault-store`)**: Atomic persistence, cross-process file locking, permission enforcement (0600), versioning, encrypted backups, tombstones/trash.
- **Tamper-Evident Audit (`fastvault-audit`)**: HMAC-SHA256 hash chain audit trail without plaintext secret leakage.
- **Local Agent (`fastvault-agent`)**: Background daemon with Unix domain socket / Windows named pipe IPC, in-memory key caching, TTL auto-lock.
- **Multi-Device Sync (`fastvault-sync`)**: Client-side encrypted sync backend abstraction with conflict detection.
- **Developer Environment Injection (`fastvault-cli`)**: Process environment injection (`fastvault run`) and template renderer (`fastvault template render`).
- **Terminal UI (`fastvault-tui`)**: Interactive TUI dashboard built with Ratatui.
- **Benchmarks & Testing (`benches/`, `tests/`, `fuzz/`)**: Criterion benchmark suite, integration tests, property testing with proptest, cargo-fuzz targets.
