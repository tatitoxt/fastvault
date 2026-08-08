# FastVault — Knowledge Base Index
#fastvault #rust #security #cryptography #architecture

> High-performance, local-first, zero-cloud-by-default secrets management system written in Rust with modern AEAD key-wrapping cryptography, zeroize memory safety, local IPC daemon, process environment injection, and Ratatui terminal UI.

Repository: [tatitoxt/fastvault](https://github.com/tatitoxt/fastvault)

---

## 📚 Core Navigation

- [[01 - Architecture & Design]] — Modular crate breakdown & system DAG
- [[02 - Cryptography & Key Wrapping]] — Argon2id KDF, AES-256-GCM, KEK/DEK key hierarchy
- [[03 - Threat Model & Security Boundaries]] — Mitigated attack vectors & explicit boundaries
- [[04 - Vault Format & File Layout]] — Binary `.fvt` envelope, header, AAD binding
- [[05 - Benchmark Results & Performance]] — Measured Criterion benchmark metrics
- [[06 - CLI & Agent Integration Guide]] — CLI subcommands, `fastvault run`, Unix socket IPC

---

## ⚡ Quick Metrics Summary

- **Language**: Rust 2021 (8 Workspace Crates)
- **KDF Derivation Time**: `~45.2 ms` (Argon2id, 64MB memory cost)
- **Encryption Time**: `~1.84 ms` (1,000 secrets)
- **Decryption Time**: `~1.12 ms` (1,000 secrets)
- **IPC Access Latency**: `~0.32 ms` (Tokio async Unix socket)
