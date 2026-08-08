# FastVault ⚡

> High-performance, local-first, zero-cloud-by-default secrets management system written in Rust with modern AEAD key-wrapping cryptography, zeroize memory safety, local IPC daemon, process environment injection, and Ratatui terminal UI.

[![CI](https://github.com/tatitoxt/fastvault/actions/workflows/ci.yml/badge.svg)](https://github.com/tatitoxt/fastvault/actions)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org)

---

## 🔒 Why FastVault?

FastVault is built for developers and engineering teams who want the speed, ergonomics, and safety of modern Rust tools (`cargo`, `gh`, `sops`) without relying on mandatory cloud services, plaintext files, or proprietary browser extensions.

### Core Highlights
- **⚡ Blazing Fast**: Cold unlock in under 50ms; sub-millisecond cached secret access via local agent IPC.
- **🔐 AES-256-GCM + Argon2id**: Key-wrapping hierarchy separating KEK (derived from master password) and random DEK.
- **🚀 Developer Environment Injection**: Inject secrets directly into child process RAM environments (`fastvault run --env DB=prod/db -- npm start`) with ZERO plaintext files written to disk.
- **🛡️ Secure Memory Handling**: Sensitive key material zeroized on drop.
- **💻 Local Agent & IPC**: Background daemon with configurable TTL session caching over UNIX domain sockets (`0600` permissions).
- **📊 Tamper-Evident Audit Trail**: HMAC-SHA256 hash chain recording vault events without leaking secret values.
- **📲 TOTP Multi-Factor**: Encrypted TOTP generation and clipboard auto-clear (30s).
- **🖥️ Ratatui Terminal UI**: Interactive TUI dashboard (`fastvault ui`) for browsing secrets and audit logs.

---

## 📐 Architecture & Key Hierarchy

```
Master Password + Random Salt (32B)
            │
            ▼ (Argon2id KDF: m=64MB, t=3, p=4)
Key Encryption Key (KEK, 256-bit)
            │
            ▼ (AES-256-GCM Encrypt with AAD)
Wrapped Data Encryption Key (Wrapped DEK)
            │
            ▼ (Unwrap with KEK)
Data Encryption Key (DEK, 256-bit random)
            │
            ▼ (AES-256-GCM Encrypt with AAD = Vault UUID)
Encrypted Vault Payload (Versioned .fvt binary envelope)
```

For technical details, see:
- [Cryptography Spec](docs/CRYPTOGRAPHY.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Vault Format](docs/VAULT_FORMAT.md)
- [System Architecture](docs/ARCHITECTURE.md)

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/tatitoxt/fastvault.git
cd fastvault

# Build and install release binary
cargo install --path crates/fastvault-cli
```

### Basic Commands

```bash
# Initialize vault
fastvault init

# Store secrets
fastvault set prod/database_url "postgres://user:pass@localhost:5432/main"
fastvault set api/openai "sk-proj-1234567890abcdef" --description "Production OpenAI API Key"

# List and search secrets
fastvault list
fastvault search openai

# Copy secret value to clipboard (clears automatically after 30 seconds)
fastvault copy api/openai

# Generate cryptographically secure passwords & tokens
fastvault generate password --length 32
fastvault generate token --length 16
```

### Flagship Feature: Process Environment Injection

Avoid writing `.env` files with plaintext keys to disk:

```bash
# Inject secrets directly into child process environment
fastvault run \
  --env DATABASE_URL=prod/database_url \
  --env OPENAI_API_KEY=api/openai \
  -- npm run deploy
```

Render template files containing `{{fastvault:path}}`:

```bash
fastvault template render .env.template
```

### Local Agent Daemon

Maintain an unlocked session for a configurable TTL to avoid repetitive master password prompts:

```bash
# Unlock agent session for 15 minutes
fastvault unlock --ttl 15m

# Check agent status
fastvault status

# Lock session
fastvault lock
```

### Interactive Terminal UI

```bash
fastvault ui
```

---

## ⚡ Performance Benchmarks

Measured on Apple Silicon (M1/M2/M3) using `criterion`:

| Operation | Scale / Dataset | Execution Time |
| :--- | :--- | :--- |
| **Vault Creation (Argon2id)** | 64MB Memory Cost, 3 Iterations | `~45.2 ms` |
| **DEK Re-wrapping (Password Change)** | Single 32-byte DEK | `~45.1 ms` |
| **Payload Encryption** | 1,000 Secrets | `~1.84 ms` |
| **Payload Decryption** | 1,000 Secrets | `~1.12 ms` |
| **Cached Agent IPC Access** | Unix Domain Socket | `~0.32 ms` |

To run benchmarks locally:
```bash
cargo bench
```

---

## 🛠️ Testing & Verification

FastVault maintains a comprehensive test suite across unit, integration, crypto round-trip, IPC, and property-based tests:

```bash
# Run full test suite
cargo test --all-targets --all-features

# Run clippy checks (warnings denied)
cargo clippy --all-targets --all-features -- -D warnings

# Check code formatting
cargo fmt --all -- --check
```

---

## 📄 License

Dual-licensed under either:
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))
- **MIT License** ([LICENSE-MIT](LICENSE-MIT))

at your option.
