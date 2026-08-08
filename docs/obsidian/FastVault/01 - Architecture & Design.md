# 01 - Architecture & Design
#fastvault #architecture #rust #crates

Back link: [[00 - FastVault Index]]

FastVault is organized as a modular Rust workspace consisting of 8 separated crates with a strict directed acyclic graph (DAG) dependency flow:

```
fastvault-cli ──► fastvault-tui ──► fastvault-store ──► fastvault-crypto ──► fastvault-core
      │                  │                │                   │
      ├──────────────────┼────────────────┴──────────┐        │
      ▼                  ▼                           ▼        ▼
fastvault-agent ──► fastvault-sync ──────────────► fastvault-audit
```

## 📦 Crate Responsibilities

- **`fastvault-core`**: Domain models (`Secret`, `SecretType`, `PolicyEngine`, `TotpGenerator`) with `Zeroize` memory protections. Zero internal dependencies.
- **`fastvault-crypto`**: Cryptographic operations (`Argon2id` KDF, `AES-256-GCM` AEAD, `KeyHierarchy` DEK/KEK wrapping, `.fvt` versioned binary container).
- **`fastvault-store`**: Persistence layer with atomic file writes (`tempfile`), cross-process locking (`fd-lock`), Unix `0600` permissions, soft deletion (trash bin), and encrypted backups.
- **`fastvault-audit`**: HMAC-SHA256 tamper-evident hash chain event log.
- **`fastvault-agent`**: Background daemon listening on Unix domain sockets (`0600` permissions) with Tokio async IPC and automatic TTL session key zeroization.
- **`fastvault-sync`**: Multi-device client-side encrypted sync engine with SHA-256 revision collision detection.
- **`fastvault-tui`**: Terminal UI dashboard built with `ratatui` and `crossterm`.
- **`fastvault-cli`**: Clap v4 CLI executable with process environment injection (`fastvault run`), template rendering, and 30s clipboard auto-clearing worker.

Related Notes:
- [[02 - Cryptography & Key Wrapping]]
- [[04 - Vault Format & File Layout]]
