# FastVault Architecture

FastVault is built as a highly modular Rust workspace designed with strict separation of domain logic, cryptography, storage, daemon IPC, multi-device synchronization, and user interfaces.

```
fastvault/
├── crates/
│   ├── fastvault-core/         # Pure domain models (Secret, PolicyEngine, TotpGenerator)
│   ├── fastvault-crypto/       # Argon2id KDF, AES-256-GCM AEAD, KeyHierarchy (KEK/DEK wrapping)
│   ├── fastvault-store/        # Atomic storage, permissions (0600), fd-lock, encrypted backups
│   ├── fastvault-audit/        # HMAC-SHA256 tamper-evident event log chain
│   ├── fastvault-agent/        # Local background daemon, Tokio async IPC (Unix socket / Named Pipe)
│   ├── fastvault-sync/         # Multi-device client-side encrypted sync (SyncBackend, Local, S3)
│   ├── fastvault-tui/          # Ratatui terminal UI dashboard
│   └── fastvault-cli/          # Command-line interface (`fastvault`) & env injection
├── docs/                       # ARCHITECTURE.md, CRYPTOGRAPHY.md, THREAT_MODEL.md, VAULT_FORMAT.md
├── benches/                    # Criterion performance benchmarks
├── fuzz/                       # cargo-fuzz parsers
└── .github/                    # CI/CD, security audit, dependabot
```

## Modular Crate System

### 1. `fastvault-core`
Contains pure domain entities with zero IO side effects:
- **`Secret`**: Represents secret entries with UUID, namespace, metadata, version history, tags, expiration timestamps, and zeroize-on-drop value buffers.
- **`PolicyEngine`**: Enforces security policies (max TTL, password age, expiration, clipboard auto-clearing).
- **`TotpGenerator`**: Encrypted TOTP multi-factor code generation.

### 2. `fastvault-crypto`
Implements the cryptographic key hierarchy and versioned binary vault format:
- **Argon2id KDF**: Key derivation function parameterized with 64 MB memory cost, 3 time iterations, and 4 parallelism lanes.
- **Key Hierarchy**: Master Password $\rightarrow$ KEK $\rightarrow$ wraps DEK $\rightarrow$ encrypts payload.
- **AES-256-GCM**: AEAD authenticated encryption with 96-bit random nonces and AAD binding.

### 3. `fastvault-store`
Manages persistence and file safety:
- **Atomic File Writes**: Writes to temporary file (`tempfile`), calls `sync_all()`, and atomically renames to target.
- **File Locking**: Cross-process file locking via `fd-lock`.
- **Permissions**: Enforces `0600` permissions on Unix systems and `0700` on configuration directories.

### 4. `fastvault-agent`
Provides an in-memory unlocked session daemon:
- **IPC Protocol**: Serialized request/response over Unix Domain Sockets (`/tmp/fastvault-<uid>/agent.sock`).
- **TTL Cache**: Holds unwrapped DEK in zeroized memory with automatic timeout cleanup worker.

### 5. `fastvault-sync`
Encrypted multi-device synchronization:
- Client-side encryption ensures remote storage backends (Local folder, WebDAV, S3) never see unencrypted data.
- Detects revision conflicts using SHA-256 payload digests and prevents silent overwrites.
