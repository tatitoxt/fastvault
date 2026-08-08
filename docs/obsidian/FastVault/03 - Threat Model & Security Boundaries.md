# 03 - Threat Model & Security Boundaries
#fastvault #security #threatmodel

Back link: [[00 - FastVault Index]]

## 🛡️ Mitigated Threats

- **Physical Storage Theft**: All vault files and backups are encrypted with AES-256-GCM. Argon2id KDF prevents GPU brute-force attacks.
- **Plaintext Disk Leakage**: Process secret injection (`fastvault run`) passes secret variables directly into child process RAM without writing `.env` files to disk.
- **IPC Interception**: UNIX domain sockets are restricted to `0600` permissions (owner read/write only) on `0700` parent directories.
- **Audit Log Tampering**: Operations are recorded in an HMAC-SHA256 hash chain where altering an entry breaks chain verification (`fastvault audit --verify`).

## ⚠️ Explicit Out-of-Scope Boundaries

- **Compromised Host Kernel / Root Malware**: Root-level keyloggers or memory scrapers on the local machine can read unlocked process RAM.
- **Clipboard Monitors**: Malware reading system clipboard before 30-second auto-clear timer expires.

Related Notes:
- [[02 - Cryptography & Key Wrapping]]
- [[06 - CLI & Agent Integration Guide]]
