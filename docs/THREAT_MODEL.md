# FastVault Threat Model

This document outlines the security boundaries, assumed threats, protected assets, and explicit limitations of FastVault.

## Protected Assets
1. **Secret Payload Confidentiality**: Plaintext values of stored API keys, database credentials, tokens, SSH metadata, notes, and TOTP seeds.
2. **Metadata Confidentiality**: Secret names, namespaces, and tags stored within the encrypted payload.
3. **Audit Trail Integrity**: Protection against undetected deletion or modification of audit log history.

## What FastVault Protects Against (Threat Vectors Mitigated)

| Threat Scenario | Mitigation Strategy |
| :--- | :--- |
| **Physical Theft of Storage Device** | All secrets and metadata are encrypted on disk using AES-256-GCM. Unlocking requires the Argon2id key derived from the master password. |
| **Malicious Sync Backend / Cloud Storage** | Sync payloads use end-to-end client-side AEAD encryption before transmission. Remote backends cannot read secret payloads or forge authentic ciphertexts. |
| **Accidental Plaintext Disk Spills** | Process environment injection (`fastvault run`) passes secret values directly to child process RAM environments without writing `.env` files to disk. |
| **Malicious IPC Interception** | Agent UNIX sockets are constrained to `0600` permissions (owner read/write only) on directory `0700`. |
| **Master Password Brute-Force** | Argon2id KDF ($m=65536, t=3, p=4$) imposes heavy computational and memory penalties on offline GPU/ASIC cracking attempts. |
| **Silent Corruption or Bit-Rot** | AES-256-GCM authentication tags guarantee tamper detection on both header and payload. Vaults fail closed. |

## What FastVault Cannot Protect Against (Out of Scope)
1. **Compromised Host OS / Kernel / Root Malware**: A keylogger, memory scraper, or rootkit running with elevated privileges on the local machine can capture keypresses or read unlocked agent memory.
2. **Clipboard Scrapers**: Malware monitoring the system clipboard before the 30-second auto-clear timer expires.
3. **Hardware / Cold Boot Attacks**: Direct physical RAM extraction while the agent daemon holds the unwrapped DEK in active memory.
