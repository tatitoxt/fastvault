# Security Policy

FastVault takes security seriously. As a local-first secrets manager written in Rust, maintaining high standards for security, cryptography, and code correctness is our highest priority.

## Reporting a Vulnerability

If you discover a security vulnerability within FastVault, please do **NOT** open a public issue on GitHub.

Instead, please send an email directly to the maintainer or report it via GitHub Private Vulnerability Reporting:

- **Email**: `security@fastvault.dev` (or maintainer contact)
- **GitHub**: Submit a security advisory under the **Security** tab of the `tatitoxt/fastvault` repository.

### What to Include in Your Report
1. A clear description of the vulnerability and its potential impact.
2. Step-by-step instructions or proof-of-concept (PoC) code to reproduce the issue.
3. Operating system, FastVault version, and platform details.

## Response Commitment
- **Initial Response**: Within 24-48 hours.
- **Triage & Assessment**: Within 5 business days.
- **Fix & Patch**: Depending on severity, critical security fixes are released within 7-14 days.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Architecture Overview
FastVault uses audited cryptographic standards:
- **AEAD**: AES-256-GCM for authenticated payload encryption.
- **KDF**: Argon2id for password-based key derivation.
- **Memory Hygiene**: Zeroize for wiping sensitive buffers on drop.
- **IPC**: Unix Domain Sockets with strict 0600 file permissions and UID verification.
