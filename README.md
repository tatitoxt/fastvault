# FastVault

A Rust CLI for storing secrets encrypted locally and delivering them to
processes without writing them to a `.env` file. The repository is a
Cargo workspace with a CLI, a core library, a local unlock agent, an
audit log, and a TUI.

*[README en español](README.es.md)*

```bash
git clone https://github.com/tatitoxt/fastvault.git && cd fastvault
cargo build --workspace
cargo run -p fastvault-cli -- --help
```

## Features

- **Encrypted vault** — Argon2id key derivation + AES-256-GCM, versioned
  vault format ([docs/VAULT_FORMAT.md](docs/VAULT_FORMAT.md))
- **Secrets with history** — namespaces, tags, per-secret version history,
  soft delete to a trash bin and restore
- **Secret delivery without `.env`** — `fastvault run --env
  NAME=path -- cmd` injects values into a child process's environment;
  `fastvault template render` substitutes `{{fastvault:path}}` markers
- **Local agent** — optional agent caches the data-encryption key over a
  Unix socket so you unlock once per session
- **Tamper-evident audit log** — every mutation appends an HMAC-chained
  event; `fastvault audit --verify` re-verifies the whole chain
- **Encrypted backups** — `backup create/inspect/restore` round-trips the
  vault through an independently encrypted `.fvbak` file
- **Directory sync** — `fastvault sync push <dir>` copies the encrypted
  vault blob to a target directory (a mounted share, an `rsync` source,
  a git remote) as a content-hashed revision; re-push is a no-op when
  nothing changed, divergence without `--force` is refused, and
  `sync list` shows the remote's revision history
- **Generators** — passwords and hex tokens with length control
- **TUI** — `fastvault ui` for browsing and editing interactively

## Requirements

- Rust and Cargo
- macOS or Linux for features that use Unix sockets (the agent)

## Build and test

Run the workspace suite from the root:

```bash
cargo test --workspace
```

The suite covers the vault lifecycle, master-password rotation, local
storage, the agent, and audit-chain verification — plus an end-to-end
suite (`crates/fastvault-cli/tests/e2e.rs`) that drives the compiled
binary against a temporary vault: set/get/list/search/delete/restore,
password rotation, backup round-trip, `run` env injection, template
rendering, directory sync, and audit-chain tamper detection.

`FASTVAULT_PASSWORD` supplies the master password non-interactively for
scripts and CI; `--vault-path` selects the vault file.

## Performance

Measured with `cargo bench -p fastvault-crypto` (Criterion, 100 samples):

| Operation | Latency |
|---|---|
| Vault creation (Argon2id KDF) | ~0.37 ms |
| Encrypt 1,000 secrets (AES-256-GCM) | ~0.70 ms (~1.4M secrets/s) |
| Decrypt 1,000 secrets | ~0.85 ms (~1.2M secrets/s) |

See [docs/benchmarks.md](docs/benchmarks.md) for methodology and
reproduction.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Cryptographic design](docs/CRYPTOGRAPHY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Vault format](docs/VAULT_FORMAT.md)
- [Benchmarks](docs/benchmarks.md)

## Limitations

- **No independent security audit.** FastVault is in development — do not
  use it as the only safeguard for critical credentials.
- **Local only** — no team sharing or access control beyond the master
  password. `sync` pushes to plain directories only (no remote server);
  the S3 backend is a stub.
- **Agent is Unix-socket based** — macOS/Linux only; Windows uses the
  prompt-per-command path.
- **`run` injects via environment variables** — visible to the child
  process and anything that can read its environment (e.g. `/proc`).

## License

MIT or Apache-2.0, at your option. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).
