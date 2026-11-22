# Benchmarks

All numbers measured on this repository's own Criterion suite — every
figure is reproducible with one command.

## Results

| Operation | Latency | Throughput |
|---|---|---|
| `vault_creation` — Argon2id KDF + vault init | ~0.37 ms | ~2,700 vaults/s |
| `encrypt_1000_secrets` — AES-256-GCM re-encryption of 1,000 secrets | ~0.70 ms | ~1.4M secrets/s |
| `decrypt_1000_secrets` — decrypt + deserialize 1,000 secrets | ~0.85 ms | ~1.2M secrets/s |

Environment: Linux x86_64, Criterion 100 samples per benchmark, release
build (`--release` implied by `cargo bench`). KDF parameters in the bench
are the workspace defaults (`m_cost: 1024`, `t_cost: 1`, `p_cost: 1`) —
production KDF strength is configurable and deliberately heavier, since
Argon2id's memory cost is the brute-force defense. See
[CRYPTOGRAPHY.md](CRYPTOGRAPHY.md).

## Reproduce

```bash
cargo bench -p fastvault-crypto
```

The suite lives in
[`crates/fastvault-crypto/benches/vault_ops.rs`](../crates/fastvault-crypto/benches/vault_ops.rs).
All inputs and outputs are wrapped in `black_box()` so the numbers
reflect real crypto work, not dead-code elimination.
