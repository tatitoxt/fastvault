# 05 - Benchmark Results & Performance
#fastvault #benchmarks #performance #criterion

Back link: [[00 - FastVault Index]]

Measured on Apple Silicon using `criterion` (`benches/bench_main.rs`):

| Operation | Benchmark Target | Execution Time |
| :--- | :--- | :--- |
| **KDF Derivation** | Argon2id ($m=64\text{MB}, t=3, p=4$) | `~45.2 ms` |
| **DEK Re-wrapping** | Single 32-byte DEK (`fastvault passwd`) | `~45.1 ms` |
| **Payload Encryption** | 1,000 Secrets | `~1.84 ms` |
| **Payload Decryption** | 1,000 Secrets | `~1.12 ms` |
| **Cached Agent Access** | Tokio Async Unix Socket IPC | `~0.32 ms` |

To run benchmarks locally:
```bash
cargo bench
```

Related Notes:
- [[01 - Architecture & Design]]
- [[06 - CLI & Agent Integration Guide]]
