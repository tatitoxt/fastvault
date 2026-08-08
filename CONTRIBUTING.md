# Contributing to FastVault

Thank you for your interest in contributing to FastVault!

## Development Guidelines

1. **Rust Code Formatting**: All code must pass `cargo fmt --check`.
2. **Clippy Lints**: All code must pass `cargo clippy --all-targets --all-features -- -D warnings`.
3. **Tests**: Add unit tests for core domain logic and integration tests for CLI workflows.
4. **Crypto Changes**: Any changes to `fastvault-crypto` or `fastvault-store` must include negative test cases and preserve backwards compatibility.

## Submitting Pull Requests
1. Fork the repository `tatitoxt/fastvault`.
2. Create a topic branch (`feat/amazing-feature` or `fix/issue-description`).
3. Ensure `cargo test` passes locally.
4. Submit a Pull Request targeting the `main` branch.
