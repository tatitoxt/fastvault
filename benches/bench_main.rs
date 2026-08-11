use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fastvault_core::secret::Secret;
use fastvault_crypto::{KdfParams, VersionedVault};

fn benchmark_vault_operations(c: &mut Criterion) {
    let params = KdfParams {
        m_cost: 1024,
        t_cost: 1,
        p_cost: 1,
        output_len: 32,
    };

    let pwd = "BenchMasterPassword123!";

    c.bench_function("vault_creation", |b| {
        b.iter(|| {
            VersionedVault::create_empty(black_box(pwd), params.clone()).unwrap();
        });
    });

    let (mut vault, dek) = VersionedVault::create_empty(pwd, params.clone()).unwrap();

    let mut secrets = Vec::new();
    for i in 0..1000 {
        secrets.push(Secret::new(
            format!("secret_{}", i),
            "bench",
            format!("val_{}", i),
        ));
    }

    c.bench_function("encrypt_1000_secrets", |b| {
        b.iter(|| {
            vault
                .update_secrets(black_box(&dek), black_box(&secrets))
                .unwrap();
        });
    });

    c.bench_function("decrypt_1000_secrets", |b| {
        b.iter(|| {
            vault.decrypt_secrets(black_box(&dek)).unwrap();
        });
    });
}

criterion_group!(benches, benchmark_vault_operations);
criterion_main!(benches);
