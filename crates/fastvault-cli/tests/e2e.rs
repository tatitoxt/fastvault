//! End-to-end tests driving the compiled `fastvault` binary against a
//! temporary vault. `FASTVAULT_PASSWORD` supplies the master password
//! non-interactively; `--vault-path` isolates each test.

use std::path::PathBuf;
use std::process::{Command, Output};

const PASSWORD: &str = "E2E-Master-Passw0rd!";

struct Vault {
    dir: tempfile::TempDir,
}

impl Vault {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join("vault.fv")
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with_password(args, PASSWORD)
    }

    fn run_with_password(&self, args: &[&str], password: &str) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fastvault"));
        cmd.arg("--vault-path")
            .arg(self.path())
            .args(args)
            .env("FASTVAULT_PASSWORD", password);
        cmd.output().unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "fastvault {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    fn fail(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            !out.status.success(),
            "fastvault {:?} unexpectedly succeeded: {}",
            args,
            String::from_utf8_lossy(&out.stdout)
        );
        String::from_utf8_lossy(&out.stderr).to_string()
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}

fn init(v: &Vault) {
    let out = v.ok(&["init", "--password", PASSWORD]);
    assert!(out.contains("Initialized"), "init output: {out}");
}

#[test]
fn vault_lifecycle_set_get_list_delete_restore() {
    let v = Vault::new();
    init(&v);

    v.ok(&["set", "prod/database", "s3cret-value"]);
    v.ok(&[
        "set",
        "prod/api-key",
        "key-abc-123",
        "-t",
        "cloud",
        "-t",
        "billing",
    ]);

    // get masks by default, reveals with -r
    let masked = v.ok(&["get", "prod/database"]);
    assert!(masked.contains("•••"), "expected masked value: {masked}");
    assert!(!masked.contains("s3cret-value"));
    let revealed = v.ok(&["get", "prod/database", "--reveal"]);
    assert_eq!(revealed.trim(), "s3cret-value");

    // list shows both secrets in the prod namespace
    let list = v.ok(&["list", "-n", "prod"]);
    assert!(
        list.contains("database") && list.contains("api-key"),
        "{list}"
    );
    let other = v.ok(&["list", "-n", "default"]);
    assert!(!other.contains("database"));

    // search by tag
    let hits = v.ok(&["search", "billing"]);
    assert!(hits.contains("api-key"), "{hits}");
    assert!(!hits.contains("database"));

    // soft delete hides it; restore brings it back
    v.ok(&["delete", "prod/database"]);
    v.fail(&["get", "prod/database", "--reveal"]);
    v.ok(&["restore", "prod/database"]);
    assert_eq!(
        v.ok(&["get", "prod/database", "--reveal"]).trim(),
        "s3cret-value"
    );

    // permanent delete is final
    v.ok(&["delete", "prod/database", "--permanent"]);
    v.fail(&["restore", "prod/database"]);
}

#[test]
fn set_updates_existing_secret_and_keeps_history() {
    let v = Vault::new();
    init(&v);
    v.ok(&["set", "app/token", "v1"]);
    v.ok(&["set", "app/token", "v2"]);
    assert_eq!(v.ok(&["get", "app/token", "--reveal"]).trim(), "v2");
    let hist = v.ok(&["history", "app/token"]);
    assert!(
        hist.contains("v1"),
        "history should list prior version: {hist}"
    );
}

#[test]
fn wrong_password_cannot_unlock() {
    let v = Vault::new();
    init(&v);
    v.ok(&["set", "k", "secret"]);
    let out = v.run_with_password(&["get", "k", "--reveal"], "not-the-password");
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("secret"));
}

#[test]
fn passwd_rotates_master_password() {
    let v = Vault::new();
    init(&v);
    v.ok(&["set", "svc/key", "value-1"]);
    v.ok(&[
        "passwd",
        "--old-password",
        PASSWORD,
        "--new-password",
        "New-Pass-999!",
    ]);
    // old password no longer opens the vault
    let out = v.run_with_password(&["get", "svc/key", "--reveal"], PASSWORD);
    assert!(!out.status.success());
    // new password does, and the secret survived re-wrapping
    let out = v.run_with_password(&["get", "svc/key", "--reveal"], "New-Pass-999!");
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "value-1");
}

#[test]
fn audit_records_and_verifies_chain() {
    let v = Vault::new();
    init(&v);
    v.ok(&["set", "a", "1"]);
    v.ok(&["set", "b", "2"]);
    let verify = v.ok(&["audit", "--verify"]);
    assert!(verify.contains("PASSED"), "{verify}");
    let log = v.ok(&["audit"]);
    assert!(log.contains("SecretUpdated"), "{log}");

    // tamper with the stored audit log -> verification fails
    let audit_path = v.file("audit.json");
    let raw = std::fs::read_to_string(&audit_path).unwrap();
    let tampered = raw.replacen("cli_user", "mallory", 1);
    assert_ne!(raw, tampered);
    std::fs::write(&audit_path, tampered).unwrap();
    v.fail(&["audit", "--verify"]);
}

#[test]
fn backup_create_inspect_restore() {
    let v = Vault::new();
    init(&v);
    v.ok(&["set", "keep/me", "backup-value"]);
    let backup = v.file("backup.fvbak");
    let backup_str = backup.to_str().unwrap();

    v.ok(&["backup", "create", backup_str]);
    assert!(backup.exists());
    let info = v.ok(&["backup", "inspect", backup_str]);
    assert!(!info.is_empty());

    // wipe the vault, restore from backup, secret is back
    let v2 = Vault::new();
    init(&v2);
    v2.fail(&["get", "keep/me", "--reveal"]);
    let restored = v.file("restored.fv");
    let out = Command::new(env!("CARGO_BIN_EXE_fastvault"))
        .arg("--vault-path")
        .arg(&restored)
        .args(["backup", "restore", backup_str])
        .env("FASTVAULT_PASSWORD", PASSWORD)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn generate_produces_requested_lengths() {
    let v = Vault::new();
    let pwd = v.ok(&["generate", "password", "-l", "32"]);
    assert_eq!(pwd.trim().len(), 32);
    let token = v.ok(&["generate", "token", "-l", "16"]);
    assert_eq!(token.trim().len(), 16);
    // two generations differ
    assert_ne!(
        pwd.trim(),
        v.ok(&["generate", "password", "-l", "32"]).trim()
    );
}

#[test]
fn run_injects_secrets_into_child_env() {
    let v = Vault::new();
    init(&v);
    v.ok(&["set", "ci/deploy_key", "deploy-secret-42"]);
    let out = v.ok(&[
        "run",
        "--env",
        "DEPLOY_KEY=ci/deploy_key",
        "--",
        "sh",
        "-c",
        "printf %s $DEPLOY_KEY",
    ]);
    assert_eq!(out.trim(), "deploy-secret-42");
    // unknown path fails before spawning
    v.fail(&["run", "--env", "X=nope/missing", "--", "sh", "-c", "true"]);
}

#[test]
fn template_render_substitutes_markers() {
    let v = Vault::new();
    init(&v);
    v.ok(&["set", "db/url", "postgres://example/db"]);
    let tpl = v.file("app.tmpl");
    std::fs::write(&tpl, "DATABASE_URL={{fastvault:db/url}}\n").unwrap();
    let rendered = v.ok(&["template", "render", tpl.to_str().unwrap()]);
    assert!(rendered.contains("postgres://example/db"), "{rendered}");
    assert!(!rendered.contains("{{fastvault:"));
}

#[test]
fn status_reports_vault_presence() {
    let v = Vault::new();
    let before = v.ok(&["status"]);
    assert!(before.contains("Vault Exists: false"), "{before}");
    init(&v);
    let after = v.ok(&["status"]);
    assert!(after.contains("Vault Exists: true"), "{after}");
}

#[test]
fn get_missing_secret_is_an_error_not_a_crash() {
    let v = Vault::new();
    init(&v);
    let err = v.fail(&["get", "ghost/path", "--reveal"]);
    assert!(!err.is_empty());
}
