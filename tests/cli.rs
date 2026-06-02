use assert_cmd::Command;
use assert_fs::TempDir;
use assert_fs::fixture::PathChild;
use predicates::prelude::*;
use secrecy::ExposeSecret;
use serde_json::Value;
use tinny::{Can, SecretBytes};

fn setup_can_with_secret(temp: &TempDir, pointer: &str, secret: &[u8], pass: &[u8]) {
    let can_path = temp.child("can.json");
    let (mut can, _) = Can::open_or_create(can_path.path().to_path_buf()).expect("open can");
    can.unlock(&SecretBytes::from(pass.to_vec()))
        .expect("unlock");
    can.create(pointer, SecretBytes::from(secret.to_vec()))
        .expect("create secret");
    can.save_atomic().expect("save can");
}

#[test]
fn create_without_tty_uses_single_passphrase_line() {
    let temp = TempDir::new().expect("tempdir");

    Command::cargo_bin("can")
        .expect("bin")
        .args([
            "--file",
            temp.child("can.json").path().to_str().expect("path"),
            "create",
            "/k",
            "--generate",
            "--length",
            "6",
        ])
        .write_stdin("pass-123\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("created /k"));

    let raw = std::fs::read_to_string(temp.child("can.json").path()).expect("read can file");
    let v: Value = serde_json::from_str(&raw).expect("parse can file");
    assert!(
        v["key"]["meta"]
            .as_str()
            .expect("meta string")
            .starts_with("$argon2id$")
    );
    assert!(!v["secrets"]["k"].as_str().expect("ciphertext").is_empty());

    temp.close().expect("close tempdir");
}

#[test]
fn create_existing_secret_fails_before_reading_stdin() {
    let temp = TempDir::new().expect("tempdir");
    setup_can_with_secret(&temp, "/k", b"first", b"pass-123");

    Command::cargo_bin("can")
        .expect("bin")
        .args([
            "--file",
            temp.child("can.json").path().to_str().expect("path"),
            "create",
            "/k",
        ])
        .write_stdin("")
        .assert()
        .failure()
        .stderr(predicate::str::contains("secret already exists: /k"))
        .stderr(predicate::str::contains("missing passphrase").not());

    temp.close().expect("close tempdir");
}

#[test]
fn read_without_tty_uses_single_passphrase_line() {
    let temp = TempDir::new().expect("tempdir");
    setup_can_with_secret(&temp, "/k", b"first", b"pass-123");

    Command::cargo_bin("can")
        .expect("bin")
        .args([
            "--file",
            temp.child("can.json").path().to_str().expect("path"),
            "read",
            "/k",
        ])
        .write_stdin("pass-123\n")
        .assert()
        .success()
        .stdout("first\n");

    temp.close().expect("close tempdir");
}

#[test]
fn read_missing_secret_fails_before_reading_stdin() {
    let temp = TempDir::new().expect("tempdir");
    setup_can_with_secret(&temp, "/k", b"first", b"pass-123");

    Command::cargo_bin("can")
        .expect("bin")
        .args([
            "--file",
            temp.child("can.json").path().to_str().expect("path"),
            "read",
            "/missing",
        ])
        .write_stdin("")
        .assert()
        .failure()
        .stderr(predicate::str::contains("pointer not found: /missing"))
        .stderr(predicate::str::contains("missing passphrase").not());

    temp.close().expect("close tempdir");
}

#[test]
fn update_without_tty_uses_single_passphrase_line() {
    let temp = TempDir::new().expect("tempdir");
    setup_can_with_secret(&temp, "/k", b"first", b"pass-123");

    Command::cargo_bin("can")
        .expect("bin")
        .args([
            "--file",
            temp.child("can.json").path().to_str().expect("path"),
            "update",
            "/k",
        ])
        .write_stdin("pass-123\nsecond")
        .assert()
        .success()
        .stdout(predicate::str::contains("updated /k"));

    let (mut can, _) =
        Can::open_or_create(temp.child("can.json").path().to_path_buf()).expect("open can");
    can.unlock(&SecretBytes::from(b"pass-123".to_vec()))
        .expect("unlock");
    let got = can.read("/k").expect("read secret");
    assert_eq!(got.expose_secret(), b"second");

    temp.close().expect("close tempdir");
}

#[test]
fn update_missing_secret_fails_before_reading_stdin() {
    let temp = TempDir::new().expect("tempdir");
    setup_can_with_secret(&temp, "/k", b"first", b"pass-123");

    Command::cargo_bin("can")
        .expect("bin")
        .args([
            "--file",
            temp.child("can.json").path().to_str().expect("path"),
            "update",
            "/missing",
        ])
        .write_stdin("")
        .assert()
        .failure()
        .stderr(predicate::str::contains("pointer not found: /missing"))
        .stderr(predicate::str::contains("missing passphrase").not());

    temp.close().expect("close tempdir");
}

#[test]
fn list_outputs_json_tree_without_passphrase_prompt() {
    let temp = TempDir::new().expect("tempdir");
    setup_can_with_secret(&temp, "/svc/db/password", b"alpha", b"pass-123");
    setup_can_with_secret(&temp, "/svc/api/token", b"beta", b"pass-123");

    Command::cargo_bin("can")
        .expect("bin")
        .args([
            "--file",
            temp.child("can.json").path().to_str().expect("path"),
            "list",
            "/svc",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"db\""))
        .stdout(predicate::str::contains("\"api\""));

    temp.close().expect("close tempdir");
}

#[test]
fn delete_removes_secret_without_passphrase_prompt() {
    let temp = TempDir::new().expect("tempdir");
    setup_can_with_secret(&temp, "/k", b"first", b"pass-123");

    Command::cargo_bin("can")
        .expect("bin")
        .args([
            "--file",
            temp.child("can.json").path().to_str().expect("path"),
            "delete",
            "/k",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("deleted /k"));

    let (mut can, _) =
        Can::open_or_create(temp.child("can.json").path().to_path_buf()).expect("open can");
    can.unlock(&SecretBytes::from(b"pass-123".to_vec()))
        .expect("unlock");
    assert!(can.read("/k").is_err());

    temp.close().expect("close tempdir");
}

#[test]
fn list_missing_pointer_fails() {
    let temp = TempDir::new().expect("tempdir");
    setup_can_with_secret(&temp, "/k", b"first", b"pass-123");

    Command::cargo_bin("can")
        .expect("bin")
        .args([
            "--file",
            temp.child("can.json").path().to_str().expect("path"),
            "list",
            "/does-not-exist",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("pointer not found"));

    temp.close().expect("close tempdir");
}
