//! `tinny` is a Rust library you can model your infrastructure with, which then
//! compiles into a dual-functioning command-line and web application with
//! basic bootstrapping abilities.
//!
//! When modelling your infrastructure you may need to store some secrets, without
//! comitting them to your Git repo. To help with this problem, `tinny` uses a JSON
//! file (named `can.json` by default) for storing passphrase-encrypted secrets
//! which you reference from your infrastructure model. To create and update a
//! can file, `tinny` provides a command-line tool named [`can`].
//!
//! [`can`]: ../can/index.html

mod opener;
mod types;
mod utils;

use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use clap::{ArgAction, Parser, Subcommand};
use inquire::{Password, PasswordDisplayMode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

pub use opener::CanOpener;
pub use types::SecretBytes;

/// The supported schema version of the tin can secret file.
pub const SCHEMA_VERSION: u32 = 1;
const LONG_ABOUT: &str = r#"
A tin can file stores encrypted secrets in JSON and addresses values with JSON pointers.
"#;
const SECRET_FROM_PIPE_DEFAULT_LENGTH: usize = 4 * 1024;

/// The main command-line interface arguments struct for `can`.
#[derive(Parser, Debug)]
#[command(name = "can", version, about, long_about = LONG_ABOUT, term_width = 80)]
pub struct Cli {
    /// Path to the tin can secret file.
    #[arg(short, long, value_name = "FILE", default_value = "can.json")]
    pub file: PathBuf,

    /// The subcommand/action to perform.
    #[command(subcommand)]
    pub action: Actions,
}

/// Subcommands / Actions supported by the `can` CLI tool.
#[derive(Subcommand, Debug)]
pub enum Actions {
    /// Creates a new secret at the specified JSON pointer path.
    #[command(aliases = ["c"])]
    Create {
        /// The JSON pointer locating where to create the secret.
        #[arg(value_name = "JSON_POINTER")]
        pointer: String,
        /// Maximum expected bytes to read from a standard input pipe.
        #[arg(short, long, default_value_t = SECRET_FROM_PIPE_DEFAULT_LENGTH)]
        length: usize,
        /// Generates a secure random secret instead of prompting or reading stdin.
        #[arg(short, long, action = ArgAction::SetTrue)]
        generate: bool,
    },
    /// Reads and decrypts a secret at the specified JSON pointer path.
    #[command(aliases = ["r"])]
    Read {
        /// The JSON pointer locating the secret to read.
        #[arg(value_name = "JSON_POINTER")]
        pointer: String,
    },
    /// Updates an existing secret at the specified JSON pointer path.
    #[command(aliases = ["u"])]
    Update {
        /// The JSON pointer locating the secret to update.
        #[arg(value_name = "JSON_POINTER")]
        pointer: String,
        /// Maximum expected bytes to read from a standard input pipe.
        #[arg(short, long, default_value_t = SECRET_FROM_PIPE_DEFAULT_LENGTH)]
        length: usize,
        /// Generates a secure random secret instead of prompting or reading stdin.
        #[arg(short, long, action = ArgAction::SetTrue)]
        generate: bool,
    },
    /// Deletes a secret or subtree at the specified JSON pointer path.
    #[command(aliases = ["d"])]
    Delete {
        /// The JSON pointer locating the secret to delete.
        #[arg(value_name = "JSON_POINTER")]
        pointer: String,
    },
    /// Lists all keys under the specified JSON pointer subtree.
    #[command(aliases = ["l"])]
    List {
        /// The JSON pointer locating the subtree to list (defaults to root).
        #[arg(
            value_name = "JSON_POINTER",
            default_value = "",
            default_missing_value = ""
        )]
        pointer: String,
    },
}

/// Represents the serialized disk/file structure of a tin can secret container.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CanFile {
    /// The schema version of the file structure.
    pub version: u32,
    /// The encryption key manager/deriver containing metadata and the derived key.
    pub key: CanOpener,
    /// The encrypted secrets organized in a JSON tree structure.
    pub secrets: Value,
}

/// Represents an active, open, and locked/unlocked tin can secret store database.
#[derive(Debug)]
pub struct Can {
    path: PathBuf,
    file: CanFile,
}

impl Can {
    /// Opens an existing tin can database file, or creates a new one in memory if it does not exist.
    ///
    /// Returns the active `Can` instance along with a boolean indicating if a new database
    /// was initialized (`true`) or if an existing one was loaded (`false`).
    ///
    /// # Errors
    /// Returns an error if the file exists but is malformed or has an unsupported version.
    pub fn open_or_create(path: PathBuf) -> Result<(Self, bool)> {
        match fs::read_to_string(path.as_path()) {
            Ok(content) => {
                let file: CanFile = serde_json::from_str(&content)
                    .with_context(|| format!("failed to parse can file: {}", path.display()))?;
                if file.version != SCHEMA_VERSION {
                    bail!(
                        "unsupported can file schema version: {} (expected {})",
                        file.version,
                        SCHEMA_VERSION
                    );
                }
                Ok((Self { path, file }, false))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok((
                Self {
                    path,
                    file: CanFile {
                        version: SCHEMA_VERSION,
                        key: CanOpener::new()?,
                        secrets: json!({}),
                    },
                },
                true,
            )),
            Err(e) => {
                Err(e).with_context(|| format!("failed to read can file: {}", path.display()))
            }
        }
    }

    /// Unlocks the database by deriving the key from the provided passphrase.
    ///
    /// # Errors
    /// Returns an error if key derivation fails or metadata is invalid.
    pub fn unlock(&mut self, passphrase: &SecretBytes) -> Result<()> {
        self.file.key.unlock(passphrase)
    }

    /// Locks the database, discarding and zeroizing the derived symmetric key.
    pub fn lock(&mut self) {
        self.file.key.lock();
    }

    /// Validates whether a secret can be created at the given JSON pointer path.
    ///
    /// # Errors
    /// Returns an error if the pointer targets the root, is invalid, or if a secret already exists there.
    pub fn validate_create(&self, pointer: &str) -> Result<()> {
        ensure_non_root_pointer(pointer)?;
        if self.file.secrets.pointer(pointer).is_some() {
            bail!("secret already exists: {pointer}");
        }
        Ok(())
    }

    /// Validates whether a secret exists and can be read at the given JSON pointer path.
    ///
    /// # Errors
    /// Returns an error if the pointer is invalid or the secret does not exist.
    pub fn validate_read(&self, pointer: &str) -> Result<()> {
        ensure_non_root_pointer(pointer)?;
        self.ciphertext_hex_at(pointer).map(|_| ())
    }

    /// Validates whether a secret exists and can be updated at the given JSON pointer path.
    ///
    /// # Errors
    /// Returns an error if the pointer is invalid or the secret does not exist.
    pub fn validate_update(&self, pointer: &str) -> Result<()> {
        ensure_non_root_pointer(pointer)?;
        if self.file.secrets.pointer(pointer).is_none() {
            bail!("pointer not found: {pointer}");
        }
        Ok(())
    }

    /// Encrypts and inserts a new secret at the specified JSON pointer path.
    ///
    /// # Errors
    /// Returns an error if the database is locked, validation fails, or encryption/insertion fails.
    pub fn create(&mut self, pointer: &str, secret: SecretBytes) -> Result<()> {
        self.validate_create(pointer)?;
        self.insert_secret(pointer, secret)
    }

    /// Reads and decrypts the secret stored at the specified JSON pointer path.
    ///
    /// # Errors
    /// Returns an error if the database is locked, validation fails, or decryption fails.
    pub fn read(&self, pointer: &str) -> Result<SecretBytes> {
        self.validate_read(pointer)?;
        let ciphertext_hex = self.ciphertext_hex_at(pointer)?;
        let bytes = hex_decode(&ciphertext_hex)?;
        self.file.key.unseal(&bytes)
    }

    /// Encrypts and updates an existing secret at the specified JSON pointer path.
    ///
    /// # Errors
    /// Returns an error if the database is locked, validation fails, or encryption/insertion fails.
    pub fn update(&mut self, pointer: &str, secret: SecretBytes) -> Result<()> {
        self.validate_update(pointer)?;
        self.insert_secret(pointer, secret)
    }

    /// Deletes a secret or subtree located at the specified JSON pointer path.
    ///
    /// # Errors
    /// Returns an error if the pointer is invalid, targets the root, or if no value is found there.
    pub fn delete(&mut self, pointer: &str) -> Result<()> {
        ensure_non_root_pointer(pointer)?;
        remove_value_at_pointer(&mut self.file.secrets, pointer)
    }

    /// Lists all secrets/subkeys under the specified JSON pointer path.
    ///
    /// If the pointer is empty, lists the entire database secrets tree.
    ///
    /// # Errors
    /// Returns an error if the pointer path is not found.
    pub fn list(&self, pointer: &str) -> Result<Value> {
        let value = if pointer.is_empty() {
            &self.file.secrets
        } else {
            self.file
                .secrets
                .pointer(pointer)
                .ok_or_else(|| anyhow!("pointer not found: {pointer}"))?
        };
        Ok(value.clone())
    }

    /// Atomically writes the serialized tin can database JSON to disk.
    ///
    /// Writes to a temporary file, flushes it to disk, and renames it over the original path.
    ///
    /// # Errors
    /// Returns an error if serialization, creation, writing, or atomical replacement fails.
    pub fn save_atomic(&self) -> Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        let serialized = serde_json::to_vec_pretty(&self.file)?;

        {
            let mut f = fs::File::create(&tmp)
                .with_context(|| format!("failed to create temp file: {}", tmp.display()))?;
            f.write_all(&serialized)
                .with_context(|| format!("failed to write temp file: {}", tmp.display()))?;
            f.sync_all()
                .with_context(|| format!("failed to sync temp file: {}", tmp.display()))?;
        }

        fs::rename(&tmp, &self.path).with_context(|| {
            format!(
                "failed to atomically replace {} with {}",
                self.path.display(),
                tmp.display()
            )
        })?;

        Ok(())
    }

    fn insert_secret(&mut self, pointer: &str, mut secret: SecretBytes) -> Result<()> {
        let ciphertext = self.file.key.seal(&mut secret)?;
        let value = Value::String(hex_encode(&ciphertext));
        upsert_value_at_pointer(&mut self.file.secrets, pointer, value)
    }

    fn ciphertext_hex_at(&self, pointer: &str) -> Result<String> {
        let value = self
            .file
            .secrets
            .pointer(pointer)
            .ok_or_else(|| anyhow!("pointer not found: {pointer}"))?
            .clone();
        serde_json::from_value(value)
            .map_err(|_| anyhow!("invalid secret record at pointer: {pointer}"))
    }
}

/// Reads a secret from either a random generator, an interactive prompt, or standard input pipe.
///
/// If `generate` is true, returns randomly generated bytes of the given `length`.
/// If stdin is a terminal, interactively prompts the user for the secret with confirmation.
/// Otherwise, reads the secret from the standard input pipe.
///
/// # Errors
/// Returns an error if the interactive prompt fails or reading from standard input fails.
pub fn read_secret(length: usize, generate: bool) -> Result<SecretBytes> {
    if generate {
        return utils::make_random(length);
    }

    if io::stdin().is_terminal() {
        let secret = prompt_secret(
            "Secret:",
            "Type the secret (twice). Use Ctrl+R to toggle visibility.",
            Some(("Re-enter secret:", "Values don't match")),
        )?;
        return Ok(SecretBytes::from(
            secret.expose_secret().as_bytes().to_vec(),
        ));
    }

    read_secret_from_pipe(length)
}

/// Interactively prompts the user for a passphrase (with optional confirmation) or reads it from stdin.
///
/// If stdin is a terminal, prompts the user. If `confirm` is true, asks the user to enter the passphrase twice.
/// If stdin is not a terminal, reads the passphrase directly from the pipe.
///
/// # Errors
/// Returns an error if prompt execution fails or standard input pipe reading fails.
pub fn prompt_passphrase(confirm: bool) -> Result<SecretBytes> {
    if !io::stdin().is_terminal() {
        let pass = read_passphrase_from_pipe()?;
        return Ok(SecretBytes::from(pass.into_bytes()));
    }

    let prompt = if confirm {
        (
            "Passphrase:",
            "Type a new passphrase (twice). Use Ctrl+R to toggle visibility.",
            Some(("Re-enter passphrase:", "Values don't match")),
        )
    } else {
        (
            "Passphrase:",
            "Type the passphrase. Use Ctrl+R to toggle visibility.",
            None,
        )
    };

    let pass = prompt_secret(prompt.0, prompt.1, prompt.2)?;
    Ok(SecretBytes::from(pass.expose_secret().as_bytes().to_vec()))
}

fn read_passphrase_from_pipe() -> Result<String> {
    let mut pass = String::new();
    let bytes = io::stdin().read_line(&mut pass)?;
    if bytes == 0 {
        bail!("missing passphrase on stdin");
    }
    while pass.ends_with('\n') || pass.ends_with('\r') {
        pass.pop();
    }
    if pass.is_empty() {
        bail!("empty passphrase on stdin");
    }
    Ok(pass)
}

fn prompt_secret(message: &str, help: &str, confirm: Option<(&str, &str)>) -> Result<SecretString> {
    let mut builder = Password::new(message)
        .with_help_message(help)
        .with_display_toggle_enabled()
        .with_display_mode(PasswordDisplayMode::Masked);

    if let Some((confirm_msg, confirm_err)) = confirm {
        builder = builder
            .with_custom_confirmation_message(confirm_msg)
            .with_custom_confirmation_error_message(confirm_err);
    }

    Ok(SecretString::from(builder.prompt()?))
}

fn read_secret_from_pipe(len: usize) -> Result<SecretBytes> {
    let mut buffer = Vec::with_capacity(len);
    let mut handle = io::stdin().take(len as u64);
    handle.read_to_end(&mut buffer)?;

    let mut overflow = [0u8; 1];
    if io::stdin().read_exact(&mut overflow).is_ok() {
        bail!("too much data written to pipe; expected at most {len} bytes");
    }

    Ok(SecretBytes::from(buffer))
}

fn ensure_non_root_pointer(pointer: &str) -> Result<()> {
    if pointer.is_empty() || pointer == "/" {
        bail!("pointer must not target the root");
    }
    if !pointer.starts_with('/') {
        bail!("invalid JSON pointer (must start with '/'): {pointer}");
    }
    Ok(())
}

fn decode_pointer_tokens(pointer: &str) -> Result<Vec<String>> {
    if pointer.is_empty() {
        return Ok(vec![]);
    }
    if !pointer.starts_with('/') {
        bail!("invalid JSON pointer (must start with '/'): {pointer}");
    }

    let tokens = pointer
        .split('/')
        .skip(1)
        .map(|t| t.replace("~1", "/").replace("~0", "~"))
        .collect::<Vec<_>>();

    if tokens.iter().any(|t| t.is_empty()) {
        bail!("invalid JSON pointer token in: {pointer}");
    }

    Ok(tokens)
}

fn upsert_value_at_pointer(root: &mut Value, pointer: &str, value: Value) -> Result<()> {
    let tokens = decode_pointer_tokens(pointer)?;
    let (leaf, parents) = tokens
        .split_last()
        .ok_or_else(|| anyhow!("pointer must not target root"))?;

    let mut current = root;
    for token in parents {
        if !current.is_object() {
            *current = Value::Object(Map::new());
        }

        let obj = current
            .as_object_mut()
            .ok_or_else(|| anyhow!("internal error: expected object"))?;
        current = obj
            .entry(token.clone())
            .or_insert_with(|| Value::Object(Map::new()));
    }

    if !current.is_object() {
        *current = Value::Object(Map::new());
    }

    let obj = current
        .as_object_mut()
        .ok_or_else(|| anyhow!("internal error: expected object"))?;
    obj.insert(leaf.to_string(), value);
    Ok(())
}

fn remove_value_at_pointer(root: &mut Value, pointer: &str) -> Result<()> {
    let tokens = decode_pointer_tokens(pointer)?;
    let (leaf, parents) = tokens
        .split_last()
        .ok_or_else(|| anyhow!("pointer must not target root"))?;

    let mut current = root;
    for token in parents {
        current = current
            .as_object_mut()
            .and_then(|o| o.get_mut(token))
            .ok_or_else(|| anyhow!("pointer not found: {pointer}"))?;
    }

    let removed = current
        .as_object_mut()
        .ok_or_else(|| anyhow!("pointer not found: {pointer}"))?
        .remove(leaf);

    if removed.is_none() {
        bail!("pointer not found: {pointer}");
    }

    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        bail!("hex string has odd length");
    }

    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_value(bytes[i])?;
        let lo = hex_value(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_value(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => bail!("invalid hex char"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("tin-can-{name}-{nanos}.json"))
    }

    #[test]
    fn crud_roundtrip() -> Result<()> {
        let path = temp_path("crud");
        let (mut can, _) = Can::open_or_create(path)?;

        let pass = SecretBytes::from(b"test-pass".to_vec());
        can.unlock(&pass)?;

        can.create("/service/db/password", SecretBytes::from(b"first".to_vec()))?;
        let got = can.read("/service/db/password")?;
        assert_eq!(got.expose_secret(), b"first");

        can.update(
            "/service/db/password",
            SecretBytes::from(b"second".to_vec()),
        )?;
        let got2 = can.read("/service/db/password")?;
        assert_eq!(got2.expose_secret(), b"second");

        let listed = can.list("/service/db")?;
        assert!(listed.get("password").is_some());

        can.delete("/service/db/password")?;
        assert!(can.read("/service/db/password").is_err());

        Ok(())
    }

    #[test]
    fn schema_and_save_load() -> Result<()> {
        let path = temp_path("save-load");
        let (mut can, is_new_file) = Can::open_or_create(path.clone())?;
        assert!(is_new_file);

        let pass = SecretBytes::from(b"test-pass".to_vec());
        can.unlock(&pass)?;
        can.create("/k", SecretBytes::from(b"v".to_vec()))?;
        can.save_atomic()?;
        let saved = fs::read_to_string(&path)?;
        assert!(saved.contains("\"meta\": \"$argon2id$"));
        assert!(!saved.contains("\"kdf\""));
        assert!(saved.contains("\"k\": \""));

        let (mut reopened, reopened_is_new_file) = Can::open_or_create(path)?;
        assert!(!reopened_is_new_file);
        reopened.unlock(&pass)?;
        let got = reopened.read("/k")?;
        assert_eq!(got.expose_secret(), b"v");
        Ok(())
    }

    #[test]
    fn rejects_legacy_key_meta_shape() -> Result<()> {
        let path = temp_path("legacy-key-meta");
        let legacy = json!({
            "version": SCHEMA_VERSION,
            "key": {
                "meta": {
                    "kdf": "argon2id",
                    "salt": "AAAAAAAAAAAAAAAAAAAAAA",
                    "m_cost": 19456,
                    "t_cost": 2,
                    "p_cost": 1,
                    "dk_len": 32
                }
            },
            "secrets": {}
        });
        fs::write(&path, serde_json::to_vec_pretty(&legacy)?)?;
        assert!(Can::open_or_create(path).is_err());
        Ok(())
    }

    #[test]
    fn rejects_legacy_secret_object_shape() -> Result<()> {
        let path = temp_path("legacy-secret-shape");
        let (mut can, _) = Can::open_or_create(path.clone())?;
        let pass = SecretBytes::from(b"test-pass".to_vec());
        can.unlock(&pass)?;
        can.create("/k", SecretBytes::from(b"v".to_vec()))?;
        can.save_atomic()?;

        let mut v: Value = serde_json::from_slice(&fs::read(&path)?)?;
        v["secrets"]["k"] = json!({
            "alg": "AES_256_GCM_SIV",
            "ciphertext_hex": "00"
        });
        fs::write(&path, serde_json::to_vec_pretty(&v)?)?;

        let (mut reopened, _) = Can::open_or_create(path)?;
        reopened.unlock(&pass)?;
        assert!(reopened.read("/k").is_err());
        Ok(())
    }

    #[test]
    fn rejects_malformed_pointer() -> Result<()> {
        let path = temp_path("bad-pointer");
        let (mut can, _) = Can::open_or_create(path)?;
        let pass = SecretBytes::from(b"test-pass".to_vec());
        can.unlock(&pass)?;
        assert!(can.create("bad", SecretBytes::from(b"v".to_vec())).is_err());
        Ok(())
    }
}
