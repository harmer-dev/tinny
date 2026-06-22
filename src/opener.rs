use anyhow::{Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use aws_lc_rs::aead::{AES_256_GCM_SIV, Aad, MAX_TAG_LEN, NONCE_LEN, Nonce, RandomizedNonceKey};
use password_hash::PasswordHash;
use secrecy::{ExposeSecret, ExposeSecretMut};
use serde::{Deserialize, Serialize};

use crate::types::SecretBytes;
use crate::utils::make_salt;

/// Handles key derivation, encryption/decryption (sealing/unsealing), and key lifecycle.
///
/// `CanOpener` uses Argon2id for KDF (Key Derivation Function) and AES-256-GCM-SIV
/// for authenticated symmetric encryption.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CanOpener {
    /// The Argon2id KDF parameter and salt metadata encoded in PHC format.
    pub meta: String,
    /// The derived symmetric key, wrapped in a secure container.
    /// It is cleared/zeroized when `CanOpener` is locked or dropped.
    #[serde(skip)]
    pub key: Option<SecretBytes>,
}

impl CanOpener {
    /// Creates a new `CanOpener` with a fresh, randomly generated KDF salt.
    ///
    /// The default Argon2id parameters (m_cost, t_cost, p_cost) are utilized.
    pub fn new() -> Result<Self> {
        let salt = make_salt()?;
        let phc = format!(
            "$argon2id$v=19$m={},t={},p={}${}",
            Params::DEFAULT_M_COST,
            Params::DEFAULT_T_COST,
            Params::DEFAULT_P_COST,
            salt.as_str()
        );
        Ok(Self {
            meta: phc,
            key: None,
        })
    }

    /// Derives the encryption key from the given passphrase and stored metadata salt.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The metadata PHC format is invalid or unsupported.
    /// - Key derivation fails.
    pub fn unlock(&mut self, passphrase: &SecretBytes) -> Result<()> {
        let parsed = PasswordHash::new(&self.meta)
            .map_err(|e| anyhow!("invalid key metadata PHC string: {e}"))?;
        if parsed.algorithm.as_str() != "argon2id" {
            bail!("unsupported kdf: {}", parsed.algorithm);
        }
        if parsed.hash.is_some() {
            bail!("invalid key metadata PHC string: hash output must be omitted");
        }
        let salt_phc = parsed
            .salt
            .ok_or_else(|| anyhow!("invalid key metadata PHC string: missing salt"))?;

        let m_cost = parsed
            .params
            .get_decimal("m")
            .ok_or_else(|| anyhow!("invalid key metadata PHC string: missing m param"))?;
        let t_cost = parsed
            .params
            .get_decimal("t")
            .ok_or_else(|| anyhow!("invalid key metadata PHC string: missing t param"))?;
        let p_cost = parsed
            .params
            .get_decimal("p")
            .ok_or_else(|| anyhow!("invalid key metadata PHC string: missing p param"))?;

        const DK_LEN: usize = 32;
        let params = Params::new(m_cost, t_cost, p_cost, Some(DK_LEN))
            .map_err(|e| anyhow!("invalid argon2 params: {e}"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut salt_buf = [0u8; 64];
        let salt = salt_phc
            .decode_b64(&mut salt_buf)
            .map_err(|e| anyhow!("invalid salt encoding: {e}"))?;
        let mut key = SecretBytes::from(vec![0u8; DK_LEN]);
        argon2
            .hash_password_into(
                passphrase.expose_secret(),
                salt.as_ref(),
                key.expose_secret_mut(),
            )
            .map_err(|e| anyhow!("failed to derive key: {e}"))?;

        self.key = Some(key);
        Ok(())
    }

    /// Locks the opener by discarding and zeroizing the derived symmetric key.
    pub fn lock(&mut self) {
        self.key = None;
    }

    /// Encrypts (seals) a secret using AES-256-GCM-SIV with the derived key.
    ///
    /// Generates a randomized nonce, encrypts the plaintext in-place, and appends the auth tag.
    ///
    /// # Errors
    /// Returns an error if the `CanOpener` is currently locked or if encryption fails.
    pub fn seal(&self, secret: &mut SecretBytes) -> Result<Vec<u8>> {
        let key_material = self
            .key
            .as_ref()
            .ok_or_else(|| anyhow!("can is locked; unlock before write"))?;

        let key = RandomizedNonceKey::new(&AES_256_GCM_SIV, key_material.expose_secret())
            .map_err(|_| anyhow!("failed to initialize encryption key"))?;

        let plaintext = secret.expose_secret_mut();
        let (nonce, tag) = key
            .seal_in_place_separate_tag(Aad::empty(), plaintext)
            .map_err(|_| anyhow!("encryption failed"))?;

        let mut ciphertext = Vec::with_capacity(NONCE_LEN + plaintext.len() + MAX_TAG_LEN);
        ciphertext.extend_from_slice(nonce.as_ref());
        ciphertext.extend_from_slice(plaintext);
        ciphertext.extend_from_slice(tag.as_ref());
        Ok(ciphertext)
    }

    /// Decrypts (unseals) a ciphertext using AES-256-GCM-SIV with the derived key.
    ///
    /// Reconstitutes the nonce and authentication tag, performs decryption, and validates integrity.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The `CanOpener` is currently locked.
    /// - The ciphertext length is too short to be valid.
    /// - Decryption or integrity verification fails (e.g. wrong passphrase or tampered data).
    pub fn unseal(&self, ciphertext: &[u8]) -> Result<SecretBytes> {
        let key_material = self
            .key
            .as_ref()
            .ok_or_else(|| anyhow!("can is locked; unlock before read"))?;

        if ciphertext.len() < NONCE_LEN + MAX_TAG_LEN {
            bail!("ciphertext is too short");
        }

        let nonce_bytes: [u8; NONCE_LEN] = ciphertext[..NONCE_LEN]
            .try_into()
            .map_err(|_| anyhow!("invalid nonce"))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = ciphertext[NONCE_LEN..].to_vec();
        let key = RandomizedNonceKey::new(&AES_256_GCM_SIV, key_material.expose_secret())
            .map_err(|_| anyhow!("failed to initialize decryption key"))?;

        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| anyhow!("decryption failed (wrong passphrase or tampered data)"))?;

        Ok(SecretBytes::from(plaintext.to_vec()))
    }
}

impl Drop for CanOpener {
    fn drop(&mut self) {
        self.lock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlock_lock_roundtrip() -> Result<()> {
        let mut opener = CanOpener::new()?;
        let passphrase = SecretBytes::from(b"test-passphrase".to_vec());
        opener.unlock(&passphrase)?;
        assert!(opener.key.is_some());
        opener.lock();
        assert!(opener.key.is_none());
        Ok(())
    }

    #[test]
    fn seal_unseal_roundtrip() -> Result<()> {
        let mut opener = CanOpener::new()?;
        let passphrase = SecretBytes::from(b"test-passphrase".to_vec());
        opener.unlock(&passphrase)?;

        let plaintext = b"my secret".to_vec();
        let mut secret = SecretBytes::from(plaintext.clone());
        let ciphertext = opener.seal(&mut secret)?;
        let unsealed = opener.unseal(&ciphertext)?;

        assert_eq!(unsealed.expose_secret(), plaintext.as_slice());
        Ok(())
    }

    #[test]
    fn unseal_fails_with_wrong_passphrase() -> Result<()> {
        let mut opener1 = CanOpener::new()?;
        let pass1 = SecretBytes::from(b"pass-1".to_vec());
        opener1.unlock(&pass1)?;

        let mut secret = SecretBytes::from(b"abc".to_vec());
        let ciphertext = opener1.seal(&mut secret)?;

        let mut opener2 = opener1.clone();
        opener2.lock();
        let pass2 = SecretBytes::from(b"pass-2".to_vec());
        opener2.unlock(&pass2)?;

        assert!(opener2.unseal(&ciphertext).is_err());
        Ok(())
    }

    #[test]
    fn default_meta_is_parseable_phc_without_hash() -> Result<()> {
        let opener = CanOpener::new()?;
        let parsed =
            PasswordHash::new(&opener.meta).map_err(|e| anyhow!("failed to parse meta: {e}"))?;
        assert_eq!(parsed.algorithm.as_str(), "argon2id");
        assert!(parsed.salt.is_some());
        assert!(parsed.hash.is_none());
        Ok(())
    }

    #[test]
    fn unlock_fails_with_malformed_phc() -> Result<()> {
        let mut opener = CanOpener::new()?;
        opener.meta = "not-phc".to_string();
        let pass = SecretBytes::from(b"test-passphrase".to_vec());
        assert!(opener.unlock(&pass).is_err());
        Ok(())
    }
}
