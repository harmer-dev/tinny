use anyhow::{Result, anyhow};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

// 1. Although a salt MAY be be all zeroes, it's far more likely to be a
//    programming error. If it ever happened, just rerun the tests.
//
// 2. And here we want to just sanity check that a non-zero value is different
//    each time.
//
// Beyond these two tests, we can't really do much. Proving something is truly
// random isn't simple or cheap. And even if it was, we would only be proving it
// for this particular implementation of the underlying system. So these tests
// just sanity check the make_salt function.

use crate::types::SecretBytes;

pub(crate) fn make_random(len: usize) -> Result<SecretBytes> {
    let mut buffer = vec![0u8; len];
    SystemRandom::new().fill(&mut buffer)?;
    let secret: SecretBytes = SecretBytes::from(buffer);
    Ok(secret)
}

#[cfg(test)]
mod make_random_tests {

    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn doesnt_produce_null_bytes() -> Result<()> {
        let secret = make_random(16)?;
        let sixteen_nulls = [0u8; 16];
        assert_ne!(secret.expose_secret(), sixteen_nulls.as_slice());
        Ok(())
    }

    #[test]
    fn is_producing_different_values() -> Result<()> {
        let secret1 = make_random(16)?;
        let secret2 = make_random(16)?;
        assert_ne!(secret1.expose_secret(), secret2.expose_secret());
        Ok(())
    }
}

pub(crate) fn make_salt() -> Result<password_hash::SaltString> {
    let mut raw_bytes = [0u8; 16];
    let rng = SystemRandom::new();
    rng.fill(&mut raw_bytes)
        .map_err(|e| anyhow!("Hardware RNG failure: {}", e))?;
    let salt = password_hash::SaltString::encode_b64(&raw_bytes)
        .map_err(|e| anyhow!("Salt encoding failed: {}", e))?;
    Ok(salt)
}

#[cfg(test)]
mod make_salt_tests {

    use super::*;

    #[test]
    fn doesnt_use_null_bytes() -> anyhow::Result<()> {
        let sixteen_zeroes_encoded_as_base64 = "AAAAAAAAAAAAAAAAAAAAAA==";
        let salt = make_salt()?;
        assert_ne!(salt.as_str(), sixteen_zeroes_encoded_as_base64);
        Ok(())
    }

    #[test]
    fn is_producing_different_values() -> anyhow::Result<()> {
        let salt1 = make_salt()?;
        let salt2 = make_salt()?;
        assert_ne!(salt1, salt2);
        Ok(())
    }
}
