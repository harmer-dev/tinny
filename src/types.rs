use secrecy::SecretBox;

/// A wrapper type for securely holding secret byte arrays in memory.
///
/// Uses `secrecy::SecretBox` to zeroize the underlying memory upon drop
/// and prevent accidental exposure in debug formatting or logging.
pub type SecretBytes = SecretBox<[u8]>;
