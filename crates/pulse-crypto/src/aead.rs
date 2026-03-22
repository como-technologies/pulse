use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};

#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    #[error("encryption failed")]
    Encryption,
    #[error("decryption failed")]
    Decryption,
    #[error("invalid key length (expected 32 bytes)")]
    InvalidKeyLength,
}

/// Encrypt plaintext using AES-256-GCM with a random nonce.
/// Returns nonce (12 bytes) prepended to ciphertext.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, AeadError> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| AeadError::Encryption)?;

    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt ciphertext produced by [`encrypt`].
/// Expects nonce (12 bytes) prepended to ciphertext.
pub fn decrypt(key: &[u8; 32], nonce_and_ciphertext: &[u8]) -> Result<Vec<u8>, AeadError> {
    if nonce_and_ciphertext.len() < 12 {
        return Err(AeadError::Decryption);
    }
    let (nonce_bytes, ciphertext) = nonce_and_ciphertext.split_at(12);
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| AeadError::Decryption)
}

/// Generate a random 256-bit encryption key.
pub fn generate_key() -> [u8; 32] {
    rand::random()
}

/// Wrap (encrypt) a 32-byte DEK under a wrapping key.
pub fn wrap_key(wrapping_key: &[u8; 32], dek: &[u8; 32]) -> Result<Vec<u8>, AeadError> {
    encrypt(wrapping_key, dek)
}

/// Unwrap (decrypt) a wrapped DEK, enforcing the 32-byte size constraint.
pub fn unwrap_key(wrapping_key: &[u8; 32], wrapped: &[u8]) -> Result<[u8; 32], AeadError> {
    let plaintext = decrypt(wrapping_key, wrapped)?;
    plaintext
        .try_into()
        .map_err(|_| AeadError::InvalidKeyLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = generate_key();
        let plaintext = b"anonymous response data";
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key1 = generate_key();
        let key2 = generate_key();
        let encrypted = encrypt(&key1, b"secret").unwrap();
        let result = decrypt(&key2, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = generate_key();
        let mut encrypted = encrypt(&key, b"secret").unwrap();
        // Flip a byte in the ciphertext (after the 12-byte nonce)
        if let Some(byte) = encrypted.get_mut(15) {
            *byte ^= 0xFF;
        }
        let result = decrypt(&key, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn wrap_unwrap_key_round_trip() {
        let wrapping_key = generate_key();
        let dek = generate_key();
        let wrapped = wrap_key(&wrapping_key, &dek).unwrap();
        let unwrapped = unwrap_key(&wrapping_key, &wrapped).unwrap();
        assert_eq!(unwrapped, dek);
    }

    #[test]
    fn wrap_key_wrong_wrapping_key_fails() {
        let wrapping_key1 = generate_key();
        let wrapping_key2 = generate_key();
        let dek = generate_key();
        let wrapped = wrap_key(&wrapping_key1, &dek).unwrap();
        assert!(unwrap_key(&wrapping_key2, &wrapped).is_err());
    }

    #[test]
    fn different_encryptions_produce_different_ciphertext() {
        let key = generate_key();
        let plaintext = b"same message";
        let enc1 = encrypt(&key, plaintext).unwrap();
        let enc2 = encrypt(&key, plaintext).unwrap();
        // Different random nonces → different ciphertext
        assert_ne!(enc1, enc2);
        // But both decrypt to the same plaintext
        assert_eq!(decrypt(&key, &enc1).unwrap(), plaintext);
        assert_eq!(decrypt(&key, &enc2).unwrap(), plaintext);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn encrypt_decrypt_roundtrip_any_data(
            plaintext in prop::collection::vec(any::<u8>(), 0..1024)
        ) {
            let key = generate_key();
            let encrypted = encrypt(&key, &plaintext).unwrap();
            let decrypted = decrypt(&key, &encrypted).unwrap();
            prop_assert_eq!(decrypted, plaintext);
        }
    }
}
