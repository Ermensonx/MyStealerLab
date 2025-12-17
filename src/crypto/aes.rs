//! Additional AES implementations

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

use super::CryptoError;

#[allow(dead_code)]
pub fn encrypt_aes_gcm(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKey)?;
    
    let nonce = Nonce::from_slice(nonce);
    
    cipher.encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))
}

#[allow(dead_code)]
pub fn decrypt_aes_gcm(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKey)?;
    
    let nonce = Nonce::from_slice(nonce);
    
    cipher.decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

#[allow(dead_code)]
pub fn generate_random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
    key
}

#[allow(dead_code)]
pub fn generate_random_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = generate_random_key();
        let nonce = generate_random_nonce();
        let plaintext = b"Test message for encryption";
        
        let ciphertext = encrypt_aes_gcm(&key, &nonce, plaintext).unwrap();
        let decrypted = decrypt_aes_gcm(&key, &nonce, &ciphertext).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}

