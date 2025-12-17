//! Exfiltração Local
//!
//! Salva dados em arquivo local (para modo lab).

use std::path::PathBuf;
use chrono::Utc;

use super::{ExfilError, Exfiltrator};

/// Exfiltrador para arquivo local
pub struct LocalExfiltrator {
    /// Diretório de saída
    output_dir: PathBuf,
}

impl LocalExfiltrator {
    /// Cria novo exfiltrador local
    pub fn new(output_dir: &str) -> Self {
        Self {
            output_dir: PathBuf::from(output_dir),
        }
    }
    
    /// Salva dados criptografados em arquivo
    pub fn save(&self, data: &[u8]) -> Result<String, ExfilError> {
        // Criar diretório se não existir
        std::fs::create_dir_all(&self.output_dir)?;
        
        // Nome do arquivo com timestamp
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let filename = format!("collected_{}.bin", timestamp);
        let filepath = self.output_dir.join(&filename);
        
        // Salvar
        std::fs::write(&filepath, data)?;
        
        tracing::info!("Dados salvos em: {}", filepath.display());
        
        Ok(filepath.to_string_lossy().to_string())
    }
    
    #[allow(dead_code)]
    pub fn save_readable(&self, json_data: &str) -> Result<String, ExfilError> {
        std::fs::create_dir_all(&self.output_dir)?;
        
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let filename = format!("collected_{}.json", timestamp);
        let filepath = self.output_dir.join(&filename);
        
        std::fs::write(&filepath, json_data)?;
        
        Ok(filepath.to_string_lossy().to_string())
    }
}

impl Exfiltrator for LocalExfiltrator {
    fn send(&self, data: &[u8]) -> Result<(), ExfilError> {
        self.save(data)?;
        Ok(())
    }
    
    fn check_connection(&self) -> bool {
        // Local sempre disponível
        true
    }
    
    fn name(&self) -> &str {
        "local_file"
    }
}

