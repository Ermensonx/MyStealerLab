//! Exfiltração de dados (lab mode)

pub mod http;
pub mod local;

use thiserror::Error;

pub use local::LocalExfiltrator;

#[allow(unused_imports)]
pub use http::HttpExfiltrator;

/// Erros de exfiltração
#[derive(Error, Debug)]
pub enum ExfilError {
    #[error("connection failed: {0}")]
    #[allow(dead_code)]
    ConnectionFailed(String),
    
    #[error("send failed: {0}")]
    #[allow(dead_code)]
    SendFailed(String),
    
    #[error("io: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("http: {0}")]
    #[allow(dead_code)]
    HttpError(String),
}

#[allow(dead_code)]
pub trait Exfiltrator {
    /// Envia dados para destino
    fn send(&self, data: &[u8]) -> Result<(), ExfilError>;
    
    /// Verifica se destino está disponível
    fn check_connection(&self) -> bool;
    
    /// Nome do exfiltrator
    fn name(&self) -> &str;
}

