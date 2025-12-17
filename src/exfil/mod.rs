//! Módulo de Exfiltração
//!
//! Contém implementações de exfiltração de dados (simulada para lab).

pub mod http;
pub mod local;

use thiserror::Error;

// Re-exports
pub use local::LocalExfiltrator;
pub use http::HttpExfiltrator;

/// Erros de exfiltração
#[derive(Error, Debug)]
pub enum ExfilError {
    #[error("Falha na conexão: {0}")]
    ConnectionFailed(String),
    
    #[error("Falha no envio: {0}")]
    SendFailed(String),
    
    #[error("Erro de IO: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Erro HTTP: {0}")]
    HttpError(String),
}

/// Trait para exfiltração de dados
pub trait Exfiltrator {
    /// Envia dados para destino
    fn send(&self, data: &[u8]) -> Result<(), ExfilError>;
    
    /// Verifica se destino está disponível
    fn check_connection(&self) -> bool;
    
    /// Nome do exfiltrator
    fn name(&self) -> &str;
}

