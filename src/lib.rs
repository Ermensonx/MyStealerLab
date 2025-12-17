//! MyStealer CTF Lab Library
//!
//! Biblioteca principal contendo todos os módulos do infostealer educacional.

pub mod config;
pub mod collectors;
pub mod crypto;
pub mod exfil;
pub mod utils;

// Re-exports para facilitar uso
pub use config::Config;
pub use collectors::{Collector, CollectorManager, CollectedData};
pub use crypto::CryptoManager;
pub use exfil::{Exfiltrator, LocalExfiltrator};

