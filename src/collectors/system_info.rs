//! Coletor de Informações do Sistema

use serde::{Deserialize, Serialize};
use sysinfo::System;

#[cfg(unix)]
use nix::unistd::geteuid;

use super::{Collector, CollectorError, ModuleData};

/// Dados do sistema coletados
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemData {
    /// Nome do host
    pub hostname: String,
    
    /// Nome do usuário
    pub username: String,
    
    /// Nome do SO
    pub os_name: String,
    
    /// Versão do SO
    pub os_version: String,
    
    /// Arquitetura
    pub arch: String,
    
    /// Modelo da CPU
    pub cpu_model: String,
    
    /// Número de cores
    pub cpu_cores: u32,
    
    /// RAM total em bytes
    pub ram_total: u64,
    
    /// RAM disponível em bytes
    pub ram_available: u64,
    
    /// Se usuário é admin
    pub is_admin: bool,
    
    /// Uptime em segundos
    pub uptime_seconds: u64,
    
    /// Processos em execução (nomes)
    pub running_processes: Vec<String>,
}

/// Coletor de informações do sistema
pub struct SystemInfoCollector;

impl SystemInfoCollector {
    pub fn new() -> Self {
        Self
    }
    
    fn collect_system_data(&self) -> Result<SystemData, CollectorError> {
        let mut sys = System::new_all();
        sys.refresh_all();
        
        // Coletar processos
        let processes: Vec<String> = sys.processes()
            .values()
            .map(|p| p.name().to_string())
            .take(100) // Limitar pra nao ficar gigante
            .collect();
        
        // Informação da CPU
        let cpu_model = sys.cpus()
            .first()
            .map(|c| c.brand().to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        
        Ok(SystemData {
            hostname: System::host_name().unwrap_or_else(|| "unknown".to_string()),
            username: whoami::username(),
            os_name: System::name().unwrap_or_else(|| "unknown".to_string()),
            os_version: System::os_version().unwrap_or_else(|| "unknown".to_string()),
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
        // Verificar se é admin no Windows
        std::process::Command::new("net")
            .args(["session"])
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
        "system"
    }
    
    fn collect(&self) -> Result<ModuleData, CollectorError> {
        let data = self.collect_system_data()?;
        Ok(ModuleData::System(data))
    }
    
    fn is_supported(&self) -> bool {
        true
    }
    
    fn priority(&self) -> u8 {
        100 // Alta prioridade
    }
}

