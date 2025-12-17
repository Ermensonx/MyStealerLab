//! Anti-Debug & Anti-Disassembly Techniques
//!
//! Técnicas avançadas para dificultar análise e engenharia reversa.
//! ⚠️ EDUCATIONAL PURPOSES ONLY - CTF IR Training
//!
//! Técnicas implementadas:
//! - Anti-debugging (múltiplos métodos)
//! - Anti-disassembly (opaque predicates, junk code)
//! - Timing attacks
//! - Exception-based detection

#![allow(dead_code)]

use std::time::{Duration, Instant};
use std::hint::black_box;

// ============================================================================
// ANTI-DEBUGGING
// ============================================================================

/// Verifica se há debugger usando múltiplos métodos
pub fn is_debugger_attached() -> bool {
    let mut detected = false;
    
    // Método 1: Timing check
    detected |= timing_check();
    
    // Método 2: Sistema específico
    #[cfg(windows)]
    {
        detected |= windows_debug_checks();
    }
    
    #[cfg(unix)]
    {
        detected |= unix_debug_checks();
    }
    
    // Método 3: Exception handling
    detected |= exception_check();
    
    detected
}

/// Timing check - debuggers causam delays
fn timing_check() -> bool {
    let start = Instant::now();
    
    // Operação que deveria ser muito rápida
    let mut x = 0u64;
    for i in 0..1000 {
        x = x.wrapping_add(i);
        x = x.wrapping_mul(0x5851F42D4C957F2D);
        x = x.rotate_left(17);
    }
    black_box(x);
    
    let elapsed = start.elapsed();
    
    // Se demorou mais de 50ms, provavelmente está sendo debugado
    elapsed > Duration::from_millis(50)
}

/// Verificações específicas do Windows
#[cfg(windows)]
fn windows_debug_checks() -> bool {
    use std::process::Command;
    
    let mut detected = false;
    
    // IsDebuggerPresent via PowerShell
    if let Ok(output) = Command::new("powershell")
        .args(["-NoProfile", "-Command", "[System.Diagnostics.Debugger]::IsAttached"])
        .output()
    {
        let result = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
        if result == "true" {
            detected = true;
        }
    }
    
    // NtGlobalFlag check (PEB offset 0x68/0xBC)
    // Em processo debugado, NtGlobalFlag contém flags específicas
    
    // Heap flags check
    // Heaps criados por debugger têm flags diferentes
    
    detected
}

#[cfg(not(windows))]
fn windows_debug_checks() -> bool {
    false
}

/// Verificações específicas do Unix
#[cfg(unix)]
fn unix_debug_checks() -> bool {
    // Verifica TracerPid em /proc/self/status
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(pid) = line.strip_prefix("TracerPid:") {
                let pid = pid.trim();
                if pid != "0" {
                    return true;
                }
            }
        }
    }
    
    // Verifica ptrace
    // Se já está sendo traceado, ptrace falha
    
    false
}

#[cfg(not(unix))]
fn unix_debug_checks() -> bool {
    false
}

/// Detection via exception handling
fn exception_check() -> bool {
    // Usa panic catch para detectar ambiente anormal
    let result = std::panic::catch_unwind(|| {
        // Operação que pode causar exceção em debugger
        let x: u64 = 0xDEADBEEF;
        black_box(x.wrapping_mul(x));
    });
    
    result.is_err()
}

// ============================================================================
// ANTI-DISASSEMBLY
// ============================================================================

/// Opaque predicate - sempre retorna true mas parece dinâmico
#[inline(never)]
#[allow(unused_comparisons)]
pub fn opaque_true() -> bool {
    let x = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(1);
    
    // Matematicamente sempre true, mas disassembler não sabe
    (x * x) >= 0 || x < 0
}

/// Opaque predicate - sempre retorna false mas parece dinâmico
#[inline(never)]
pub fn opaque_false() -> bool {
    let x = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(1);
    
    // Matematicamente sempre false para qualquer x real
    x * x < 0
}

/// Junk code generator - confunde análise estática
#[inline(never)]
pub fn junk_code_block() {
    let mut arr = [0u8; 64];
    
    // Operações inúteis mas que parecem importantes
    for i in 0..64 {
        arr[i] = (i as u8).wrapping_mul(0x41);
        arr[i] = arr[i].rotate_left(3);
        arr[i] ^= 0x55;
    }
    
    // Mais confusão
    let mut sum = 0u64;
    for &b in &arr {
        sum = sum.wrapping_add(b as u64);
        sum = sum.wrapping_mul(0x100000001B3);
        if opaque_false() {
            sum = 0; // Nunca executa
        }
    }
    
    // Hash inútil
    let hash = sum.wrapping_mul(0x517CC1B727220A95);
    
    black_box(arr);
    black_box(hash);
    
    // Conditional que nunca é true
    if opaque_false() {
        panic!("This never happens");
    }
}

/// Dead code block - código que nunca executa
#[inline(never)]
fn dead_code() {
    // Este código nunca é chamado, mas está no binário
    let secret = [0x41, 0x42, 0x43, 0x44];
    let mut result = 0u32;
    for &b in &secret {
        result = result.wrapping_add(b as u32);
    }
    println!("Dead code result: {}", result);
}

/// Anti-pattern: chamada indireta via function pointer
#[inline(never)]
pub fn indirect_call<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    // Adiciona indireção para confundir análise
    junk_code_block();
    
    let result = f();
    
    if opaque_false() {
        dead_code();
    }
    
    result
}

// ============================================================================
// API OBFUSCATION
// ============================================================================

/// Resolve API dinamicamente por hash (técnica comum em malware)
#[cfg(windows)]
pub fn get_proc_by_hash(_module_hash: u32, _proc_hash: u32) -> Option<usize> {
    // Em implementação real:
    // 1. Percorre PEB->Ldr->InMemoryOrderModuleList
    // 2. Calcula hash do nome do módulo
    // 3. Se match, percorre Export Directory
    // 4. Calcula hash de cada função exportada
    // 5. Retorna endereço se match
    
    // Simplificado para CTF
    None
}

/// Calcula hash de string (para API hashing)
pub fn hash_string(s: &str) -> u32 {
    let mut hash = 0x811C9DC5u32; // FNV-1a offset basis
    
    for byte in s.bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193); // FNV-1a prime
    }
    
    hash
}

/// Calcula hash de string (case insensitive)
pub fn hash_string_ci(s: &str) -> u32 {
    let mut hash = 0x811C9DC5u32;
    
    for byte in s.bytes() {
        let b = if byte >= b'A' && byte <= b'Z' {
            byte + 0x20 // lowercase
        } else {
            byte
        };
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    
    hash
}

// ============================================================================
// ENVIRONMENT CHECKS
// ============================================================================

/// Verifica se está rodando em ambiente virtualizado
pub fn is_virtual_environment() -> bool {
    let mut score = 0;
    
    // Check 1: MAC address prefixes
    if has_vm_mac_prefix() {
        score += 2;
    }
    
    // Check 2: VM processes
    if has_vm_processes() {
        score += 2;
    }
    
    // Check 3: VM files
    if has_vm_files() {
        score += 2;
    }
    
    // Check 4: Low resources
    if has_low_resources() {
        score += 1;
    }
    
    // Check 5: Suspicious username
    if has_suspicious_username() {
        score += 1;
    }
    
    // Score >= 3 indica VM/sandbox
    score >= 3
}

fn has_vm_mac_prefix() -> bool {
    #[cfg(unix)]
    {
        if let Ok(output) = std::process::Command::new("ip").args(["link"]).output() {
            let result = String::from_utf8_lossy(&output.stdout).to_lowercase();
            let vm_macs = ["00:0c:29", "00:50:56", "08:00:27", "52:54:00", "00:1c:42"];
            for mac in vm_macs {
                if result.contains(mac) {
                    return true;
                }
            }
        }
    }
    false
}

fn has_vm_processes() -> bool {
    let vm_procs = [
        "vmtoolsd", "vmwaretray", "vboxservice", "vboxtray",
        "qemu-ga", "xenservice", "vmsrvc",
    ];
    
    #[cfg(unix)]
    {
        if let Ok(output) = std::process::Command::new("ps").args(["aux"]).output() {
            let procs = String::from_utf8_lossy(&output.stdout).to_lowercase();
            for p in vm_procs {
                if procs.contains(p) {
                    return true;
                }
            }
        }
    }
    
    #[cfg(windows)]
    {
        if let Ok(output) = std::process::Command::new("tasklist").output() {
            let procs = String::from_utf8_lossy(&output.stdout).to_lowercase();
            for p in vm_procs {
                if procs.contains(p) {
                    return true;
                }
            }
        }
    }
    
    false
}

fn has_vm_files() -> bool {
    #[cfg(windows)]
    {
        let vm_files = [
            "C:\\windows\\system32\\drivers\\vmmouse.sys",
            "C:\\windows\\system32\\drivers\\vmhgfs.sys",
            "C:\\windows\\system32\\drivers\\vboxmouse.sys",
        ];
        
        for path in vm_files {
            if std::path::Path::new(path).exists() {
                return true;
            }
        }
    }
    
    #[cfg(unix)]
    {
        let vm_files = [
            "/sys/class/dmi/id/product_name",
        ];
        
        for path in vm_files {
            if let Ok(content) = std::fs::read_to_string(path) {
                let lower = content.to_lowercase();
                if lower.contains("vmware") || lower.contains("virtualbox") || lower.contains("qemu") {
                    return true;
                }
            }
        }
    }
    
    false
}

fn has_low_resources() -> bool {
    use sysinfo::System;
    let sys = System::new_all();
    
    // Menos de 2 CPUs ou menos de 2GB RAM
    let cpus = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);
    
    let ram_gb = sys.total_memory() / (1024 * 1024 * 1024);
    
    cpus < 2 || ram_gb < 2
}

fn has_suspicious_username() -> bool {
    let user = whoami::username().to_lowercase();
    let suspicious = [
        "sandbox", "virus", "malware", "sample", "test",
        "cuckoo", "analyst", "vmware", "virtual", "honey",
    ];
    
    for s in suspicious {
        if user.contains(s) {
            return true;
        }
    }
    
    false
}

// ============================================================================
// EXECUTION FLOW OBFUSCATION
// ============================================================================

/// Executa função com verificações de segurança
pub fn guarded_execute<F, R>(f: F) -> Option<R>
where
    F: FnOnce() -> R,
{
    // Pre-execution checks
    if is_debugger_attached() {
        return None;
    }
    
    // Junk antes
    junk_code_block();
    
    // Execução real via indireção
    let result = indirect_call(f);
    
    // Junk depois
    if opaque_true() {
        junk_code_block();
    }
    
    Some(result)
}

/// Delay com jitter para evitar timing signatures
pub fn anti_timing_delay() {
    let base = 100u64;
    let jitter = rand::random::<u64>() % 50;
    let delay = Duration::from_millis(base + jitter);
    
    // Sleep fragmentado para dificultar análise
    for _ in 0..10 {
        std::thread::sleep(delay / 10);
        junk_code_block();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_opaque_predicates() {
        // Deve sempre ser true
        assert!(opaque_true());
        // Deve sempre ser false
        assert!(!opaque_false());
    }
    
    #[test]
    fn test_hash_string() {
        let hash1 = hash_string("kernel32.dll");
        let hash2 = hash_string("kernel32.dll");
        assert_eq!(hash1, hash2);
        
        let hash3 = hash_string("ntdll.dll");
        assert_ne!(hash1, hash3);
    }
    
    #[test]
    fn test_junk_code() {
        // Não deve panic
        junk_code_block();
    }
}
