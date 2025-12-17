//! Anti-Debug & Anti-Disassembly Techniques
//!
//! ⚠️ EDUCATIONAL PURPOSES ONLY - CTF IR Training
//! Todas as strings são construídas em runtime.

#![allow(dead_code)]

use std::time::{Duration, Instant};
use std::hint::black_box;

// ============================================================================
// STRING BUILDERS
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
// ANTI-DEBUGGING
// ============================================================================

pub fn is_debugger_attached() -> bool {
    let mut detected = false;
    
    detected |= timing_check();
    
    #[cfg(windows)]
    {
        detected |= windows_debug_checks();
    }
    
    #[cfg(unix)]
    {
        detected |= unix_debug_checks();
    }
    
    detected |= exception_check();
    
    detected
}

fn timing_check() -> bool {
    let start = Instant::now();
    
    let mut x = 0u64;
    for i in 0..1000 {
        x = x.wrapping_add(i);
        x = x.wrapping_mul(0x5851F42D4C957F2D);
        x = x.rotate_left(17);
    }
    black_box(x);
    
    start.elapsed() > Duration::from_millis(50)
}

#[cfg(windows)]
fn windows_debug_checks() -> bool {
    use std::process::Command;
    
    // PowerShell check (ofuscado)
    let ps = bs(&['p','o','w','e','r','s','h','e','l','l']);
    let arg1 = bs(&['-','N','o','P','r','o','f','i','l','e']);
    let arg2 = bs(&['-','C','o','m','m','a','n','d']);
    // [System.Diagnostics.Debugger]::IsAttached
    let check = bs(&['[','S','y','s','t','e','m','.','D','i','a','g','n','o','s','t','i','c','s','.','D','e','b','u','g','g','e','r',']',':',':','I','s','A','t','t','a','c','h','e','d']);
    
    if let Ok(output) = Command::new(&ps).args([&arg1, &arg2, &check]).output() {
        let result = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
        let tr = bs(&['t','r','u','e']);
        if result == tr {
            return true;
        }
    }
    
    false
}

#[cfg(not(windows))]
fn windows_debug_checks() -> bool {
    false
}

#[cfg(unix)]
fn unix_debug_checks() -> bool {
    // /proc/self/status -> TracerPid
    let status_path = bs(&['/','p','r','o','c','/','s','e','l','f','/','s','t','a','t','u','s']);
    if let Ok(status) = std::fs::read_to_string(&status_path) {
        let prefix = bs(&['T','r','a','c','e','r','P','i','d',':']);
        for line in status.lines() {
            if let Some(pid) = line.strip_prefix(&prefix) {
                if pid.trim() != "0" {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(not(unix))]
fn unix_debug_checks() -> bool {
    false
}

fn exception_check() -> bool {
    let result = std::panic::catch_unwind(|| {
        let x: u64 = 0xDEADBEEF;
        black_box(x.wrapping_mul(x));
    });
    result.is_err()
}

// ============================================================================
// ANTI-DISASSEMBLY
// ============================================================================

#[inline(never)]
#[allow(unused_comparisons)]
pub fn opaque_true() -> bool {
    let x = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(1);
    
    (x * x) >= 0 || x < 0
}

#[inline(never)]
pub fn opaque_false() -> bool {
    let x = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(1);
    
    x * x < 0
}

#[inline(never)]
pub fn junk_code_block() {
    let mut arr = [0u8; 64];
    
    for i in 0..64 {
        arr[i] = (i as u8).wrapping_mul(0x41);
        arr[i] = arr[i].rotate_left(3);
        arr[i] ^= 0x55;
    }
    
    let mut sum = 0u64;
    for &b in &arr {
        sum = sum.wrapping_add(b as u64);
        sum = sum.wrapping_mul(0x100000001B3);
        if opaque_false() {
            sum = 0;
        }
    }
    
    let hash = sum.wrapping_mul(0x517CC1B727220A95);
    
    black_box(arr);
    black_box(hash);
    
    if opaque_false() {
        std::process::exit(1);
    }
}

#[inline(never)]
fn dead_code() {
    let secret = [0x41, 0x42, 0x43, 0x44];
    let mut result = 0u32;
    for &b in &secret {
        result = result.wrapping_add(b as u32);
    }
    black_box(result);
}

#[inline(never)]
pub fn indirect_call<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    junk_code_block();
    let result = f();
    if opaque_false() {
        dead_code();
    }
    result
}

// ============================================================================
// API HASHING
// ============================================================================

pub fn hash_string(s: &str) -> u32 {
    let mut hash = 0x811C9DC5u32;
    for byte in s.bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

pub fn hash_string_ci(s: &str) -> u32 {
    let mut hash = 0x811C9DC5u32;
    for byte in s.bytes() {
        let b = if byte >= b'A' && byte <= b'Z' {
            byte + 0x20
        } else {
            byte
        };
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

// ============================================================================
// ENVIRONMENT CHECKS (strings ofuscadas)
// ============================================================================

pub fn is_virtual_environment() -> bool {
    let mut score = 0;
    
    if has_vm_mac_prefix() { score += 2; }
    if has_vm_processes() { score += 2; }
    if has_vm_files() { score += 2; }
    if has_low_resources() { score += 1; }
    if has_suspicious_username() { score += 1; }
    
    score >= 3
}

fn has_vm_mac_prefix() -> bool {
    #[cfg(unix)]
    {
        use std::process::Command;
        let cmd = bs(&['i','p']);
        let arg = bs(&['l','i','n','k']);
        if let Ok(output) = Command::new(&cmd).args([&arg]).output() {
            let result = String::from_utf8_lossy(&output.stdout).to_lowercase();
            // MAC prefixes de VMs
            let vm_macs = [
                bs(&['0','0',':','0','c',':','2','9']),
                bs(&['0','0',':','5','0',':','5','6']),
                bs(&['0','8',':','0','0',':','2','7']),
                bs(&['5','2',':','5','4',':','0','0']),
                bs(&['0','0',':','1','c',':','4','2']),
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

fn has_vm_processes() -> bool {
    use std::process::Command;
    
    // Processos de VM (ofuscados)
    let vm_procs: Vec<String> = vec![
        xd(&[0x6f, 0x6c, 0x7d, 0x6c, 0x6c, 0x69, 0x7c, 0x75], 0x19), // vmtoolsd
        xd(&[0x6f, 0x6c, 0x78, 0x70, 0x79, 0x72, 0x7d, 0x79, 0x70, 0x68], 0x19), // vmwaretray
        bs(&['v','b','o','x','s','e','r','v','i','c','e']),
        bs(&['v','b','o','x','t','r','a','y']),
        bs(&['q','e','m','u','-','g','a']),
        bs(&['x','e','n','s','e','r','v','i','c','e']),
        bs(&['v','m','s','r','v','c']),
    ];
    
    #[cfg(unix)]
    {
        let cmd = bs(&['p','s']);
        let arg = bs(&['a','u','x']);
        if let Ok(output) = Command::new(&cmd).args([&arg]).output() {
            let procs = String::from_utf8_lossy(&output.stdout).to_lowercase();
            for p in &vm_procs {
                if procs.contains(&p.to_lowercase()) {
                    return true;
                }
            }
        }
    }
    
    #[cfg(windows)]
    {
        let cmd = bs(&['t','a','s','k','l','i','s','t']);
        if let Ok(output) = Command::new(&cmd).output() {
            let procs = String::from_utf8_lossy(&output.stdout).to_lowercase();
            for p in &vm_procs {
                if procs.contains(&p.to_lowercase()) {
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
        // Paths de drivers de VM (ofuscados)
        let base = bs(&['C',':','\\','w','i','n','d','o','w','s','\\','s','y','s','t','e','m','3','2','\\','d','r','i','v','e','r','s','\\']);
        let vm_files = [
            format!("{}{}", base, bs(&['v','m','m','o','u','s','e','.','s','y','s'])),
            format!("{}{}", base, bs(&['v','m','h','g','f','s','.','s','y','s'])),
            format!("{}{}", base, bs(&['v','b','o','x','m','o','u','s','e','.','s','y','s'])),
        ];
        
        for path in &vm_files {
            if std::path::Path::new(path).exists() {
                return true;
            }
        }
    }
    
    #[cfg(unix)]
    {
        let path = bs(&['/','s','y','s','/','c','l','a','s','s','/','d','m','i','/','i','d','/','p','r','o','d','u','c','t','_','n','a','m','e']);
        if let Ok(content) = std::fs::read_to_string(&path) {
            let lower = content.to_lowercase();
            let checks = [
                bs(&['v','m','w','a','r','e']),
                bs(&['v','i','r','t','u','a','l','b','o','x']),
                bs(&['q','e','m','u']),
            ];
            for c in &checks {
                if lower.contains(c) {
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
    
    let cpus = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);
    
    let ram_gb = sys.total_memory() / (1024 * 1024 * 1024);
    
    cpus < 2 || ram_gb < 2
}

fn has_suspicious_username() -> bool {
    let user = whoami::username().to_lowercase();
    
    // Usernames suspeitos (ofuscados com XOR 0x19)
    let suspicious: Vec<String> = vec![
        xd(&[0x7a, 0x76, 0x69, 0x75, 0x77, 0x68, 0x63], 0x19), // sandbox
        xd(&[0x6f, 0x6a, 0x79, 0x7e, 0x7c], 0x19), // virus
        xd(&[0x64, 0x76, 0x6d, 0x78, 0x76, 0x79, 0x72], 0x19), // malware
        xd(&[0x7a, 0x76, 0x64, 0x7f, 0x6d, 0x72], 0x19), // sample
        xd(&[0x6d, 0x72, 0x7c, 0x6d], 0x19), // test
        xd(&[0x74, 0x7e, 0x74, 0x6c, 0x68, 0x68], 0x19), // cuckoo
        xd(&[0x76, 0x69, 0x76, 0x6d, 0x68, 0x7c, 0x6d], 0x19), // analyst
        xd(&[0x6f, 0x6c, 0x78, 0x76, 0x79, 0x72], 0x19), // vmware
        xd(&[0x6f, 0x6a, 0x79, 0x6d, 0x7e, 0x76, 0x6d], 0x19), // virtual
        xd(&[0x70, 0x68, 0x69, 0x72, 0x68], 0x19), // honey
    ];
    
    for s in &suspicious {
        if user.contains(s) {
            return true;
        }
    }
    
    false
}

// ============================================================================
// EXECUTION FLOW OBFUSCATION
// ============================================================================

pub fn guarded_execute<F, R>(f: F) -> Option<R>
where
    F: FnOnce() -> R,
{
    if is_debugger_attached() {
        return None;
    }
    
    junk_code_block();
    let result = indirect_call(f);
    
    if opaque_true() {
        junk_code_block();
    }
    
    Some(result)
}

pub fn anti_timing_delay() {
    let base = 100u64;
    let jitter = rand::random::<u64>() % 50;
    let delay = Duration::from_millis(base + jitter);
    
    for _ in 0..10 {
        std::thread::sleep(delay / 10);
        junk_code_block();
    }
}
