//! Build script para adicionar entropia e metadados ao binário
//!
//! Este script é executado antes da compilação e:
//! - Adiciona timestamp único
//! - Gera dados aleatórios para mudar o hash
//! - Define variáveis de ambiente para ofuscação

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Adiciona timestamp de build (muda hash a cada compilação)
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    println!("cargo:rustc-env=BUILD_TIMESTAMP={}", timestamp);
    
    // Gera um ID único para esta build
    let build_id: u64 = rand_simple();
    println!("cargo:rustc-env=BUILD_ID={:016x}", build_id);
    
    // Recompila se build.rs mudar
    println!("cargo:rerun-if-changed=build.rs");
    
    // Adiciona metadados falsos para confundir análise
    #[cfg(windows)]
    {
        // Em Windows, poderia adicionar resource section personalizada
        // Aqui apenas imprimimos para o log
    }
}

// Gerador simples de números aleatórios (sem dependências)
fn rand_simple() -> u64 {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap();
    
    let mut seed = time.as_nanos() as u64;
    seed ^= seed >> 12;
    seed ^= seed << 25;
    seed ^= seed >> 27;
    seed.wrapping_mul(0x2545F4914F6CDD1D)
}
