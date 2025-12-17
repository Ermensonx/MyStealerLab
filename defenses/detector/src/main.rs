//! MyStealer Detector - Ferramenta de Defesa
//!
//! Esta ferramenta detecta comportamentos típicos de infostealers
//! para fins educacionais em ambiente de CTF.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use sysinfo::{System, ProcessExt, SystemExt};
use tracing::{info, warn, error, Level};
use tracing_subscriber::FmtSubscriber;

/// Indicadores de Compromisso (IOCs)
struct IocDatabase {
    /// Processos suspeitos
    suspicious_processes: HashSet<String>,
    
    /// Arquivos sensíveis monitorados
    sensitive_paths: Vec<PathBuf>,
    
    /// Portas suspeitas
    suspicious_ports: Vec<u16>,
    
    /// Strings suspeitas em memória
    suspicious_strings: Vec<String>,
}

impl Default for IocDatabase {
    fn default() -> Self {
        Self {
            suspicious_processes: [
                "mystealer",
                "stealer",
                "grabber",
                "keylogger",
            ].iter().map(|s| s.to_string()).collect(),
            
            sensitive_paths: vec![
                dirs::home_dir().unwrap().join(".config/google-chrome/Default/Login Data"),
                dirs::home_dir().unwrap().join(".mozilla/firefox"),
                dirs::home_dir().unwrap().join(".ssh"),
                dirs::home_dir().unwrap().join(".aws/credentials"),
            ],
            
            suspicious_ports: vec![8080, 4444, 5555, 1337, 31337],
            
            suspicious_strings: vec![
                "password".to_string(),
                "credential".to_string(),
                "cookie".to_string(),
                "wallet".to_string(),
            ],
        }
    }
}

/// Resultado de detecção
#[derive(Debug)]
struct Detection {
    category: String,
    description: String,
    severity: Severity,
    timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug)]
enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Detector principal
struct Detector {
    iocs: IocDatabase,
    system: System,
    detections: Vec<Detection>,
}

impl Detector {
    fn new() -> Self {
        Self {
            iocs: IocDatabase::default(),
            system: System::new_all(),
            detections: Vec::new(),
        }
    }
    
    /// Executa todas as verificações
    fn run_checks(&mut self) {
        self.system.refresh_all();
        
        self.check_suspicious_processes();
        self.check_network_connections();
        self.check_file_access();
        self.check_persistence();
    }
    
    /// Verifica processos suspeitos
    fn check_suspicious_processes(&mut self) {
        info!("Verificando processos...");
        
        for (pid, process) in self.system.processes() {
            let name = process.name().to_lowercase();
            
            for suspicious in &self.iocs.suspicious_processes {
                if name.contains(suspicious) {
                    self.add_detection(Detection {
                        category: "Process".to_string(),
                        description: format!(
                            "Processo suspeito detectado: {} (PID: {})",
                            process.name(), pid
                        ),
                        severity: Severity::High,
                        timestamp: chrono::Utc::now(),
                    });
                }
            }
        }
    }
    
    /// Verifica conexões de rede suspeitas
    fn check_network_connections(&mut self) {
        info!("Verificando conexões de rede...");
        
        // Em produção, usaria netstat ou /proc/net/tcp
        // Para o CTF, simplificamos
        
        #[cfg(unix)]
        {
            use std::process::Command;
            
            if let Ok(output) = Command::new("ss").args(["-tuln"]).output() {
                let ss_output = String::from_utf8_lossy(&output.stdout);
                
                for port in &self.iocs.suspicious_ports {
                    if ss_output.contains(&format!(":{}", port)) {
                        self.add_detection(Detection {
                            category: "Network".to_string(),
                            description: format!(
                                "Porta suspeita em uso: {}",
                                port
                            ),
                            severity: Severity::Medium,
                            timestamp: chrono::Utc::now(),
                        });
                    }
                }
            }
        }
    }
    
    /// Verifica acesso a arquivos sensíveis
    fn check_file_access(&mut self) {
        info!("Verificando arquivos sensíveis...");
        
        for path in &self.iocs.sensitive_paths {
            if path.exists() {
                // Verificar tempo de acesso recente
                if let Ok(metadata) = path.metadata() {
                    if let Ok(accessed) = metadata.accessed() {
                        let now = std::time::SystemTime::now();
                        if let Ok(duration) = now.duration_since(accessed) {
                            // Se acessado nos últimos 5 minutos
                            if duration < Duration::from_secs(300) {
                                self.add_detection(Detection {
                                    category: "FileAccess".to_string(),
                                    description: format!(
                                        "Arquivo sensível acessado recentemente: {}",
                                        path.display()
                                    ),
                                    severity: Severity::Medium,
                                    timestamp: chrono::Utc::now(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    
    /// Verifica mecanismos de persistência
    fn check_persistence(&mut self) {
        info!("Verificando persistência...");
        
        // Verificar cron jobs suspeitos
        #[cfg(unix)]
        {
            let crontab_path = format!(
                "/var/spool/cron/crontabs/{}",
                whoami::username()
            );
            
            if let Ok(content) = std::fs::read_to_string(&crontab_path) {
                for suspicious in &self.iocs.suspicious_processes {
                    if content.to_lowercase().contains(suspicious) {
                        self.add_detection(Detection {
                            category: "Persistence".to_string(),
                            description: format!(
                                "Cron job suspeito encontrado: {}",
                                suspicious
                            ),
                            severity: Severity::Critical,
                            timestamp: chrono::Utc::now(),
                        });
                    }
                }
            }
        }
        
        // Verificar arquivos de autostart
        if let Some(config) = dirs::config_dir() {
            let autostart = config.join("autostart");
            if autostart.exists() {
                if let Ok(entries) = std::fs::read_dir(&autostart) {
                    for entry in entries.flatten() {
                        let name = entry.file_name().to_string_lossy().to_lowercase();
                        for suspicious in &self.iocs.suspicious_processes {
                            if name.contains(suspicious) {
                                self.add_detection(Detection {
                                    category: "Persistence".to_string(),
                                    description: format!(
                                        "Autostart suspeito: {}",
                                        entry.path().display()
                                    ),
                                    severity: Severity::Critical,
                                    timestamp: chrono::Utc::now(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    
    fn add_detection(&mut self, detection: Detection) {
        let severity_str = match detection.severity {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        };
        
        warn!(
            "[{}] {} - {}",
            severity_str,
            detection.category,
            detection.description
        );
        
        self.detections.push(detection);
    }
    
    fn report(&self) {
        println!("\n{}", "=".repeat(60));
        println!("📊 RELATÓRIO DE DETECÇÃO");
        println!("{}", "=".repeat(60));
        
        if self.detections.is_empty() {
            println!("✅ Nenhuma ameaça detectada");
        } else {
            println!("⚠️  {} ameaças detectadas:\n", self.detections.len());
            
            for (i, detection) in self.detections.iter().enumerate() {
                println!("{}. [{}] {}", i + 1, detection.category, detection.description);
            }
        }
        
        println!("{}", "=".repeat(60));
    }
}

#[tokio::main]
async fn main() {
    // Configurar logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    
    tracing::subscriber::set_global_default(subscriber)
        .expect("Falha ao configurar logging");
    
    println!(r#"
    ╔═══════════════════════════════════════════╗
    ║  🛡️  MyStealer Detector - CTF Defense    ║
    ╚═══════════════════════════════════════════╝
    "#);
    
    info!("Iniciando verificação de segurança...");
    
    let mut detector = Detector::new();
    
    // Executar verificações
    detector.run_checks();
    
    // Exibir relatório
    detector.report();
    
    info!("Verificação concluída.");
}

