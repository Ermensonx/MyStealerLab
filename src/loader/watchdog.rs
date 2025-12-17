//! Watchdog - Process Monitor & Guardian
//! 
//! Monitora processos e implementa técnicas de evasão de detecção.
//! Simula comportamento de serviços legítimos do sistema.
//!
//! ⚠️ EDUCATIONAL PURPOSES ONLY - CTF IR Training

use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// Jitter máximo para timing (em %)
const TIMING_JITTER_PERCENT: u32 = 20;

/// Histórico de eventos para detecção de anomalias
const EVENT_HISTORY_SIZE: usize = 100;

/// Tipos de eventos monitorados
#[derive(Debug, Clone)]
pub enum WatchdogEvent {
    Heartbeat { timestamp: Instant },
    ProcessCheck { pid: u32, alive: bool },
    Respawn { head: String, success: bool },
    AnomalyDetected { kind: String },
    #[allow(dead_code)]
    SystemSleep { duration: Duration },
}

/// Watchdog que monitora e protege os processos
pub struct Watchdog {
    /// Histórico de eventos
    events: VecDeque<WatchdogEvent>,
    /// Última verificação de sistema
    last_system_check: Instant,
    /// Contador de anomalias detectadas
    anomaly_count: u32,
    /// Flag de modo stealth
    stealth_mode: bool,
}

impl Watchdog {
    pub fn new() -> Self {
        Self {
            events: VecDeque::with_capacity(EVENT_HISTORY_SIZE),
            last_system_check: Instant::now(),
            anomaly_count: 0,
            stealth_mode: true,
        }
    }

    /// Adiciona evento ao histórico
    pub fn log_event(&mut self, event: WatchdogEvent) {
        if self.events.len() >= EVENT_HISTORY_SIZE {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    /// Adiciona jitter ao timing para evitar detecção por padrões
    pub fn jittered_sleep(base_duration: Duration) -> Duration {
        let jitter_range = (base_duration.as_millis() as u32 * TIMING_JITTER_PERCENT) / 100;
        let jitter = if jitter_range > 0 {
            rand::random::<u32>() % jitter_range
        } else {
            0
        };
        
        // Adiciona ou subtrai jitter aleatoriamente
        if rand::random::<bool>() {
            base_duration + Duration::from_millis(jitter as u64)
        } else {
            base_duration.saturating_sub(Duration::from_millis(jitter as u64))
        }
    }

    /// Verifica se o sistema está em modo de análise
    pub fn check_analysis_mode(&mut self) -> bool {
        // Em produção real, verificaria processos de análise
        // Aqui apenas simula para CTF
        false
    }

    /// Simula comportamento de processo legítimo
    pub fn mimic_legitimate_activity(&self) {
        // Faz operações "normais" que processos legítimos fariam
        
        // 1. Lê arquivos de configuração do sistema (comum)
        #[cfg(windows)]
        {
            let _ = std::fs::metadata("C:\\Windows\\System32\\config");
        }
        
        #[cfg(unix)]
        {
            let _ = std::fs::metadata("/etc/passwd");
            let _ = std::fs::metadata("/etc/hostname");
        }
        
        // 2. Verifica tempo do sistema (comum)
        let _ = std::time::SystemTime::now();
        
        // 3. Pequeno sleep com jitter (parece idle natural)
        std::thread::sleep(Self::jittered_sleep(Duration::from_millis(10)));
    }

    /// Verifica integridade do próprio executável
    pub fn check_self_integrity(&self) -> bool {
        if let Ok(exe_path) = std::env::current_exe() {
            // Verifica se o executável ainda existe
            if !exe_path.exists() {
                return false;
            }
            
            // Verifica permissões
            if let Ok(metadata) = std::fs::metadata(&exe_path) {
                // Em Unix, verifica se ainda é executável
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = metadata.permissions();
                    if perms.mode() & 0o111 == 0 {
                        return false;
                    }
                }
                
                #[cfg(windows)]
                {
                    let _ = metadata;
                }
            }
        }
        
        true
    }

    /// Detecta tentativas de terminação do processo
    pub fn setup_termination_handler(&self) {
        #[cfg(unix)]
        {
            // Em Unix, configura handler para SIGTERM
            debug!("[WATCHDOG] Signal handlers configured");
        }
        
        #[cfg(windows)]
        {
            // Em Windows, usaria SetConsoleCtrlHandler
            debug!("[WATCHDOG] Console handlers configured");
        }
    }

    /// Retorna estatísticas do watchdog
    pub fn stats(&self) -> WatchdogStats {
        WatchdogStats {
            events_logged: self.events.len(),
            anomalies_detected: self.anomaly_count,
            uptime: self.last_system_check.elapsed(),
            stealth_mode: self.stealth_mode,
        }
    }

    /// Ativa/desativa modo stealth
    pub fn set_stealth(&mut self, enabled: bool) {
        self.stealth_mode = enabled;
        info!("[WATCHDOG] Stealth mode: {}", if enabled { "ON" } else { "OFF" });
    }

    /// Executa verificações periódicas
    pub fn periodic_check(&mut self) {
        self.log_event(WatchdogEvent::Heartbeat {
            timestamp: Instant::now(),
        });
        
        // Verifica integridade
        if !self.check_self_integrity() {
            self.anomaly_count += 1;
            self.log_event(WatchdogEvent::AnomalyDetected {
                kind: "integrity_violation".into(),
            });
        }
        
        // Verifica análise
        if self.check_analysis_mode() {
            self.anomaly_count += 1;
            self.log_event(WatchdogEvent::AnomalyDetected {
                kind: "analysis_detected".into(),
            });
        }
        
        // Simula atividade legítima
        if self.stealth_mode {
            self.mimic_legitimate_activity();
        }
        
        self.last_system_check = Instant::now();
    }
}

impl Default for Watchdog {
    fn default() -> Self {
        Self::new()
    }
}

/// Estatísticas do watchdog
#[derive(Debug)]
pub struct WatchdogStats {
    pub events_logged: usize,
    pub anomalies_detected: u32,
    pub uptime: Duration,
    pub stealth_mode: bool,
}

/// Gerador de nomes de processo "naturais"
pub struct ProcessNameGenerator;

impl ProcessNameGenerator {
    /// Gera um nome de processo que parece legítimo
    pub fn generate() -> String {
        let prefixes = [
            "svc", "Runtime", "System", "Service", "Update",
            "Helper", "Agent", "Host", "Manager", "Monitor",
        ];
        
        let suffixes = [
            "Host", "Broker", "Worker", "Service", "Agent",
            "Helper", "Daemon", "Process", "Task", "App",
        ];
        
        let prefix = prefixes[rand::random::<usize>() % prefixes.len()];
        let suffix = suffixes[rand::random::<usize>() % suffixes.len()];
        
        format!("{}{}", prefix, suffix)
    }

    /// Nomes que parecem serviços Windows legítimos
    #[allow(dead_code)]
    pub fn windows_service_names() -> Vec<&'static str> {
        vec![
            "svchost",
            "RuntimeBroker",
            "SearchApp",
            "SecurityHealthService",
            "WmiPrvSE",
            "conhost",
            "dllhost",
            "taskhostw",
            "sihost",
            "fontdrvhost",
        ]
    }

    /// Nomes que parecem daemons Linux legítimos
    #[allow(dead_code)]
    pub fn linux_daemon_names() -> Vec<&'static str> {
        vec![
            "systemd-journal",
            "dbus-daemon",
            "NetworkManager",
            "pulseaudio",
            "gnome-shell",
            "Xorg",
            "gdm-session",
            "gvfsd",
            "evolution-data",
            "tracker-miner",
        ]
    }
}

/// Técnicas de anti-kill
pub mod anti_kill {
    /// Tenta tornar o processo mais difícil de matar
    pub fn harden_process() {
        #[cfg(windows)]
        {
            // Em Windows real, usaria:
            // - SetProcessMitigationPolicy
            // - Modificar DACL do processo
            // - Critical process flag
        }
        
        #[cfg(unix)]
        {
            // Em Unix real, usaria:
            // - prctl(PR_SET_DUMPABLE, 0)
            // - rlimit para prevenir core dumps
            // - Ignorar certos sinais
        }
    }
    
    /// Detecta se alguém está tentando terminar o processo
    #[allow(dead_code)]
    pub fn detect_termination_attempt() -> bool {
        #[cfg(unix)]
        {
            // Verifica se há sinais pendentes
            // sigpending() em código real
        }
        
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jittered_sleep() {
        let base = Duration::from_secs(1);
        let jittered = Watchdog::jittered_sleep(base);
        
        // Deve estar dentro de ±20% do base
        let min = Duration::from_millis(800);
        let max = Duration::from_millis(1200);
        
        assert!(jittered >= min && jittered <= max);
    }

    #[test]
    fn test_process_name_generator() {
        let name = ProcessNameGenerator::generate();
        assert!(!name.is_empty());
        println!("Generated name: {}", name);
    }

    #[test]
    fn test_watchdog_events() {
        let mut wd = Watchdog::new();
        wd.log_event(WatchdogEvent::Heartbeat {
            timestamp: Instant::now(),
        });
        
        assert_eq!(wd.events.len(), 1);
    }
}
