//! Helper functions

use std::path::PathBuf;

#[allow(dead_code)]

/// Expande variáveis de ambiente em caminhos
pub fn expand_path(path: &str) -> PathBuf {
    let expanded = if path.starts_with('~') {
        if let Some(home) = dirs::home_dir() {
            path.replacen('~', &home.to_string_lossy(), 1)
        } else {
            path.to_string()
        }
    } else {
        path.to_string()
    };
    
    // Expandir variáveis de ambiente
    #[cfg(windows)]
    let expanded = {
        let mut result = expanded;
        for (key, value) in std::env::vars() {
            result = result.replace(&format!("%{}%", key), &value);
        }
        result
    };
    
    #[cfg(unix)]
    let expanded = {
        let mut result = expanded;
        for (key, value) in std::env::vars() {
            result = result.replace(&format!("${}", key), &value);
            result = result.replace(&format!("${{{}}}", key), &value);
        }
        result
    };
    
    PathBuf::from(expanded)
}

/// Format bytes to human readable
#[allow(dead_code)]
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    
    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

#[allow(dead_code)]
pub fn generate_session_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[allow(dead_code)]
pub fn current_timestamp() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[allow(dead_code)]
pub fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500 bytes");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1024 * 1024), "1.00 MB");
    }
    
    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("test file.txt"), "test_file.txt");
        assert_eq!(sanitize_filename("hello/world"), "hello_world");
    }
}

