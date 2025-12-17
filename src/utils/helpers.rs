//! Funções Auxiliares

use std::path::PathBuf;

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

/// Formata tamanho em bytes para formato legível
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

/// Gera ID único para sessão
pub fn generate_session_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Obtém timestamp atual em formato ISO
pub fn current_timestamp() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Sanitiza string para uso em nome de arquivo
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

