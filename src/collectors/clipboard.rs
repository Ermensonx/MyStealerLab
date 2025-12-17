//! Coletor de Área de Transferência

use serde::{Deserialize, Serialize};
use std::process::Command;

use super::{Collector, CollectorError, ModuleData};

/// Dados da área de transferência
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardData {
    /// Conteúdo atual (texto)
    pub current_text: Option<String>,
    
    /// Timestamp da coleta
    pub collected_at: String,
    
    /// Tipo de conteúdo
    pub content_type: String,
    
    /// Tamanho em bytes
    pub size_bytes: usize,
}

/// Coletor de clipboard
pub struct ClipboardCollector;

impl ClipboardCollector {
    pub fn new() -> Self {
        Self
    }
    
    /// Coleta conteúdo da área de transferência
    fn collect_clipboard(&self) -> Result<ClipboardData, CollectorError> {
        let content = self.get_clipboard_text()?;
        
        let size = content.as_ref().map(|s| s.len()).unwrap_or(0);
        
        Ok(ClipboardData {
            current_text: content.map(|s| {
                // Truncar se muito grande
                if s.len() > 4096 {
                    format!("{}... [truncated]", &s[..4096])
                } else {
                    s
                }
            }),
            collected_at: chrono::Utc::now().to_rfc3339(),
            content_type: "text/plain".to_string(),
            size_bytes: size,
        })
    }
    
    #[cfg(windows)]
    fn get_clipboard_text(&self) -> Result<Option<String>, CollectorError> {
        // Usar PowerShell para acessar clipboard no Windows
        let output = Command::new("powershell")
            .args(["-Command", "Get-Clipboard"])
            .output()?;
        
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if text.is_empty() {
                Ok(None)
            } else {
                Ok(Some(text))
            }
        } else {
            Ok(None)
        }
    }
    
    #[cfg(unix)]
    fn get_clipboard_text(&self) -> Result<Option<String>, CollectorError> {
        // Tentar xclip primeiro, depois xsel, depois wl-paste (Wayland)
        let tools = [
            ("xclip", vec!["-selection", "clipboard", "-o"]),
            ("xsel", vec!["--clipboard", "--output"]),
            ("wl-paste", vec![]),
        ];
        
        for (tool, args) in tools {
            if let Ok(output) = Command::new(tool).args(&args).output() {
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !text.is_empty() {
                        return Ok(Some(text));
                    }
                }
            }
        }
        
        Ok(None)
    }
}

impl Default for ClipboardCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for ClipboardCollector {
    fn name(&self) -> &str {
        "clipboard"
    }
    
    fn collect(&self) -> Result<ModuleData, CollectorError> {
        let data = self.collect_clipboard()?;
        Ok(ModuleData::Clipboard(data))
    }
    
    fn is_supported(&self) -> bool {
        // Verificar se temos ferramentas disponíveis
        #[cfg(windows)]
        return true;
        
        #[cfg(unix)]
        {
            // Verificar se xclip, xsel ou wl-paste está disponível
            Command::new("which").arg("xclip").output().map(|o| o.status.success()).unwrap_or(false)
                || Command::new("which").arg("xsel").output().map(|o| o.status.success()).unwrap_or(false)
                || Command::new("which").arg("wl-paste").output().map(|o| o.status.success()).unwrap_or(false)
        }
    }
    
    fn priority(&self) -> u8 {
        50
    }
}

