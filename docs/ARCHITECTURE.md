# 🏗️ Arquitetura Técnica - MyStealer CTF Lab

## Visão Geral da Arquitetura

```
┌─────────────────────────────────────────────────────────────────┐
│                         MYSTEALER CTF                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   CORE       │  │  COLLECTORS  │  │    EXFILTRATION      │  │
│  │              │  │              │  │    (Simulada)        │  │
│  │ • Config     │  │ • Browser    │  │                      │  │
│  │ • Logger     │  │ • System     │  │ • Local File         │  │
│  │ • Crypto     │  │ • Clipboard  │  │ • Mock Server        │  │
│  │ • Utils      │  │ • FileSystem │  │ • Encrypted Output   │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    ANTI-ANALYSIS (Lab Mode)              │  │
│  │  • VM Detection • Debugger Check • Sandbox Detection     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Componentes Principais

### 1. Core Module

O módulo central gerencia toda a lógica de negócio:

```rust
// Estrutura principal
pub struct MyStealer {
    config: Config,
    collectors: Vec<Box<dyn Collector>>,
    exfiltrator: Box<dyn Exfiltrator>,
    crypto: CryptoManager,
}
```

#### 1.1 Configuração

```rust
pub struct Config {
    /// Modo de operação (lab, debug, release)
    pub mode: OperationMode,
    
    /// Módulos habilitados
    pub enabled_modules: Vec<ModuleType>,
    
    /// Configuração de exfiltração
    pub exfil_config: ExfilConfig,
    
    /// Chave de criptografia (gerada dinamicamente)
    pub encryption_key: Option<[u8; 32]>,
}
```

### 2. Sistema de Collectors

Interface trait para todos os coletores:

```rust
pub trait Collector: Send + Sync {
    /// Nome do coletor
    fn name(&self) -> &str;
    
    /// Executa a coleta
    fn collect(&self) -> Result<CollectedData, CollectorError>;
    
    /// Verifica se o coletor é suportado no SO atual
    fn is_supported(&self) -> bool;
    
    /// Prioridade de execução
    fn priority(&self) -> u8;
}
```

### 3. Sistema de Exfiltração (Simulado)

```rust
pub trait Exfiltrator: Send + Sync {
    /// Envia dados coletados
    fn exfiltrate(&self, data: &EncryptedData) -> Result<(), ExfilError>;
    
    /// Verifica conectividade
    fn check_connection(&self) -> bool;
}

// Implementações para lab
pub struct LocalFileExfil { /* salva em arquivo local */ }
pub struct MockServerExfil { /* envia para servidor local */ }
```

## Fluxo de Execução

```
┌─────────────┐
│   START     │
└──────┬──────┘
       ▼
┌──────────────────┐
│ Load Config      │
│ (lab-mode check) │
└────────┬─────────┘
         ▼
┌──────────────────┐     ┌─────────────────┐
│ Anti-Analysis    │────▶│ Exit if Real    │
│ Checks           │ Yes │ Environment     │
└────────┬─────────┘     └─────────────────┘
         │ No (Lab OK)
         ▼
┌──────────────────┐
│ Initialize       │
│ Collectors       │
└────────┬─────────┘
         ▼
┌──────────────────┐
│ Run Collection   │
│ Pipeline         │
└────────┬─────────┘
         ▼
┌──────────────────┐
│ Encrypt Data     │
│ (AES-256-GCM)    │
└────────┬─────────┘
         ▼
┌──────────────────┐
│ Exfiltrate       │
│ (Local/Mock)     │
└────────┬─────────┘
         ▼
┌──────────────────┐
│ Cleanup &        │
│ Generate Report  │
└────────┬─────────┘
         ▼
┌─────────────┐
│    END      │
└─────────────┘
```

## Estrutura de Dados

### CollectedData

```rust
#[derive(Serialize, Deserialize)]
pub struct CollectedData {
    /// Timestamp da coleta
    pub timestamp: DateTime<Utc>,
    
    /// Identificador único da sessão
    pub session_id: Uuid,
    
    /// Informações do sistema
    pub system_info: SystemInfo,
    
    /// Dados coletados por módulo
    pub modules_data: HashMap<String, ModuleData>,
}

#[derive(Serialize, Deserialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub os_version: String,
    pub username: String,
    pub is_admin: bool,
    pub cpu_info: String,
    pub ram_total: u64,
}

#[derive(Serialize, Deserialize)]
pub enum ModuleData {
    Browser(BrowserData),
    Clipboard(ClipboardData),
    FileSystem(FileSystemData),
    Credentials(CredentialData),
}
```

## Segurança do Código

### Proteções Implementadas (Lab Mode)

1. **Verificação de Ambiente**
   - Detecta VMs conhecidas
   - Verifica debuggers
   - Checa sandboxes

2. **Criptografia**
   - AES-256-GCM para dados em repouso
   - ChaCha20-Poly1305 como alternativa
   - Chaves derivadas com Argon2

3. **Ofuscação (Opcional)**
   - String encryption
   - Control flow flattening
   - Anti-tampering

## Dependências Rust

```toml
[dependencies]
tokio = { version = "1.35", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
aes-gcm = "0.10"
argon2 = "0.5"
base64 = "0.21"
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1.6", features = ["v4", "serde"] }
thiserror = "1.0"
tracing = "0.1"
tracing-subscriber = "0.3"

# Windows-specific
[target.'cfg(windows)'.dependencies]
windows = { version = "0.52", features = [
    "Win32_Foundation",
    "Win32_Security",
    "Win32_System_Threading",
    "Win32_UI_WindowsAndMessaging",
]}

# Linux-specific  
[target.'cfg(unix)'.dependencies]
nix = { version = "0.27", features = ["user"] }
```

## Considerações de Performance

- **Async/Await**: Coleta paralela de múltiplos módulos
- **Memory Safety**: Rust previne buffer overflows nativamente
- **Zero-Copy**: Minimiza alocações desnecessárias
- **Lazy Loading**: Módulos carregados sob demanda

## Próximos Passos

Ver [MODULES.md](MODULES.md) para detalhes de cada módulo.

