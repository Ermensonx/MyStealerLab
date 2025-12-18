# 🔬 MyStealer CTF Lab v0.3 - Stealth Edition

> **⚠️ EDUCATIONAL PURPOSES ONLY** - Este projeto é exclusivamente para treinamento de **Incident Response** e **Threat Hunting** em ambientes isolados. Uso indevido é **ILEGAL**.

## 🎯 Overview

Laboratório de CTF avançado para estudo de técnicas de infostealers em Rust. Projetado para treinar equipes de Blue Team em detecção e análise de malware moderno.

**Baseado em:**
- [Rust-for-Malware-Development](https://github.com/Whitecat18/Rust-for-Malware-Development)
- [Goldberg Obfuscation](https://github.com/frank2/goldberg)

---

## 🆕 O Que Há de Novo na v0.3

| Feature | Descrição |
|---------|-----------|
| 🛡️ **Anti-Análise Estática** | Todas as strings sensíveis ofuscadas |
| 🔐 **Anti-Debug** | Múltiplas técnicas de detecção de debuggers |
| 🧩 **Anti-Disassembly** | Opaque predicates, junk code, dead code |
| 🐍 **Hydra System** | 3 processos redundantes com auto-respawn |
| 🔇 **Silent Mode** | Build sem strings detectáveis |
| 🎭 **String Obfuscation** | XOR encoding, stack strings, runtime construction |

---

## 🏗️ Arquitetura

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        MYSTEALER v0.3 - STEALTH EDITION                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────────────────┐   │
│  │    CORE       │  │  COLLECTORS   │  │      EXFILTRATION         │   │
│  │               │  │               │  │                           │   │
│  │ • Config      │  │ • Browser     │  │ • Local File (encrypted)  │   │
│  │ • Crypto      │  │ • System      │  │ • HTTP (mock C2)          │   │
│  │ • Utils       │  │ • Clipboard   │  │ • AES-256-GCM output      │   │
│  └───────────────┘  │ • Files       │  └───────────────────────────┘   │
│                     └───────────────┘                                   │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │                    🐍 HYDRA PERSISTENCE SYSTEM                     │ │
│  │  ┌─────────┐     ┌─────────┐     ┌─────────┐                      │ │
│  │  │  ALPHA  │◄───►│  BETA   │◄───►│  GAMMA  │   Heartbeat IPC      │ │
│  │  │ Primary │     │Backup 1 │     │Backup 2 │   Auto-respawn       │ │
│  │  └─────────┘     └─────────┘     └─────────┘                      │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │                    🛡️ ANTI-ANALYSIS MODULE                        │ │
│  │  • VM Detection (DMI, MAC, CPUID, processes, registry)           │ │
│  │  • Debugger Detection (timing, TracerPid, IsDebuggerPresent)     │ │
│  │  • Sandbox Detection (username, resources, uptime)               │ │
│  │  • Anti-Disassembly (opaque predicates, junk code)               │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │                    🔐 STRING OBFUSCATION                          │ │
│  │  • XOR encoding (keys: 0x17, 0x19, 0x33, 0x42, 0x55, 0x77)       │ │
│  │  • Stack strings (char-by-char construction)                      │ │
│  │  • Runtime SQL query building                                     │ │
│  │  • No static strings in binary                                    │ │
│  └───────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Técnicas Anti-Análise Implementadas

### 1. Anti-Debug

| Técnica | Plataforma | Descrição |
|---------|------------|-----------|
| **Timing Check** | All | Detecta delays causados por single-stepping |
| **TracerPid** | Linux | Verifica `/proc/self/status` |
| **IsDebuggerPresent** | Windows | Via PowerShell |
| **Exception Check** | All | Detecta handlers de exceção anormais |

```rust
// Exemplo de timing check
fn timing_check() -> bool {
    let start = Instant::now();
    // Operação que deveria ser rápida
    for i in 0..1000 { black_box(i); }
    start.elapsed() > Duration::from_millis(50)
}
```

### 2. Anti-Disassembly

| Técnica | Descrição |
|---------|-----------|
| **Opaque Predicates** | Condições que parecem dinâmicas mas são constantes |
| **Junk Code** | Código inútil que confunde análise |
| **Dead Code** | Código que nunca executa mas está no binário |
| **Indirect Calls** | Chamadas via function pointers |

```rust
// Opaque predicate - sempre true, mas IDA não sabe
fn opaque_true() -> bool {
    let x = SystemTime::now().duration_since(UNIX_EPOCH).as_nanos();
    (x * x) >= 0 || x < 0  // Matematicamente sempre true
}
```

### 3. Detecção de VM/Sandbox

| Check | Indicadores |
|-------|-------------|
| **MAC Address** | `00:0c:29` (VMware), `08:00:27` (VBox), `52:54:00` (QEMU) |
| **Processes** | vmtoolsd, vboxservice, qemu-ga |
| **DMI/SMBIOS** | /sys/class/dmi/id/product_name |
| **Username** | sandbox, analyst, malware, cuckoo |
| **Resources** | < 2 CPUs, < 2GB RAM, < 50GB disk |
| **Uptime** | < 2 minutos |

### 4. String Obfuscation

**ANTES (detectável):**
```
$ strings mystealer.exe | grep sandbox
"Sandbox indicators found"
"sandbox", "vmware", "analyst"
```

**DEPOIS (ofuscado):**
```
$ strings mystealer.exe | grep sandbox
(nenhum resultado)
```

#### Técnicas Usadas:

1. **XOR Encoding** - Strings sensíveis encriptadas
```rust
// "sandbox" XOR 0x19 = [0x7a, 0x76, 0x69, 0x75, 0x77, 0x68, 0x63]
fn get_sandbox_string() -> String {
    xd(&[0x7a, 0x76, 0x69, 0x75, 0x77, 0x68, 0x63], 0x19)
}
```

2. **Stack Strings** - Construção char-by-char
```rust
fn build_command() -> String {
    let mut s = String::new();
    s.push('t'); s.push('a'); s.push('s'); s.push('k');
    s.push('l'); s.push('i'); s.push('s'); s.push('t');
    s
}
```

3. **Runtime SQL Building** - Queries montadas em runtime
```rust
fn build_cookies_query() -> String {
    let mut q = String::new();
    for c in ['S','E','L','E','C','T',' '] { q.push(c); }
    // ...
    q
}
```

---

## 🐍 Sistema Hydra (Persistência Multi-Processo)

### Como Funciona

```
    ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
    │   ALPHA     │◄───►│    BETA     │◄───►│   GAMMA     │
    │  (Primary)  │     │  (Backup 1) │     │  (Backup 2) │
    └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
           │                   │                   │
           └───────────────────┼───────────────────┘
                               │
                        ┌──────▼──────┐
                        │  Heartbeat  │
                        │    Files    │
                        │   (.hb)     │
                        └─────────────┘
```

1. **Inicialização**: Primeiro processo torna-se Alpha
2. **Spawn**: Alpha cria Beta e Gamma automaticamente
3. **Heartbeat**: Cada processo envia heartbeat a cada 5s
4. **Monitoramento**: Cada processo monitora os outros
5. **Respawn**: Se um morre, os outros o ressuscitam (~15s)

### Diretórios IPC (Indicators of Compromise)

| OS | Caminho |
|----|---------|
| **Linux** | `~/.cache/fontconfig/` |
| **Windows** | `%LOCALAPPDATA%\.cache\ms-runtime\` |

### Arquivos Criados

```yaml
files:
  - alpha.lock    # PID do processo Alpha
  - alpha.hb      # Timestamp do último heartbeat
  - beta.lock
  - beta.hb
  - gamma.lock
  - gamma.hb
```

### Detecção (Blue Team)

```bash
# Linux - Encontrar processos Hydra
ps aux | grep mystealer
ls -la ~/.cache/fontconfig/*.hb

# Windows - PowerShell
Get-Process | Where-Object { $_.Name -eq "mystealer" }
Get-ChildItem "$env:LOCALAPPDATA\.cache\ms-runtime\"
```

---

## 📦 Estrutura do Projeto

```
mysteellerCTF/
├── src/
│   ├── main.rs                 # Entry point
│   ├── lib.rs                  # Library exports
│   ├── config.rs               # Configuração
│   ├── collectors/             # Módulos de coleta
│   │   ├── mod.rs              # Collector trait
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
│       ├── anti_analysis.rs    # VM/Sandbox/Debugger detection
│       ├── anti_debug.rs       # Anti-debug + Anti-disassembly
│       ├── evasion.rs          # Evasion checks
│       ├── helpers.rs          # Utility functions
│       ├── obfuscated_strings.rs # String obfuscation helpers
│       └── silent_log.rs       # Conditional logging
├── challenges/                 # 6 CTF challenges
├── defenses/                   # Detector de comportamento
├── docs/                       # Documentação técnica
├── lab_environment/            # Docker compose + C2 mock
├── Dockerfile.test             # Build + test Linux
├── Dockerfile.windows          # Cross-compile Windows
└── output/                     # Dados coletados
```

---

## 🚀 Quick Start

### Build Padrão (com logs)
```bash
cargo build --release
./target/release/mystealer --skip-checks
```

### Build Silencioso (sem strings detectáveis)
```bash
cargo build --release --features "hydra-auto,silent"
```

### Cross-Compile para Windows
```bash
# Build via Docker
docker build -f Dockerfile.windows -t mystealer-win .
docker run --rm -v $(pwd)/output:/output mystealer-win \
    sh -c "cp /app/target/x86_64-pc-windows-gnu/release/mystealer.exe /output/"
```

### Verificar Strings no Binário
```bash
# Não deve encontrar nada sensível
strings output/mystealer.exe | grep -iE "sandbox|vmware|analyst|malware"
```

---

## 🔧 Features (Cargo)

| Feature | Descrição |
|---------|-----------|
| `lab-mode` | ✅ Ativo por padrão. Verificações de segurança |
| `hydra` | Sistema de redundância de processos |
| `hydra-auto` | Hydra ativado automaticamente |
| `silent` | Remove logs e strings de debug |

```toml
[features]
default = ["lab-mode"]
lab-mode = []
hydra = []
hydra-auto = []
silent = []
```

---

## 🔐 Criptografia

### Pipeline de Dados

```
Raw JSON → Byte Shuffle → AES-256-GCM → Output File
                ↓               ↓
         Seed: 0xDEADBEEF   Key: Argon2(machine-id)
```

### Técnicas de Ofuscação de Dados

| Técnica | Descrição |
|---------|-----------|
| **XOR Encode** | Chave rotativa multi-byte |
| **UUID Encoding** | Dados parecem UUIDs válidos |
| **Byte Shuffling** | Embaralhamento determinístico |
| **Base64 Encode** | Encoding padrão |
| **Salt Ofuscado** | Construído byte-a-byte |

---

## 📊 Módulos de Coleta

| Módulo | Dados Coletados |
|--------|-----------------|
| `system` | Hostname, username, OS, CPU, RAM, processos |
| `browser` | Cookies, history, login data (Chrome/Firefox/Brave/Edge) |
| `clipboard` | Conteúdo da área de transferência |
| `files` | Arquivos sensíveis (.env, id_rsa, passwords.txt, wallets) |

---

## 🎮 Challenges CTF

| # | Challenge | Descrição | Pontos |
|---|-----------|-----------|--------|
| 1 | [Análise Estática](challenges/CHALLENGE_01.md) | Strings, imports, estrutura | 40 |
| 2 | [Análise Dinâmica](challenges/CHALLENGE_02.md) | Comportamento, syscalls | 60 |
| 3 | [Criptografia](challenges/CHALLENGE_03.md) | Reverter AES, encontrar chave | 80 |
| 4 | [Evasion](challenges/CHALLENGE_04.md) | Anti-VM, Anti-Debug | 100 |
| 5 | [Hydra Persistence](challenges/CHALLENGE_05.md) | Multi-process, IPC | 120 |
| 6 | [String Obfuscation](challenges/CHALLENGE_06.md) | XOR decode, stack strings | 100 |

**Total: 500 pontos**

---

## 🔍 IOCs (Indicators of Compromise)

### Arquivos
```yaml
Linux:
  - ~/.cache/fontconfig/alpha.lock
  - ~/.cache/fontconfig/alpha.hb
  - ~/.cache/fontconfig/beta.lock
  - ~/.cache/fontconfig/beta.hb
  - ~/.cache/fontconfig/gamma.lock
  - ~/.cache/fontconfig/gamma.hb

Windows:
  - %LOCALAPPDATA%\.cache\ms-runtime\alpha.lock
  - %LOCALAPPDATA%\.cache\ms-runtime\*.hb
```

### Comportamento
```yaml
behavior:
  - Múltiplos processos idênticos (3 instâncias)
  - Arquivos .hb atualizados a cada 5 segundos
  - Respawn automático após kill (~15s)
  - Acesso a Cookies/Login Data dos browsers
  - Leitura de /etc/machine-id ou registry MachineGuid
```

### Yara Rule
```yara
rule MyStealer_Hydra {
    meta:
        description = "Detecta MyStealer Hydra System"
        author = "Blue Team CTF"
    
    strings:
        $hydra1 = ".lock" ascii
        $hydra2 = ".hb" ascii
        $path1 = "fontconfig" ascii
        $path2 = "ms-runtime" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($hydra*) and 1 of ($path*))
}
```

---

## 🛠️ Tech Stack

- **Rust 1.75+**
- **tokio** - Async runtime
- **aes-gcm** - AES-256-GCM encryption
- **argon2** - Key derivation
- **rusqlite** - Browser SQLite reading
- **sysinfo** - System information
- **tracing** - Conditional logging
- **clap** - CLI parsing

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

**v0.3 - Stealth Edition** 🔇
