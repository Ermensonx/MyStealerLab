# 🔬 MyStealer CTF Lab v0.2 - Hydra Edition

> **⚠️ EDUCATIONAL PURPOSES ONLY** - Este projeto é exclusivamente para aprendizado em ambientes isolados. Uso indevido é **ILEGAL**.

## Overview

Lab de CTF para estudo de técnicas de infostealers em Rust. Baseado em práticas do [Rust-for-Malware-Development](https://github.com/Whitecat18/Rust-for-Malware-Development) e [Goldberg](https://github.com/frank2/goldberg).

### Features

- **System Info**: hostname, user, OS, CPU, RAM, processos
- **Browser Data**: cookies, history, login data (Chrome, Firefox, Brave, Edge)
- **File Scanner**: busca arquivos sensíveis (.env, id_rsa, passwords.txt, etc)
- **Clipboard**: captura conteúdo atual
- **Anti-Analysis**: detecção de VM, sandbox, debugger
- **Crypto**: AES-256-GCM + XOR + UUID encoding + byte shuffling
- **🐍 Hydra System**: 3 processos redundantes com respawn automático

## 🐍 Sistema Hydra (NOVO!)

O sistema Hydra implementa redundância de processos para persistência:

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
                        └─────────────┘
```

### Como Funciona

1. **Inicialização**: Primeiro processo torna-se Alpha
2. **Spawn**: Alpha spawna Beta e Gamma automaticamente
3. **Heartbeat**: Cada cabeça envia heartbeat a cada 5 segundos
4. **Monitoramento**: Cada cabeça monitora as outras
5. **Respawn**: Se uma cabeça morre, as outras a respawnam em ~15s

### Uso

```bash
# Ativar sistema Hydra
./target/release/mystealer --skip-checks --hydra

# Verificar processos
ps aux | grep mystealer

# Diretório IPC
# Linux: ~/.cache/fontconfig/
# Windows: %LOCALAPPDATA%\.cache\ms-runtime\
```

### IOCs (para Blue Team)

```yaml
files:
  - ~/.cache/fontconfig/alpha.lock
  - ~/.cache/fontconfig/alpha.hb
  - ~/.cache/fontconfig/beta.lock
  - ~/.cache/fontconfig/beta.hb
  - ~/.cache/fontconfig/gamma.lock
  - ~/.cache/fontconfig/gamma.hb
  
behavior:
  - Múltiplos processos idênticos
  - Arquivos .hb atualizados a cada 5s
  - Respawn automático após kill (~15s)
  - Backoff exponencial em falhas repetidas
```

## Quick Start

### Linux
```bash
# Build
cargo build --release

# Run (lab mode)
./target/release/mystealer --output-dir ./output

# Com Hydra (3 processos redundantes)
./target/release/mystealer --skip-checks --hydra

# Com verificações desabilitadas
./target/release/mystealer --skip-checks
```

### Windows (cross-compile)
```bash
# Build via Docker
docker build -f Dockerfile.windows -t mystealer-win .
docker run --rm -v $(pwd)/output:/output mystealer-win \
    sh -c "cp /app/target/x86_64-pc-windows-gnu/release/mystealer.exe /output/"

# Executar na VM Windows
mystealer.exe --skip-checks --output-dir .\output

# Com Hydra
mystealer.exe --skip-checks --hydra
```

### Docker (teste isolado)
```bash
docker build -f Dockerfile.test -t mystealer-test .
docker run --rm -v $(pwd)/output:/app/output mystealer-test
```

## Estrutura

```
mysteellerCTF/
├── src/
│   ├── main.rs              # Entry point
│   ├── lib.rs               # Library exports
│   ├── config.rs            # Configuração
│   ├── collectors/          # Módulos de coleta
│   │   ├── browser.rs       # Chrome, Firefox, etc (SQLite)
│   │   ├── clipboard.rs     # Área de transferência
│   │   ├── files.rs         # Scanner de arquivos sensíveis
│   │   └── system_info.rs   # Info do sistema
│   ├── crypto/
│   │   ├── mod.rs           # AES-256-GCM + obfuscation
│   │   └── aes.rs           # Funções auxiliares
│   ├── exfil/
│   │   ├── http.rs          # Exfil via HTTP
│   │   └── local.rs         # Salvar local
│   ├── loader/              # 🆕 Sistema Hydra
│   │   ├── mod.rs           # Orquestrador
│   │   ├── hydra.rs         # Redundância multi-processo
│   │   └── watchdog.rs      # Monitor de integridade
│   └── utils/
│       ├── anti_analysis.rs # VM/Sandbox/Debugger detection
│       └── helpers.rs       # Funções auxiliares
├── challenges/              # Desafios CTF (5 challenges)
├── defenses/                # Detector de comportamento
├── lab_environment/         # Docker compose + C2 mock
├── Dockerfile.test          # Build + test Linux
├── Dockerfile.windows       # Cross-compile Windows
└── output/                  # Dados coletados
```

## Módulos

| Módulo | Descrição |
|--------|-----------|
| `system` | Hostname, user, OS, CPU, RAM, processos |
| `browser` | Cookies, history, passwords (Chrome/Firefox/Brave/Edge) |
| `clipboard` | Conteúdo da área de transferência |
| `files` | Arquivos sensíveis (.env, keys, passwords, wallets) |
| `loader` 🆕 | Sistema Hydra de redundância |

## Anti-Analysis

- **VM Detection**: DMI, MAC address, processos, CPUID
- **Sandbox Detection**: usernames típicos, uptime baixo, poucos processos
- **Debugger Detection**: TracerPid (Linux), IsDebuggerPresent (Windows)
- **Timing Check**: detecta single-stepping/emulação

## Obfuscation Techniques 🆕

- **XOR encoding**: Chave rotativa com transformação
- **Multi-XOR**: Múltiplas camadas de XOR
- **UUID encoding**: Dados parecem UUIDs válidos
- **Byte shuffling**: Embaralhamento determinístico com seed
- **Salt ofuscado**: Construído byte a byte (evita strings)

## Output

```json
{
  "timestamp": "2025-12-17T21:38:14Z",
  "session_id": "524c7173-a404-4496-ac95-9c17bbe842ff",
  "modules": {
    "system": { "hostname": "...", "username": "...", ... },
    "browser": { "browsers_found": ["Chrome", "Firefox"], ... },
    "files": { "found_files": [{ "path": "/root/.ssh/id_rsa", ... }] },
    "clipboard": { "current_text": "..." }
  }
}
```

Dados são criptografados com AES-256-GCM (chave derivada do machine-id).

## CLI Options

```
Usage: mystealer [OPTIONS]

Options:
      --lab-mode                 Modo laboratório (default: true)
  -l, --log-level <LEVEL>        trace|debug|info|warn|error [default: info]
  -o, --output-dir <DIR>         Diretório de saída [default: ./output]
  -m, --modules <MODULES>        Módulos separados por vírgula [default: system,browser,clipboard,files]
      --skip-checks              Pular verificações de ambiente
      --hydra                    🆕 Ativar sistema Hydra (3 processos)
  -h, --help                     Ajuda
  -V, --version                  Versão
```

## Challenges

| Challenge | Descrição | Pontos |
|-----------|-----------|--------|
| [CHALLENGE_01](challenges/CHALLENGE_01.md) | Análise estática básica | 40 |
| [CHALLENGE_02](challenges/CHALLENGE_02.md) | Análise dinâmica | 60 |
| [CHALLENGE_03](challenges/CHALLENGE_03.md) | Criptografia | 80 |
| [CHALLENGE_04](challenges/CHALLENGE_04.md) | Evasion | 100 |
| [CHALLENGE_05](challenges/CHALLENGE_05.md) 🆕 | Hydra Persistence | 120 |

**Total: 400 pontos**

## Tech Stack

- **Rust 1.75+**
- **rusqlite** - Browser SQLite
- **aes-gcm** - Criptografia
- **sysinfo** - System info
- **tokio** - Async runtime
- **tracing** - Logging
- **goldberg** 🆕 - Code obfuscation
- **obfstr** 🆕 - String obfuscation

## Legal

Este software é fornecido "como está" apenas para fins educacionais. 

**Ao usar, você concorda que:**
- Usará apenas em ambientes controlados de sua propriedade
- Não usará para atividades maliciosas ou ilegais
- Compreende as leis locais sobre segurança cibernética

**MIT License** - Educational purposes only.

---

*Built for security research and education* 🛡️

**v0.2 - Hydra Edition** 🐍
