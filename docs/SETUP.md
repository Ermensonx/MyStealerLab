# 🔧 Setup do Ambiente - MyStealer CTF Lab

## Pré-requisitos

### Sistema Host

- **OS**: Linux (Ubuntu 22.04+) ou Windows 10/11
- **RAM**: Mínimo 16GB (32GB recomendado)
- **Disco**: 100GB+ livres
- **CPU**: 4+ cores

### Software Necessário

- [Rust](https://rustup.rs/) 1.75+
- [Docker](https://docker.com/) & Docker Compose
- [VirtualBox](https://www.virtualbox.org/) ou VMware
- [Git](https://git-scm.com/)

---

## 1. Instalação do Rust

```bash
# Instalar Rust via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Selecionar instalação padrão
# Depois recarregar o shell
source $HOME/.cargo/env

# Verificar instalação
rustc --version
cargo --version

# Adicionar targets para cross-compilation
rustup target add x86_64-pc-windows-gnu
rustup target add x86_64-unknown-linux-gnu

# Instalar ferramentas úteis
cargo install cargo-watch cargo-edit cargo-audit
```

---

## 2. Configuração do Projeto

```bash
# Clonar o repositório
git clone <repo-url> mysteellerCTF
cd mysteellerCTF

# Inicializar projeto Rust
cargo init

# Verificar compilação
cargo build
```

---

## 3. Ambiente de Laboratório Isolado

### 3.1 Opção A: Docker (Recomendado para Testes Rápidos)

```yaml
# docker-compose.yml
version: '3.8'

services:
  # Servidor C2 simulado
  mock-c2:
    image: python:3.11-slim
    container_name: mock-c2-server
    command: python -m http.server 8080
    ports:
      - "8080:8080"
    volumes:
      - ./exfil_data:/data
    networks:
      - lab-network

  # Container de build Rust
  rust-builder:
    image: rust:1.75
    container_name: rust-builder
    volumes:
      - .:/app
      - cargo-cache:/usr/local/cargo/registry
    working_dir: /app
    command: cargo build --release
    networks:
      - lab-network

  # Ambiente Linux para testes
  linux-target:
    image: ubuntu:22.04
    container_name: linux-target
    volumes:
      - ./target/release:/malware:ro
    networks:
      - lab-network
    tty: true
    stdin_open: true

networks:
  lab-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16

volumes:
  cargo-cache:
```

```bash
# Iniciar ambiente
docker-compose up -d

# Compilar
docker-compose run rust-builder

# Acessar target
docker-compose exec linux-target bash
```

### 3.2 Opção B: Máquinas Virtuais (Recomendado para Testes Completos)

#### VM Windows 10 (Target Principal)

```bash
# Baixar ISO de desenvolvimento do Windows
# https://developer.microsoft.com/windows/downloads/virtual-machines/

# Criar VM no VirtualBox
VBoxManage createvm --name "Win10-Target" --ostype Windows10_64 --register

VBoxManage modifyvm "Win10-Target" \
    --memory 4096 \
    --cpus 2 \
    --vram 128 \
    --nic1 intnet \
    --intnet1 "lab-network"

# Adicionar disco
VBoxManage createhd --filename "Win10-Target.vdi" --size 50000
VBoxManage storagectl "Win10-Target" --name "SATA" --add sata
VBoxManage storageattach "Win10-Target" --storagectl "SATA" \
    --port 0 --device 0 --type hdd --medium "Win10-Target.vdi"
```

#### Configurações de Segurança da VM

```powershell
# Desabilitar Windows Defender (apenas para lab!)
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableIOAVProtection $true

# Criar usuário de teste
net user testuser Password123! /add
net localgroup Administrators testuser /add
```

#### VM Linux (Target Secundário)

```bash
# Usar Ubuntu Server 22.04
VBoxManage createvm --name "Ubuntu-Target" --ostype Ubuntu_64 --register

VBoxManage modifyvm "Ubuntu-Target" \
    --memory 2048 \
    --cpus 2 \
    --nic1 intnet \
    --intnet1 "lab-network"
```

---

## 4. Estrutura de Diretórios

Crie a seguinte estrutura:

```bash
mkdir -p src/{collectors,crypto,exfil,utils}
mkdir -p lab_environment/{docker,vm_setup,scripts}
mkdir -p defenses/detector
mkdir -p challenges
mkdir -p docs
```

```
mysteellerCTF/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── MODULES.md
│   ├── TECHNIQUES.md
│   └── SETUP.md
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── config.rs
│   ├── collectors/
│   │   ├── mod.rs
│   │   ├── system_info.rs
│   │   ├── browser.rs
│   │   ├── clipboard.rs
│   │   ├── files.rs
│   │   ├── credentials.rs
│   │   └── network.rs
│   ├── crypto/
│   │   ├── mod.rs
│   │   ├── aes.rs
│   │   └── obfuscation.rs
│   ├── exfil/
│   │   ├── mod.rs
│   │   ├── http.rs
│   │   ├── local.rs
│   │   └── dns.rs
│   └── utils/
│       ├── mod.rs
│       ├── anti_analysis.rs
│       └── helpers.rs
├── lab_environment/
│   ├── docker-compose.yml
│   ├── Dockerfile
│   └── vm_setup/
│       ├── setup_windows.ps1
│       └── setup_linux.sh
├── defenses/
│   └── detector/
│       ├── Cargo.toml
│       └── src/
└── challenges/
    ├── challenge_01.md
    ├── challenge_02.md
    └── challenge_03.md
```

---

## 5. Cargo.toml

```toml
[package]
name = "mystealer"
version = "0.1.0"
edition = "2021"
authors = ["CTF Lab"]
description = "Educational infostealer for CTF lab"

[features]
default = ["lab-mode"]
lab-mode = []  # Ativa verificações de segurança
release = []   # Remove verificações (NUNCA usar fora do lab)

[dependencies]
# Async runtime
tokio = { version = "1.35", features = ["full"] }

# Serialização
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Criptografia
aes-gcm = "0.10"
argon2 = "0.5"
rand = "0.8"
base64 = "0.21"
base32 = "0.4"

# Data e tempo
chrono = { version = "0.4", features = ["serde"] }

# Identificadores
uuid = { version = "1.6", features = ["v4", "serde"] }

# Erros
thiserror = "1.0"
anyhow = "1.0"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# HTTP
reqwest = { version = "0.11", features = ["json", "rustls-tls"] }

# Diretórios do sistema
dirs = "5.0"

# Informações do sistema
sysinfo = "0.30"
whoami = "1.4"

# Regex para busca de arquivos
regex = "1.10"
walkdir = "2.4"

# Hash
sha2 = "0.10"

[target.'cfg(windows)'.dependencies]
windows = { version = "0.52", features = [
    "Win32_Foundation",
    "Win32_Security",
    "Win32_Security_Credentials",
    "Win32_System_Threading",
    "Win32_System_SystemInformation",
    "Win32_System_Registry",
    "Win32_System_DataExchange",
    "Win32_System_Memory",
    "Win32_System_Diagnostics_Debug",
    "Win32_UI_WindowsAndMessaging",
    "Win32_Networking_WinSock",
]}

[target.'cfg(unix)'.dependencies]
nix = { version = "0.27", features = ["user", "process"] }

[dev-dependencies]
tempfile = "3.9"
mockall = "0.12"

[profile.release]
lto = true
codegen-units = 1
panic = "abort"
strip = true
opt-level = "z"  # Otimizar para tamanho

[profile.dev]
debug = true
opt-level = 0
```

---

## 6. Scripts de Setup

### setup_lab.sh

```bash
#!/bin/bash

# Script de configuração do laboratório

set -e

echo "🔬 MyStealer CTF Lab - Setup Script"
echo "===================================="

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Verificar se está em ambiente de lab
check_lab_environment() {
    echo -e "${YELLOW}[*] Verificando ambiente de laboratório...${NC}"
    
    # Verificar se está em VM
    if systemd-detect-virt -q 2>/dev/null; then
        echo -e "${GREEN}[✓] Executando em ambiente virtualizado${NC}"
    else
        echo -e "${RED}[!] AVISO: Não detectado ambiente virtual${NC}"
        echo -e "${RED}[!] Este software deve ser executado APENAS em VMs isoladas${NC}"
        read -p "Continuar mesmo assim? (s/N): " confirm
        if [[ $confirm != [sS] ]]; then
            exit 1
        fi
    fi
}

# Instalar dependências
install_dependencies() {
    echo -e "${YELLOW}[*] Instalando dependências...${NC}"
    
    # Rust
    if ! command -v rustc &> /dev/null; then
        echo -e "${YELLOW}[*] Instalando Rust...${NC}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source $HOME/.cargo/env
    fi
    
    # Docker
    if ! command -v docker &> /dev/null; then
        echo -e "${YELLOW}[*] Docker não encontrado. Instale manualmente.${NC}"
    fi
    
    echo -e "${GREEN}[✓] Dependências instaladas${NC}"
}

# Criar estrutura de diretórios
create_structure() {
    echo -e "${YELLOW}[*] Criando estrutura de diretórios...${NC}"
    
    mkdir -p src/{collectors,crypto,exfil,utils}
    mkdir -p lab_environment/{docker,vm_setup,scripts}
    mkdir -p defenses/detector/src
    mkdir -p challenges
    mkdir -p target
    mkdir -p exfil_data
    
    echo -e "${GREEN}[✓] Estrutura criada${NC}"
}

# Configurar rede isolada
setup_network() {
    echo -e "${YELLOW}[*] Configurando rede isolada...${NC}"
    
    # Criar rede Docker
    docker network create --driver bridge \
        --subnet 172.28.0.0/16 \
        lab-network 2>/dev/null || true
    
    echo -e "${GREEN}[✓] Rede configurada${NC}"
}

# Compilar projeto
build_project() {
    echo -e "${YELLOW}[*] Compilando projeto...${NC}"
    
    cargo build --features lab-mode
    
    echo -e "${GREEN}[✓] Projeto compilado${NC}"
}

# Main
main() {
    check_lab_environment
    install_dependencies
    create_structure
    
    if command -v docker &> /dev/null; then
        setup_network
    fi
    
    build_project
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}[✓] Setup completo!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Próximos passos:"
    echo "  1. Revise a documentação em docs/"
    echo "  2. Configure as VMs de teste"
    echo "  3. Execute: cargo run --features lab-mode"
    echo ""
    echo -e "${YELLOW}⚠️  Use APENAS em ambiente controlado!${NC}"
}

main "$@"
```

```bash
# Tornar executável
chmod +x lab_environment/scripts/setup_lab.sh
```

---

## 7. Verificação Final

```bash
# Verificar Rust
rustc --version  # Deve ser 1.75+

# Verificar projeto
cargo check

# Rodar testes
cargo test

# Compilar em modo lab
cargo build --features lab-mode

# Verificar dependências por vulnerabilidades
cargo audit
```

---

## 8. Próximos Passos

1. ✅ Ambiente configurado
2. 📝 Ler a documentação de arquitetura
3. 🖥️ Configurar VMs de teste
4. 🔨 Começar a implementar os módulos
5. 🧪 Testar em ambiente isolado

---

## ⚠️ Lembrete de Segurança

- **NUNCA** execute este código em sistemas reais
- **SEMPRE** use VMs isoladas e snapshots
- **MANTENHA** o firewall ativo no host
- **DOCUMENTE** todos os testes realizados
- **DESTRUA** as VMs após os testes

---

*Happy Hacking! 🛡️*

