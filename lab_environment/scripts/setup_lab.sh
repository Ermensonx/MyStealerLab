#!/bin/bash
# ============================================
# MyStealer CTF Lab - Setup Script
# ============================================
# Este script configura o ambiente de laboratório
# Execute: chmod +x setup_lab.sh && ./setup_lab.sh

set -e

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║   ███╗   ███╗██╗   ██╗███████╗████████╗███████╗ █████╗ ██╗   ║"
    echo "║   ████╗ ████║╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗██║   ║"
    echo "║   ██╔████╔██║ ╚████╔╝ ███████╗   ██║   █████╗  ███████║██║   ║"
    echo "║   ██║╚██╔╝██║  ╚██╔╝  ╚════██║   ██║   ██╔══╝  ██╔══██║██║   ║"
    echo "║   ██║ ╚═╝ ██║   ██║   ███████║   ██║   ███████╗██║  ██║███████╗"
    echo "║   ╚═╝     ╚═╝   ╚═╝   ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝"
    echo "║                                                              ║"
    echo "║                    CTF LAB - Setup Script                    ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Verificar ambiente
check_environment() {
    log_info "Verificando ambiente..."
    
    # Verificar se é VM (recomendado)
    if command -v systemd-detect-virt &> /dev/null; then
        VIRT=$(systemd-detect-virt 2>/dev/null || echo "none")
        if [ "$VIRT" != "none" ]; then
            log_success "Ambiente virtualizado detectado: $VIRT"
        else
            log_warning "Não parece ser ambiente virtualizado"
            log_warning "Recomendado usar VMs para este laboratório!"
            read -p "Continuar mesmo assim? (s/N): " confirm
            if [[ ! $confirm =~ ^[sS]$ ]]; then
                log_error "Abortado pelo usuário"
                exit 1
            fi
        fi
    fi
    
    # Verificar SO
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        log_success "Sistema operacional: Linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        log_success "Sistema operacional: macOS"
    else
        log_warning "Sistema operacional: $OSTYPE (pode haver problemas)"
    fi
}

# Verificar dependências
check_dependencies() {
    log_info "Verificando dependências..."
    
    local missing=()
    
    # Rust
    if ! command -v rustc &> /dev/null; then
        missing+=("rust")
    else
        RUST_VERSION=$(rustc --version | cut -d' ' -f2)
        log_success "Rust instalado: $RUST_VERSION"
    fi
    
    # Cargo
    if ! command -v cargo &> /dev/null; then
        missing+=("cargo")
    else
        log_success "Cargo disponível"
    fi
    
    # Docker (opcional)
    if ! command -v docker &> /dev/null; then
        log_warning "Docker não encontrado (opcional, mas recomendado)"
    else
        log_success "Docker disponível"
    fi
    
    # Git
    if ! command -v git &> /dev/null; then
        missing+=("git")
    else
        log_success "Git disponível"
    fi
    
    # Se faltar dependências obrigatórias
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Dependências faltando: ${missing[*]}"
        log_info "Instalando dependências..."
        install_dependencies
    fi
}

# Instalar dependências
install_dependencies() {
    log_info "Instalando dependências do sistema..."
    
    # Rust
    if ! command -v rustc &> /dev/null; then
        log_info "Instalando Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
        log_success "Rust instalado"
    fi
    
    # Ferramentas extras
    log_info "Instalando ferramentas Rust..."
    rustup component add clippy rustfmt 2>/dev/null || true
    cargo install cargo-audit 2>/dev/null || true
    
    log_success "Dependências instaladas"
}

# Criar estrutura de diretórios
create_structure() {
    log_info "Criando estrutura de diretórios..."
    
    # Voltar ao diretório raiz do projeto
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
    cd "$PROJECT_ROOT"
    
    # Criar diretórios
    mkdir -p src/{collectors,crypto,exfil,utils}
    mkdir -p lab_environment/{docker,scripts,dns,exfil_data,logs,captures,target_data}
    mkdir -p defenses/detector/src
    mkdir -p challenges
    mkdir -p output
    mkdir -p docs
    
    # Criar arquivo marcador de lab
    touch /tmp/.mystealer_lab 2>/dev/null || true
    
    # Arquivo de DNS para Docker
    cat > lab_environment/dns/Corefile << 'EOF'
. {
    forward . 8.8.8.8 8.8.4.4
    log
    errors
}

lab.local {
    file /zones/lab.local.zone
    log
}
EOF

    cat > lab_environment/dns/zones/lab.local.zone << 'EOF'
$ORIGIN lab.local.
@       3600    IN      SOA     ns.lab.local. admin.lab.local. (
                                2024010101
                                3600
                                1800
                                604800
                                86400 )
@       3600    IN      NS      ns.lab.local.
ns      3600    IN      A       172.28.1.30
c2      3600    IN      A       172.28.1.10
target  3600    IN      A       172.28.1.20
EOF

    log_success "Estrutura de diretórios criada"
}

# Compilar projeto
build_project() {
    log_info "Compilando projeto..."
    
    cd "$PROJECT_ROOT"
    
    # Check de código
    cargo check 2>&1 | head -20
    
    if [ $? -eq 0 ]; then
        log_success "Verificação de código passou"
        
        # Build em modo lab
        log_info "Compilando em modo laboratório..."
        cargo build --features lab-mode 2>&1 | tail -5
        
        if [ $? -eq 0 ]; then
            log_success "Projeto compilado com sucesso!"
        else
            log_error "Falha na compilação"
            exit 1
        fi
    else
        log_error "Erros no código - verifique e corrija"
        exit 1
    fi
}

# Configurar Docker
setup_docker() {
    if command -v docker &> /dev/null; then
        log_info "Configurando ambiente Docker..."
        
        cd "$PROJECT_ROOT/lab_environment"
        
        # Criar rede se não existir
        docker network create lab-network 2>/dev/null || true
        
        # Build das imagens
        log_info "Construindo imagens Docker..."
        docker-compose build 2>&1 | tail -10
        
        log_success "Ambiente Docker configurado"
        log_info "Para iniciar: cd lab_environment && docker-compose up -d"
    else
        log_warning "Docker não disponível - pulando configuração"
    fi
}

# Exibir próximos passos
show_next_steps() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    SETUP COMPLETO! 🎉                        ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Próximos passos:${NC}"
    echo ""
    echo "  1. 📖 Leia a documentação:"
    echo "     cat docs/README.md"
    echo ""
    echo "  2. 🐳 Inicie o ambiente Docker (opcional):"
    echo "     cd lab_environment && docker-compose up -d"
    echo ""
    echo "  3. 🔨 Execute o projeto:"
    echo "     cargo run --features lab-mode -- --help"
    echo ""
    echo "  4. 🧪 Execute em modo lab:"
    echo "     MYSTEALER_LAB_MODE=1 cargo run --features lab-mode"
    echo ""
    echo "  5. 📚 Resolva os desafios CTF:"
    echo "     ls challenges/"
    echo ""
    echo -e "${YELLOW}⚠️  LEMBRETE: Use APENAS em ambientes controlados!${NC}"
    echo ""
}

# Main
main() {
    print_banner
    
    echo ""
    log_info "Iniciando configuração do laboratório..."
    echo ""
    
    check_environment
    check_dependencies
    create_structure
    build_project
    setup_docker
    
    show_next_steps
}

# Executar
main "$@"

