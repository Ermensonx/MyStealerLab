# 🔬 MyStealer CTF Lab

> **⚠️ AVISO IMPORTANTE**: Este projeto é **EXCLUSIVAMENTE PARA FINS EDUCACIONAIS** em ambientes controlados de laboratório. O uso indevido de técnicas de infostealer é **ILEGAL** e pode resultar em sérias consequências legais. Use apenas em máquinas virtuais e ambientes isolados de sua propriedade.

## 📋 Visão Geral

Este laboratório de CTF foi desenvolvido para ensinar os fundamentos de:
- Programação em Rust para segurança ofensiva
- Técnicas de coleta de informações em sistemas Windows/Linux
- Análise de malware e engenharia reversa
- Desenvolvimento de contramedidas defensivas

## 🎯 Objetivos Educacionais

1. Compreender como infostealers funcionam internamente
2. Aprender técnicas de programação segura em Rust
3. Desenvolver habilidades de análise de malware
4. Criar ferramentas de detecção e prevenção

## 🏗️ Arquitetura do Projeto

```
mysteellerCTF/
├── docs/                    # Documentação completa
│   ├── ARCHITECTURE.md      # Arquitetura técnica
│   ├── MODULES.md           # Descrição dos módulos
│   ├── SETUP.md             # Configuração do ambiente
│   └── TECHNIQUES.md        # Técnicas utilizadas
├── src/                     # Código fonte
│   ├── main.rs              # Entry point
│   ├── lib.rs               # Biblioteca principal
│   ├── collectors/          # Módulos de coleta
│   ├── crypto/              # Criptografia
│   ├── exfil/               # Exfiltração (simulada)
│   └── utils/               # Utilitários
├── lab_environment/         # Ambiente de laboratório
│   ├── docker-compose.yml   # Infra do lab
│   └── vm_setup/            # Scripts de VMs
├── defenses/                # Ferramentas de defesa
│   └── detector/            # Detector de comportamento
├── challenges/              # Desafios CTF
├── Cargo.toml               # Dependências Rust
└── README.md
```

## 🛠️ Stack Tecnológico

- **Linguagem**: Rust 1.75+
- **SO Alvo**: Windows 10/11 (principal), Linux (secundário)
- **Ambiente Lab**: Docker, VirtualBox/VMware
- **Ferramentas**: Cargo, Clippy, LLVM

## 🚀 Quick Start

```bash
# Clone o repositório
git clone <repo-url>
cd mysteellerCTF

# Configure o ambiente de lab (ver docs/SETUP.md)
./scripts/setup_lab.sh

# Compile o projeto
cargo build --release

# Execute em ambiente controlado APENAS
./target/release/mystealer --lab-mode
```

## 📚 Documentação

| Documento | Descrição |
|-----------|-----------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Arquitetura técnica detalhada |
| [MODULES.md](docs/MODULES.md) | Descrição de cada módulo |
| [SETUP.md](docs/SETUP.md) | Configuração do ambiente |
| [TECHNIQUES.md](docs/TECHNIQUES.md) | Técnicas e TTPs utilizados |

## ⚖️ Disclaimer Legal

Este software é fornecido **"como está"** apenas para fins educacionais e de pesquisa em segurança da informação. Os autores não se responsabilizam por qualquer uso indevido ou ilegal deste código.

**Ao usar este projeto, você concorda que:**
- Utilizará apenas em ambientes controlados de sua propriedade
- Não usará para atividades maliciosas ou ilegais
- Compreende as leis locais sobre segurança cibernética
- Assume total responsabilidade pelo uso do código

## 📝 Licença

MIT License - Apenas para fins educacionais.

---

*Desenvolvido para fins de aprendizado em segurança cibernética* 🛡️

