# 🎯 Desafio 04: Defesa e Detecção

## Objetivo

Desenvolva ferramentas de defesa para detectar e bloquear o infostealer.

## Contexto

Agora que você entende como o malware funciona, é hora de desenvolver contramedidas. Este desafio foca no lado defensivo da segurança.

## Tarefas

### Tarefa 1: Regras YARA (25 pts)

Crie regras YARA para detectar o malware:

```yara
// mystealer.yar
rule MyStealer_Detector {
    meta:
        description = "Detecta MyStealer CTF Lab"
        author = "Seu Nome"
        date = "2024-01-01"
        
    strings:
        // Adicione strings identificadoras
        $s1 = "???"
        $s2 = "???"
        
        // Padrões hexadecimais
        $hex1 = { ?? ?? ?? }
        
    condition:
        // Sua condição aqui
        ???
}
```

Sua regra deve:
- Detectar o binário compilado
- Ter baixa taxa de falso positivo
- Detectar variantes com strings ofuscadas

**FLAG**: Hash SHA256 da sua regra YARA

### Tarefa 2: Script de Detecção (25 pts)

Crie um script que detecte comportamento do malware em runtime:

```python
#!/usr/bin/env python3
"""
detector.py - Detecta comportamento de infostealer
"""

import os
import psutil
import time

def check_suspicious_file_access():
    """Monitora acesso a arquivos sensíveis"""
    sensitive_paths = [
        ".config/google-chrome",
        ".mozilla/firefox",
        ".ssh",
        "Cookies",
        "Login Data",
    ]
    # Implementar monitoramento
    pass

def check_suspicious_network():
    """Detecta conexões suspeitas"""
    # Implementar
    pass

def check_suspicious_process():
    """Detecta processos suspeitos"""
    # Implementar
    pass

if __name__ == "__main__":
    while True:
        check_suspicious_file_access()
        check_suspicious_network()
        check_suspicious_process()
        time.sleep(1)
```

**FLAG**: Capture 3 indicadores de compromisso: `CTF{ioc1_ioc2_ioc3}`

### Tarefa 3: Honeypot de Credenciais (25 pts)

Crie arquivos "honeypot" que alertam quando acessados:

```bash
#!/bin/bash
# honeypot_setup.sh

# Criar arquivos falsos
mkdir -p ~/.config/chrome-fake/
echo "user:password123" > ~/.config/chrome-fake/Login\ Data

# Monitorar acesso com inotify
inotifywait -m -e access ~/.config/chrome-fake/ | while read line; do
    echo "[ALERT] Honeypot accessed: $line"
    # Notificar, logar, etc
done
```

Implemente:
1. Criação de arquivos honeypot
2. Monitoramento de acesso
3. Alertas/Notificações

**FLAG**: Timestamp do primeiro alerta: `CTF{timestamp}`

### Tarefa 4: Ferramenta de Limpeza (25 pts)

Desenvolva uma ferramenta que:
1. Detecta artefatos do malware
2. Remove persistência
3. Limpa dados exfiltrados do sistema

```rust
// defenses/cleaner/src/main.rs

fn detect_artifacts() -> Vec<String> {
    // Buscar arquivos do malware
    // Buscar chaves de registro (Windows)
    // Buscar cron jobs (Linux)
    vec![]
}

fn remove_persistence() {
    // Remover persistência
}

fn cleanup() {
    // Limpar artefatos
}

fn main() {
    println!("🧹 MyStealer Cleaner");
    
    let artifacts = detect_artifacts();
    println!("Encontrados {} artefatos", artifacts.len());
    
    // Implementar lógica de limpeza
}
```

**FLAG**: Número de artefatos removidos: `CTF{numero}`

## Tarefas Bônus

### Bônus 1: EDR Simulator (20 pts extra)

Crie um mini-EDR que:
- Monitora processos em tempo real
- Detecta injeção de código
- Bloqueia comportamento malicioso

### Bônus 2: Threat Intelligence (15 pts extra)

Extraia IOCs do malware e crie:
- Lista de hashes
- Lista de IPs/Domínios
- Lista de TTPs (MITRE ATT&CK)

## Ferramentas Recomendadas

- `yara` - Pattern matching
- `inotify-tools` - Monitoramento de arquivos
- `auditd` - Auditoria de sistema
- `osquery` - Queries de sistema
- `sysdig` - Monitoramento de containers

## Dicas

1. Pense como defensor: o que o malware deixa para trás?
2. Use múltiplas camadas de detecção
3. Balance entre detecção e performance
4. Documente todos os IOCs encontrados

## Solução

<details>
<summary>Clique para ver as respostas (SPOILER)</summary>

### Tarefa 1 - YARA
```yara
rule MyStealer {
    strings:
        $s1 = "mystealer" nocase
        $s2 = "CTF LAB"
        $s3 = "lab-mode"
        $url = /http:\/\/localhost:\d+\/collect/
        
    condition:
        2 of them
}
```

### Tarefa 2 - Detector
IOCs típicos:
- Acesso a `~/.config/google-chrome/Default/Login Data`
- Conexão para porta 8080
- Processo com nome suspeito

FLAG: `CTF{browserdata_port8080_mystealer}`

### Tarefa 3 - Honeypot
Varia por execução

### Tarefa 4 - Cleaner
Artefatos típicos:
- /tmp/.mystealer_lab
- ~/.config/mystealer/
- Logs em /app/data

</details>

---

**Pontuação Total**: 100 pontos (+35 bônus)
**Dificuldade**: ⭐⭐⭐ Difícil

---

## 🏆 Ranking Final

| Desafio | Pontos | Dificuldade |
|---------|--------|-------------|
| 01 - Análise Básica | 40 | ⭐ |
| 02 - Análise Dinâmica | 70 | ⭐⭐ |
| 03 - Engenharia Reversa | 100 | ⭐⭐⭐ |
| 04 - Defesa e Detecção | 100 (+35) | ⭐⭐⭐ |
| **TOTAL** | **310 (+35)** | |

**Parabéns por completar o MyStealer CTF Lab!** 🎉

