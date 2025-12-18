# 🛡️ Desafio 04: Defesa e Detecção

**Dificuldade**: ⭐⭐⭐ Difícil  
**Pontos**: 100 (+35 bônus)  
**Versão**: v0.3.1 (Stealth Edition)

---

## ⚠️ Nota sobre Ofuscação

Na versão 0.3.1, o MyStealer usa **ofuscação completa de strings**. Isso significa que regras de detecção baseadas em strings **não funcionam**. Este challenge foi atualizado para ensinar técnicas de detecção **comportamental** e **estrutural**.

---

## Objetivo

Desenvolva ferramentas de defesa para detectar e bloquear o infostealer ofuscado.

## Contexto

Você já entende como o malware funciona. Agora precisa desenvolver contramedidas que funcionem **mesmo com ofuscação**.

---

## Tarefas

### Tarefa 1: Regras YARA Estruturais (25 pts)

⚠️ **Desafio**: Strings como "Chrome", "Firefox", "mystealer" **NÃO EXISTEM** no binário!

Crie regras YARA baseadas em:
- **Estrutura do binário** (headers, seções)
- **Padrões de bytecode** (não strings)
- **Comportamento do código** (sequências de instruções)

```yara
// mystealer_v031.yar
rule MyStealer_Behavioral {
    meta:
        description = "Detecta MyStealer v0.3.1 via padrões estruturais"
        author = "Seu Nome"
        date = "2024-12-17"
        
    strings:
        // Padrões de bytecode do loop bs()
        // Procure por: mov + push + cmp + jne (padrão de loop de caracteres)
        $bs_pattern = { 
            48 89 ??              // mov reg, reg
            E8 ?? ?? ?? ??        // call String::push
            48 83 ?? 01           // add/inc
            48 39 ??              // cmp
            75 ??                 // jne (loop)
        }
        
        // Padrões de heartbeat IPC
        $hb_ext = ".hb"
        $lock_ext = ".lock"
        
        // Padrões de diretório Hydra (estes PODEM aparecer)
        $fontconfig = "fontconfig"
        $ms_runtime = "ms-runtime"
        
        // Padrões de criptografia AES-GCM
        $aes_sbox = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b }
        
    condition:
        uint16(0) == 0x5A4D and (  // PE header
            $bs_pattern or
            (2 of ($hb_ext, $lock_ext, $fontconfig, $ms_runtime)) or
            $aes_sbox
        )
}

rule MyStealer_Hydra_Files {
    meta:
        description = "Detecta arquivos IPC do sistema Hydra"
        
    strings:
        $hb_format = /[0-9]+:[0-9]+/  // PID:timestamp
        
    condition:
        filesize < 100 and $hb_format
}
```

**Tarefa**: Crie pelo menos 2 regras YARA que detectem o binário **sem usar strings ofuscadas**.

**FLAG**: Hash SHA256 da sua melhor regra YARA

---

### Tarefa 2: Detecção Comportamental (25 pts)

Crie um script que detecte o malware pelo **comportamento**, não por assinaturas:

```python
#!/usr/bin/env python3
"""
detector_behavioral.py - Detecta MyStealer v0.3.1 via comportamento
"""

import os
import psutil
import time
from pathlib import Path
from collections import defaultdict

class StealerDetector:
    def __init__(self):
        self.alerts = []
        
    def check_browser_db_access(self):
        """
        Detecta processos acessando databases de browsers.
        MyStealer acessa: Cookies, Login Data, History
        """
        browser_dbs = [
            "Cookies",
            "Login Data", 
            "History",
            "cookies.sqlite",
            "logins.json",
            "places.sqlite",
        ]
        
        for proc in psutil.process_iter(['pid', 'name', 'open_files']):
            try:
                files = proc.info.get('open_files') or []
                for f in files:
                    for db in browser_dbs:
                        if db in f.path:
                            self.alerts.append({
                                'type': 'BROWSER_DB_ACCESS',
                                'pid': proc.info['pid'],
                                'process': proc.info['name'],
                                'file': f.path
                            })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        return len(self.alerts) > 0
    
    def check_hydra_pattern(self):
        """
        Detecta padrão Hydra: múltiplos processos idênticos
        """
        process_count = defaultdict(list)
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                name = proc.info['name']
                process_count[name].append(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Hydra tem exatamente 3 processos idênticos
        for name, pids in process_count.items():
            if len(pids) == 3:
                self.alerts.append({
                    'type': 'HYDRA_PATTERN',
                    'process': name,
                    'pids': pids
                })
        
        return len(self.alerts) > 0
    
    def check_heartbeat_files(self):
        """
        Detecta arquivos de heartbeat do sistema Hydra
        """
        hb_locations = [
            Path.home() / ".cache" / "fontconfig",
            Path(os.environ.get('LOCALAPPDATA', '')) / ".cache" / "ms-runtime",
        ]
        
        for loc in hb_locations:
            if loc.exists():
                hb_files = list(loc.glob("*.hb"))
                lock_files = list(loc.glob("*.lock"))
                
                if len(hb_files) >= 2 or len(lock_files) >= 2:
                    self.alerts.append({
                        'type': 'HYDRA_IPC_FILES',
                        'location': str(loc),
                        'hb_count': len(hb_files),
                        'lock_count': len(lock_files)
                    })
        
        return len(self.alerts) > 0
    
    def check_rapid_file_updates(self):
        """
        Detecta arquivos sendo atualizados a cada ~5 segundos (heartbeat)
        """
        for loc in [Path.home() / ".cache" / "fontconfig"]:
            if not loc.exists():
                continue
                
            # Monitorar por 10 segundos
            timestamps = {}
            for _ in range(2):
                for f in loc.glob("*.hb"):
                    mtime = f.stat().st_mtime
                    if f.name in timestamps:
                        if mtime != timestamps[f.name]:
                            self.alerts.append({
                                'type': 'RAPID_FILE_UPDATE',
                                'file': str(f),
                                'interval': '~5s'
                            })
                    timestamps[f.name] = mtime
                time.sleep(5)
        
        return len(self.alerts) > 0

    def run_all_checks(self):
        """Executa todas as verificações"""
        print("🔍 Iniciando detecção comportamental...")
        
        checks = [
            ("Browser DB Access", self.check_browser_db_access),
            ("Hydra Pattern", self.check_hydra_pattern),
            ("Heartbeat Files", self.check_heartbeat_files),
        ]
        
        for name, check in checks:
            print(f"  Verificando: {name}...", end=" ")
            if check():
                print("⚠️ DETECTADO!")
            else:
                print("✓ Limpo")
        
        return self.alerts

if __name__ == "__main__":
    detector = StealerDetector()
    alerts = detector.run_all_checks()
    
    if alerts:
        print(f"\n🚨 {len(alerts)} ALERTAS DETECTADOS:")
        for alert in alerts:
            print(f"  [{alert['type']}] {alert}")
    else:
        print("\n✅ Nenhuma atividade suspeita detectada")
```

**FLAG**: Capture 3 indicadores comportamentais: `CTF{ioc1_ioc2_ioc3}`

---

### Tarefa 3: Honeypot de Credenciais (25 pts)

Crie arquivos "honeypot" que alertam quando acessados:

```bash
#!/bin/bash
# honeypot_setup.sh

# Criar estrutura fake de browser
mkdir -p ~/.config/chromium-fake/Default/
echo "HONEYPOT_DATA" > ~/.config/chromium-fake/Default/Cookies
echo "user:honeypot123" > ~/.config/chromium-fake/Default/"Login Data"

# SQLite fake para parecer real
sqlite3 ~/.config/chromium-fake/Default/Cookies << 'EOF'
CREATE TABLE cookies (
    host_key TEXT,
    name TEXT,
    value TEXT,
    path TEXT,
    expires_utc INTEGER,
    is_secure INTEGER
);
INSERT INTO cookies VALUES ('honeypot.local', 'ALERT', 'COMPROMISED', '/', 0, 0);
EOF

# Monitorar acesso com inotify
echo "🍯 Honeypot ativo. Monitorando acessos..."
inotifywait -m -e access -e open ~/.config/chromium-fake/Default/ 2>/dev/null | while read line; do
    echo "[$(date)] 🚨 HONEYPOT ACESSADO: $line"
    # Logar para syslog
    logger -t HONEYPOT "Browser data honeypot accessed: $line"
    # Capturar processo suspeito
    lsof ~/.config/chromium-fake/Default/* 2>/dev/null | tail -1
done
```

**Implementar**:
1. Criação de arquivos honeypot realistas
2. Monitoramento de acesso
3. Alertas/Notificações

**FLAG**: Timestamp do primeiro alerta: `CTF{timestamp}`

---

### Tarefa 4: Ferramenta de Limpeza (25 pts)

Desenvolva uma ferramenta que limpe **todos** os artefatos do MyStealer:

```rust
// defenses/cleaner/src/main.rs
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn get_hydra_directories() -> Vec<PathBuf> {
    let mut dirs = vec![];
    
    // Linux
    if let Some(home) = dirs::home_dir() {
        dirs.push(home.join(".cache/fontconfig"));
    }
    
    // Windows
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        dirs.push(PathBuf::from(local_app_data).join(".cache/ms-runtime"));
    }
    
    dirs
}

fn kill_hydra_processes() -> usize {
    let mut killed = 0;
    
    // Encontrar e matar processos Hydra
    // Procurar por processos com padrão de 3 instâncias idênticas
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("pkill")
            .args(["-9", "-f", "mystealer"])
            .output();
        if output.is_ok() {
            killed = 3; // Assume 3 cabeças
        }
    }
    
    killed
}

fn clean_heartbeat_files() -> usize {
    let mut cleaned = 0;
    
    for dir in get_hydra_directories() {
        if dir.exists() {
            // Remover arquivos .hb e .lock
            if let Ok(entries) = fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(ext) = path.extension() {
                        if ext == "hb" || ext == "lock" {
                            if fs::remove_file(&path).is_ok() {
                                println!("  ✓ Removido: {:?}", path);
                                cleaned += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    
    cleaned
}

fn prevent_respawn() {
    // Tornar diretório IPC inacessível temporariamente
    for dir in get_hydra_directories() {
        if dir.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&dir).unwrap().permissions();
                perms.set_mode(0o000);
                let _ = fs::set_permissions(&dir, perms);
                println!("  🔒 Bloqueado: {:?}", dir);
            }
        }
    }
}

fn main() {
    println!("🧹 MyStealer Cleaner v0.3.1");
    println!("============================\n");
    
    // 1. Bloquear IPC primeiro (prevenir respawn)
    println!("1. Bloqueando comunicação IPC...");
    prevent_respawn();
    
    // 2. Matar processos
    println!("\n2. Terminando processos Hydra...");
    let killed = kill_hydra_processes();
    println!("  Processos terminados: {}", killed);
    
    // 3. Limpar arquivos
    println!("\n3. Limpando arquivos de heartbeat...");
    let cleaned = clean_heartbeat_files();
    println!("  Arquivos removidos: {}", cleaned);
    
    // 4. Restaurar permissões
    println!("\n4. Restaurando permissões...");
    for dir in get_hydra_directories() {
        if dir.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&dir).unwrap().permissions();
                perms.set_mode(0o755);
                let _ = fs::set_permissions(&dir, perms);
            }
        }
    }
    
    println!("\n✅ Limpeza concluída!");
    println!("   Processos mortos: {}", killed);
    println!("   Arquivos limpos: {}", cleaned);
}
```

**FLAG**: Número total de artefatos removidos: `CTF{numero}`

---

## Tarefas Bônus

### Bônus 1: YARA para Padrão bs() (20 pts extra)

Crie uma regra YARA que detecte o **padrão de código** da função `bs()`:

```yara
rule MyStealer_BS_Pattern {
    meta:
        description = "Detecta padrão de ofuscação bs()"
        
    strings:
        // Padrão: String::with_capacity seguido de loop de push
        $with_capacity = { 
            E8 ?? ?? ?? ??        // call String::with_capacity
        }
        
        // Loop de push de caracteres
        $push_loop = {
            0F B6 ??              // movzx (load char)
            E8 ?? ?? ?? ??        // call push
            48 83 ?? 01           // add 1
            48 39 ??              // cmp
            (75|0F 85) ??         // jne/jnz (loop)
        }
        
        // black_box call
        $black_box = "black_box"
        
    condition:
        uint16(0) == 0x5A4D and 
        (#push_loop > 10) and      // Muitas chamadas = bs() pattern
        $with_capacity
}
```

### Bônus 2: Threat Intelligence (15 pts extra)

Extraia IOCs do malware e crie relatório no formato STIX/TAXII:

```json
{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--mystealer-hydra",
    "name": "MyStealer v0.3.1 Hydra System",
    "pattern": "[file:hashes.'SHA-256' = 'hash_aqui'] OR [file:name LIKE '%.hb']",
    "pattern_type": "stix",
    "valid_from": "2024-12-17T00:00:00Z",
    "labels": ["malicious-activity", "attribution"],
    "external_references": [
        {
            "source_name": "MITRE ATT&CK",
            "url": "https://attack.mitre.org/techniques/T1480/",
            "external_id": "T1480"
        }
    ]
}
```

---

## Ferramentas Recomendadas

| Ferramenta | Uso |
|------------|-----|
| `yara` | Pattern matching estrutural |
| `inotify-tools` | Monitoramento de arquivos |
| `auditd` | Auditoria de sistema |
| `osquery` | Queries comportamentais |
| `sysdig` | Monitoramento de containers |
| `psutil` (Python) | Análise de processos |

---

## Dicas

1. **Strings ofuscadas? Use comportamento!** - O malware pode esconder strings, mas não pode esconder ações
2. **Procure padrões, não assinaturas** - 3 processos idênticos = padrão Hydra
3. **Arquivos temporários revelam** - .hb e .lock ainda precisam existir
4. **Timing é tudo** - Heartbeat a cada 5s é detectável

---

## Solução

<details>
<summary>Clique para ver as respostas (SPOILER)</summary>

### Tarefa 1 - YARA Estrutural
```yara
rule MyStealer_v031 {
    strings:
        $hb = ".hb"
        $lock = ".lock"
        $fontconfig = "fontconfig"
        $aes = { 63 7c 77 7b f2 6b }  // AES S-box
        
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($hb, $lock, $fontconfig) or $aes)
}
```

### Tarefa 2 - Detector
IOCs comportamentais:
1. `BROWSER_DB_ACCESS` - Acesso a Cookies/Login Data
2. `HYDRA_PATTERN` - 3 processos idênticos
3. `HYDRA_IPC_FILES` - Arquivos .hb/.lock em fontconfig

**FLAG**: `CTF{browserdb_hydra3_heartbeat}`

### Tarefa 3 - Honeypot
Varia por execução - capture o timestamp do alerta.

### Tarefa 4 - Cleaner
Artefatos típicos:
- 3 processos Hydra
- 6 arquivos (3x .hb + 3x .lock)

**FLAG**: `CTF{9}` (3 processos + 6 arquivos)

</details>

---

## 📊 Resumo de Pontuação

| Tarefa | Pontos |
|--------|--------|
| 1 - YARA Estrutural | 25 |
| 2 - Detecção Comportamental | 25 |
| 3 - Honeypot | 25 |
| 4 - Cleaner | 25 |
| **Bônus 1** - YARA bs() | +20 |
| **Bônus 2** - Threat Intel | +15 |
| **Total** | **100 (+35)** |

---

## 🏆 Ranking Final

| Desafio | Pontos | Dificuldade |
|---------|--------|-------------|
| 01 - Análise Básica | 40 (+10) | ⭐ |
| 02 - Análise Dinâmica | 70 | ⭐⭐ |
| 03 - Engenharia Reversa | 100 | ⭐⭐⭐ |
| 04 - Defesa e Detecção | 100 (+35) | ⭐⭐⭐ |
| 05 - Hydra Persistence | 120 (+45) | ⭐⭐⭐⭐⭐ |
| 06 - String Obfuscation | 100 | ⭐⭐⭐⭐ |
| **TOTAL** | **530 (+90)** | |

**Parabéns por completar o MyStealer CTF Lab!** 🎉

---

*Atualizado para MyStealer v0.3.1 - Stealth Edition* 🕵️
