# 🐍 Challenge 05: Hydra Persistence

**Dificuldade:** ⭐⭐⭐⭐⭐ (120 pontos)  
**Categoria:** Persistence & Process Analysis  
**Tema:** Sistema de redundância multi-processo

## 📖 Cenário

Durante uma investigação de IR, você identificou que um malware está extremamente difícil de remover. Toda vez que você mata o processo, ele reaparece em segundos. Análise inicial mostra que há múltiplas instâncias do mesmo binário rodando simultaneamente.

## 🎯 Objetivos

### Parte 1: Identificação (30 pontos)
1. Identifique quantos processos "hydra" estão rodando simultaneamente
2. Determine os nomes/roles de cada instância (Alpha, Beta, Gamma)
3. Encontre o diretório de comunicação IPC usado pelo sistema

### Parte 2: Análise de Comunicação (40 pontos)
1. Analise os arquivos `.hb` (heartbeat) e `.lock`
2. Determine o formato do heartbeat (PID:timestamp)
3. Calcule o intervalo de heartbeat
4. Identifique o timeout para considerar uma cabeça "morta"

### Parte 3: Neutralização (50 pontos)
1. Desenvolva uma estratégia para matar TODAS as cabeças simultaneamente
2. OU identifique uma forma de prevenir o respawn
3. OU encontre uma vulnerabilidade no mecanismo de IPC

## 🔬 Ambiente de Teste

```bash
# Iniciar o sistema Hydra
./mystealer --skip-checks --hydra

# Verificar processos
ps aux | grep mystealer

# Encontrar diretório IPC
# Linux: ~/.cache/fontconfig/
# Windows: %LOCALAPPDATA%\.cache\ms-runtime\

# Monitorar heartbeats
watch -n 1 'ls -la ~/.cache/fontconfig/*.hb 2>/dev/null'
```

## 📝 Formato das Respostas

### Resposta 1: Identificação
```
Número de processos: ___
Roles identificados: Alpha, Beta, Gamma
Diretório IPC: ___
```

### Resposta 2: Comunicação
```
Formato heartbeat: ___
Intervalo: ___ segundos
Timeout: ___ segundos
```

### Resposta 3: Estratégia de Neutralização
```
Método escolhido: ___
Comandos/Script: ___
Explicação: ___
```

## 💡 Dicas

<details>
<summary>Dica 1 (Identificação)</summary>

Use `pstree` para ver a hierarquia de processos. O processo Alpha é o pai dos outros.
</details>

<details>
<summary>Dica 2 (IPC)</summary>

Os arquivos `.lock` contêm o PID do processo que "owns" aquela cabeça. Os arquivos `.hb` contêm PID:timestamp do último heartbeat.
</details>

<details>
<summary>Dica 3 (Timing)</summary>

O código fonte revela:
- `HEARTBEAT_INTERVAL = 5` segundos
- `HEARTBEAT_TIMEOUT = 15` segundos
</details>

<details>
<summary>Dica 4 (Neutralização - Método 1)</summary>

Mate todos simultaneamente:
```bash
pkill -9 -f mystealer
```
Mas seja RÁPIDO - você tem ~5 segundos antes do respawn.
</details>

<details>
<summary>Dica 5 (Neutralização - Método 2)</summary>

Corrompa o diretório IPC:
```bash
rm -rf ~/.cache/fontconfig/
mkdir ~/.cache/fontconfig/
chmod 000 ~/.cache/fontconfig/
```
Sem IPC, as cabeças não conseguem se comunicar.
</details>

<details>
<summary>Dica 6 (Neutralização - Método 3)</summary>

Race condition: Crie locks falsos antes de matar:
```bash
for head in alpha beta gamma; do
    echo "99999" > ~/.cache/fontconfig/${head}.lock
done
# Agora mate os processos - eles não conseguirão reclamar os locks
```
</details>

## 🏆 Pontuação Extra

- **+10 pontos**: Identifique o mecanismo de backoff exponencial no respawn
- **+15 pontos**: Encontre as strings ofuscadas no binário que revelam os nomes das cabeças
- **+20 pontos**: Desenvolva um script que monitora e mata automaticamente todas as instâncias

## 📚 Referências

- [Process Redundancy in Malware](https://attack.mitre.org/techniques/T1480/)
- [IPC Mechanisms](https://en.wikipedia.org/wiki/Inter-process_communication)
- [Goldberg Obfuscation](https://github.com/frank2/goldberg)

## 🔍 Indicadores de Compromisso (IOCs)

```yaml
files:
  - ~/.cache/fontconfig/alpha.lock
  - ~/.cache/fontconfig/alpha.hb
  - ~/.cache/fontconfig/beta.lock
  - ~/.cache/fontconfig/beta.hb
  - ~/.cache/fontconfig/gamma.lock
  - ~/.cache/fontconfig/gamma.hb
  
processes:
  - mystealer --hydra-role alpha
  - mystealer --hydra-role beta
  - mystealer --hydra-role gamma

behavior:
  - Multiple identical processes
  - Heartbeat files updated every 5 seconds
  - Automatic respawn within 15 seconds of process death
  - Exponential backoff on repeated failures
```

## ✅ Checklist de Validação

- [ ] Identificou os 3 processos Hydra
- [ ] Encontrou o diretório IPC correto
- [ ] Analisou o formato dos arquivos de comunicação
- [ ] Conseguiu matar todas as cabeças permanentemente
- [ ] Documentou a estratégia de neutralização

---

**Nota:** Este desafio simula técnicas reais de persistência usadas por malware avançado. O sistema Hydra é inspirado em técnicas de redundância observadas em APTs.
