# 🎯 Desafio 02: Análise Dinâmica

## Objetivo

Execute o malware em ambiente controlado e capture seu comportamento.

## Pré-requisitos

- Ambiente de lab configurado (Docker ou VM)
- Servidor C2 mock rodando
- Ferramentas de monitoramento instaladas

## Tarefas

### Tarefa 1: Preparação (5 pts)

Configure o ambiente de monitoramento:

```bash
# Iniciar containers
cd lab_environment
docker-compose up -d

# Verificar se está rodando
curl http://localhost:8080/health
```

**FLAG**: Hash MD5 da resposta do health check

### Tarefa 2: Execução Monitorada (20 pts)

Execute o malware com strace e capture:

```bash
# Em uma VM ou container de teste
export MYSTEALER_LAB_MODE=1
strace -f -o /tmp/strace.log ./mystealer --lab-mode

# Analisar syscalls
grep -E "open|read|write|connect" /tmp/strace.log | head -50
```

Identifique:
1. Quais arquivos são acessados?
2. Quais conexões de rede são feitas?
3. Quais dados são escritos?

**FLAG**: Número de syscalls `open` + `connect`: `CTF{numero}`

### Tarefa 3: Captura de Rede (25 pts)

Capture o tráfego de rede:

```bash
# Em outro terminal
tcpdump -i any -w /tmp/capture.pcap port 8080

# Executar o malware
./mystealer --lab-mode

# Analisar captura
tcpdump -r /tmp/capture.pcap -A | head -100
```

Responda:
1. Qual protocolo é usado para exfiltração?
2. Os dados são criptografados?
3. Qual o tamanho médio dos pacotes?

**FLAG**: Extraia o header customizado: `CTF{X-Session-ID_value}`

### Tarefa 4: Análise do C2 (20 pts)

Verifique os dados recebidos pelo servidor C2:

```bash
# Listar sessões
curl http://localhost:8080/sessions

# Ver detalhes
curl http://localhost:8080/sessions/{session_id}

# Download dos dados
curl -O http://localhost:8080/download/{session_id}/{filename}
```

Decodifique os dados recebidos e encontre a flag.

**FLAG**: Dentro dos dados coletados: `CTF{???}`

## Ferramentas Recomendadas

- `strace` / `ltrace` - Tracing de syscalls
- `tcpdump` / `Wireshark` - Captura de rede
- `procmon` (Linux) - Monitor de processos
- `curl` / `httpie` - Testar endpoints

## Dicas

1. Sempre use ambiente isolado (VM/Container)
2. Faça snapshots antes de executar
3. Monitore em tempo real com `watch`
4. Use `jq` para parsear JSON

## Solução

<details>
<summary>Clique para ver as respostas (SPOILER)</summary>

### Tarefa 1
```bash
curl -s http://localhost:8080/health | md5sum
```
FLAG: Varia por execução

### Tarefa 2
```bash
grep -c "open\|connect" /tmp/strace.log
```
FLAG: Depende da execução

### Tarefa 3
```bash
tcpdump -r /tmp/capture.pcap -A 2>/dev/null | grep "X-Session-ID"
```
FLAG: UUID da sessão

### Tarefa 4
```bash
# Decodificar base64 dos dados
base64 -d < data.bin > decoded.json
cat decoded.json | jq '.session_id'
```

</details>

---

**Pontuação Total**: 70 pontos
**Dificuldade**: ⭐⭐ Médio

