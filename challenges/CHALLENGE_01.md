# 🎯 Desafio 01: Análise Básica

## Objetivo

Analise o binário compilado e encontre as flags escondidas.

## Contexto

Você recebeu um sample de malware suspeito. Sua missão é analisá-lo estaticamente e encontrar informações sobre seu funcionamento.

## Tarefas

### Tarefa 1: Identificação (10 pts)
Identifique as seguintes informações sobre o binário:

- Qual linguagem foi usada para compilar?
- Qual arquitetura alvo?
- Quais bibliotecas são linkadas?

**FLAG**: Use o comando `file` e `ldd` para encontrar: `CTF{tipo_arquivo_arquitetura}`

### Tarefa 2: Strings (15 pts)
Extraia strings do binário e encontre:

- URLs de C2
- Nomes de navegadores alvo
- Extensões de arquivo buscadas

```bash
strings target/release/mystealer | grep -i "http"
strings target/release/mystealer | grep -i "chrome"
```

**FLAG**: Encontre a string de configuração: `CTF{???}`

### Tarefa 3: Imports (15 pts)
Analise as funções importadas:

```bash
nm -D target/release/mystealer | head -50
objdump -T target/release/mystealer
```

Identifique 3 funções suspeitas relacionadas a:
- Acesso a arquivos
- Rede
- Criptografia

**FLAG**: `CTF{funcao1_funcao2_funcao3}`

## Ferramentas Recomendadas

- `file` - Identificar tipo de arquivo
- `strings` - Extrair strings
- `nm` - Listar símbolos
- `objdump` - Disassembly
- `ltrace` - Trace de library calls
- `strace` - Trace de syscalls

## Dicas

1. Comece sempre com análise estática antes de executar
2. Use `RUST_BACKTRACE=1` para mais informações em caso de crash
3. Compare o binário de release vs debug

## Solução

<details>
<summary>Clique para ver as respostas (SPOILER)</summary>

### Tarefa 1
```bash
file target/release/mystealer
# ELF 64-bit LSB pie executable, x86-64...
```
FLAG: `CTF{elf64_x86_64}`

### Tarefa 2
```bash
strings target/release/mystealer | grep -E "http|localhost"
# http://localhost:8080/collect
```
FLAG: `CTF{localhost_8080_collect}`

### Tarefa 3
```bash
nm -D target/release/mystealer | grep -E "open|send|encrypt"
```
FLAG: `CTF{open_send_encrypt}`

</details>

---

**Pontuação Total**: 40 pontos
**Dificuldade**: ⭐ Fácil

