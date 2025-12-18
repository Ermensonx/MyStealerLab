# 🔐 Challenge 06 - String Obfuscation Reversing

**Dificuldade**: ⭐⭐⭐⭐ (Difícil)  
**Pontos**: 100  
**Categoria**: Reverse Engineering

---

## 📋 Briefing

O malware MyStealer v0.3 utiliza técnicas avançadas de ofuscação de strings para evitar detecção por ferramentas de análise estática. Seu objetivo é reverter a ofuscação e extrair as strings sensíveis.

---

## 🎯 Objetivos

1. **Identificar o método de ofuscação** (20 pontos)
   - Qual técnica é usada para esconder strings?
   - Quantas chaves XOR diferentes são utilizadas?

2. **Extrair as strings de processos de VM** (30 pontos)
   - Encontre os nomes dos processos que o malware procura
   - Decodifique pelo menos 5 nomes

3. **Extrair as strings de usernames suspeitos** (25 pontos)
   - Quais usernames são considerados indicadores de sandbox?
   - Decodifique a lista completa

4. **Reverter uma query SQL** (25 pontos)
   - Encontre a função que constrói queries SQL
   - Reconstrua a query completa de cookies

---

## 📁 Arquivos

```
output/mystealer.exe     # Binário Windows ofuscado
```

---

## 🔍 Dicas

### Nível 1 (Básico)
- Procure por padrões de XOR no disassembly
- A instrução `XOR` com constante é um indicador

### Nível 2 (Intermediário)
- As chaves XOR são: `0x17`, `0x19`, `0x33`, `0x42`, `0x55`, `0x77`
- Procure por funções que fazem iteração sobre arrays de bytes

### Nível 3 (Avançado)
- A função `xd()` ou similar decodifica strings XOR
- A função `bs()` constrói strings caractere por caractere
- Queries SQL são construídas com loops `for c in [...]`

---

## 🧪 Exercícios Práticos

### Exercício 1: Identificar XOR Decode

```python
# Decodifique esta string (key = 0x19):
encoded = [0x7a, 0x76, 0x69, 0x75, 0x77, 0x68, 0x63]

def xor_decode(data, key):
    return ''.join(chr(b ^ key) for b in data)

result = xor_decode(encoded, 0x19)
print(f"Decodificado: {result}")
```

**Pergunta**: Qual é a string decodificada?

### Exercício 2: Encontrar Processos de VM

```python
# Estes bytes representam nomes de processos de VM (key = 0x19):
vm_procs_encoded = [
    [0x6f, 0x6c, 0x7d, 0x6c, 0x6c, 0x69, 0x7c, 0x75],  # ???
    [0x6f, 0x6c, 0x78, 0x70, 0x79, 0x72, 0x7d, 0x79, 0x70, 0x68],  # ???
]

for proc in vm_procs_encoded:
    print(xor_decode(proc, 0x19))
```

### Exercício 3: Reconstruir Query SQL

No binário, a query de cookies é construída assim:

```rust
fn build_cookies_query() -> String {
    let mut q = String::new();
    for c in ['S','E','L','E','C','T',' '] { q.push(c); }
    for c in ['h','o','s','t','_','k','e','y',',',' '] { q.push(c); }
    // ... continue
}
```

**Tarefa**: Encontre a função no disassembly e reconstrua a query completa.

---

## 🔓 Soluções (Spoiler)

<details>
<summary>Clique para ver - Exercício 1</summary>

```python
encoded = [0x7a, 0x76, 0x69, 0x75, 0x77, 0x68, 0x63]
result = xor_decode(encoded, 0x19)
# Resultado: "sandbox"
```

</details>

<details>
<summary>Clique para ver - Exercício 2</summary>

```python
# Processo 1: vmtoolsd
# Processo 2: vmwaretray
```

</details>

<details>
<summary>Clique para ver - Lista completa de usernames</summary>

```
sandbox, malware, virus, sample, test,
john, user, admin, cuckoo, honey,
analysis, analyst, vmuser
```

</details>

<details>
<summary>Clique para ver - Query SQL completa</summary>

```sql
SELECT host_key, name, value, expires_utc, is_secure, is_httponly 
FROM cookies LIMIT 100
```

</details>

---

## 📊 Tabela de Chaves XOR

| Key | Uso | Exemplos |
|-----|-----|----------|
| `0x17` | Paths de sistema | ".config", "Cookies", "History" |
| `0x19` | Processos e usernames | "vmtoolsd", "sandbox", "analyst" |
| `0x33` | Variáveis de ambiente | "HOME", "APPDATA" |
| `0x42` | Nomes de browsers | "chromium", "firefox", "brave" |
| `0x55` | Strings de crypto | "v10", "encrypted_key" |
| `0x77` | Ferramentas de análise | "wireshark", "procmon", "x64dbg" |

---

## 🛠️ Ferramentas Recomendadas

- **IDA Pro / Ghidra**: Análise estática
- **x64dbg**: Debug dinâmico
- **Python**: Scripts de decodificação
- **CyberChef**: Operações XOR online

---

## 📝 Entrega

Submeta um relatório contendo:

1. Lista de todas as chaves XOR encontradas
2. Pelo menos 10 strings decodificadas
3. Query SQL completa reconstruída
4. Explicação do método de ofuscação usado

---

## 🏆 Pontuação

| Critério | Pontos |
|----------|--------|
| Identificar método de ofuscação | 20 |
| Extrair 5+ processos de VM | 30 |
| Extrair lista de usernames | 25 |
| Reconstruir query SQL | 25 |
| **Total** | **100** |

---

*Challenge criado para treinamento de IR e Threat Hunting*
