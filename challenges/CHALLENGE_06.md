# 🔐 Challenge 06 - String Obfuscation Reversing

**Dificuldade**: ⭐⭐⭐⭐ (Difícil)  
**Pontos**: 100  
**Categoria**: Reverse Engineering  
**Versão**: v0.3.1

---

## 📋 Briefing

O malware MyStealer v0.3.1 utiliza técnicas avançadas de ofuscação de strings para evitar detecção por ferramentas de análise estática. Nesta versão, TODAS as strings sensíveis são construídas em runtime usando a função `bs()` (build string).

Seu objetivo é:
1. Entender como a ofuscação funciona
2. Reverter as técnicas e extrair as strings originais
3. Identificar os padrões no binário

---

## 🎯 Objetivos

### Parte 1: Identificar o Método (20 pontos)
- Qual técnica principal é usada para esconder strings?
- Encontre a função `bs()` no disassembly
- Explique como `black_box()` previne otimizações

### Parte 2: Extrair Nomes de Browsers (25 pontos)
- Encontre os paths de browsers no código
- Reconstrua pelo menos 3 paths completos
- Identifique o padrão de construção

### Parte 3: Reverter Queries SQL (30 pontos)
- Encontre as funções `build_*_query()`
- Reconstrua a query de cookies completa
- Identifique quantas queries diferentes existem

### Parte 4: Serde Rename Analysis (25 pontos)
- Analise o JSON de output
- Mapeie os campos curtos para nomes reais
- Crie uma tabela de mapeamento completa

---

## 📁 Arquivos

```
output/mystealer.exe     # Binário Windows ofuscado
output/collected_*.bin   # Dados coletados (encrypted)
```

---

## 🔍 Análise Inicial

### Verificando Strings

```bash
# Antes (v0.2) - Muitas strings visíveis
$ strings old_mystealer.exe | grep -iE "Chrome|Firefox" | wc -l
47

# Depois (v0.3.1) - Quase nenhuma
$ strings mystealer.exe | grep -iE "Chrome|Firefox" | wc -l
0
```

### O que mudou?

Na v0.3.1, todas as strings são construídas assim:

```rust
// ❌ ANTES - Detectável
let browser = "Chrome";

// ✅ DEPOIS - Não detectável
fn bs(chars: &[char]) -> String {
    let mut s = String::with_capacity(chars.len());
    for &c in chars { s.push(c); }
    std::hint::black_box(s)
}
let browser = bs(&['C', 'h', 'r', 'o', 'm', 'e']);
```

---

## 🧪 Exercícios Práticos

### Exercício 1: Encontrar bs() no Disassembly

No IDA/Ghidra, procure por padrões como:

```asm
; Loop de push de caracteres
mov     eax, [rsp+...]    ; Carrega caractere
call    String::push      ; Adiciona à string
inc     rdi               ; Próximo caractere
cmp     rdi, ...          ; Verifica fim
jne     loop_start
```

**Dica**: Procure por chamadas repetidas a `String::push` com valores imediatos (caracteres ASCII).

### Exercício 2: Reconstruir Path de Browser

No binário, você verá algo assim:

```asm
; Construindo ".config/google-chrome"
mov byte ptr [rsp+0], 2Eh   ; '.'
mov byte ptr [rsp+1], 63h   ; 'c'
mov byte ptr [rsp+2], 6Fh   ; 'o'
mov byte ptr [rsp+3], 6Eh   ; 'n'
; ...
```

**Tarefa**: Encontre e reconstrua o path completo.

### Exercício 3: Reverter Query SQL

As queries são construídas assim:

```rust
fn build_cookies_query() -> String {
    let mut q = String::new();
    for c in ['S', 'E', 'L', 'E', 'C', 'T', ' '] { q.push(c); }
    for c in ['h', 'o', 's', 't', '_', 'k', 'e', 'y', ',', ' '] { q.push(c); }
    // ...
}
```

**Tarefa**: Encontre a função e reconstrua a query completa.

### Exercício 4: Mapeamento Serde

Analise um arquivo de output e mapeie os campos:

```json
{
  "t": "2024-12-17T21:00:00Z",   // ? → timestamp
  "s": "abc123",                  // ? → session_id
  "m": {
    "b": {
      "b": ["C", "F"],            // ? → browsers_found
      "c": 42,                    // ? → total_cookies
      "w": 5,                     // ? → total_passwords
      "h": 100                    // ? → total_history
    }
  }
}
```

---

## 💡 Dicas

### Nível 1 (Básico)
- Procure por loops que fazem `push` de caracteres
- Os caracteres são valores ASCII (0x41 = 'A', 0x61 = 'a', etc)

### Nível 2 (Intermediário)
- A função `bs()` sempre termina com `black_box()`
- Procure por `std::hint::black_box` no binário

### Nível 3 (Avançado)
- Use um debugger para capturar strings em runtime
- Coloque breakpoints após a construção de strings

---

## 🔓 Soluções

<details>
<summary>Clique para ver - Path do Chrome (Linux)</summary>

```
.config/google-chrome
```

Construído com:
```rust
home.join(bs(&['.', 'c', 'o', 'n', 'f', 'i', 'g', '/', 
               'g', 'o', 'o', 'g', 'l', 'e', '-', 
               'c', 'h', 'r', 'o', 'm', 'e']))
```

</details>

<details>
<summary>Clique para ver - Query de Cookies</summary>

```sql
SELECT host_key, name, value, expires_utc, is_secure, is_httponly FROM cookies LIMIT 100
```

</details>

<details>
<summary>Clique para ver - Mapeamento Serde Completo</summary>

**CollectedData:**
| Campo JSON | Nome Original |
|------------|---------------|
| `t` | timestamp |
| `s` | session_id |
| `m` | modules |
| `x` | metadata |

**BrowserData:**
| Campo JSON | Nome Original |
|------------|---------------|
| `b` | browsers_found |
| `p` | profiles |
| `c` | total_cookies |
| `w` | total_passwords |
| `h` | total_history |

**FileData:**
| Campo JSON | Nome Original |
|------------|---------------|
| `d` | scanned_dirs |
| `f` | found_files |
| `ts` | total_scanned |
| `tm` | total_matches |
| `ms` | scan_duration_ms |

</details>

---

## 🛠️ Ferramentas Recomendadas

| Ferramenta | Uso |
|------------|-----|
| **IDA Pro** | Análise estática, encontrar padrões |
| **Ghidra** | Decompilação, análise de funções |
| **x64dbg** | Debug dinâmico, capturar strings em runtime |
| **Python** | Scripts para reconstruir strings |
| **CyberChef** | Conversão ASCII/Hex |

---

## 📝 Script de Ajuda

```python
#!/usr/bin/env python3
"""
Script para reconstruir strings do MyStealer v0.3.1
"""

def reconstruct_from_chars(char_list):
    """Reconstrói string a partir de lista de caracteres"""
    return ''.join(char_list)

def hex_to_string(hex_bytes):
    """Converte bytes hex para string"""
    return bytes.fromhex(hex_bytes).decode('utf-8')

# Exemplo: Path do Chrome
chrome_chars = ['.', 'c', 'o', 'n', 'f', 'i', 'g', '/', 
                'g', 'o', 'o', 'g', 'l', 'e', '-', 
                'c', 'h', 'r', 'o', 'm', 'e']
print(f"Chrome path: {reconstruct_from_chars(chrome_chars)}")

# Exemplo: Query de cookies
query_parts = [
    ['S', 'E', 'L', 'E', 'C', 'T', ' '],
    ['h', 'o', 's', 't', '_', 'k', 'e', 'y', ',', ' '],
    ['n', 'a', 'm', 'e', ',', ' '],
    ['v', 'a', 'l', 'u', 'e', ',', ' '],
    ['e', 'x', 'p', 'i', 'r', 'e', 's', '_', 'u', 't', 'c', ',', ' '],
    ['i', 's', '_', 's', 'e', 'c', 'u', 'r', 'e', ',', ' '],
    ['i', 's', '_', 'h', 't', 't', 'p', 'o', 'n', 'l', 'y', ' '],
    ['F', 'R', 'O', 'M', ' '],
    ['c', 'o', 'o', 'k', 'i', 'e', 's', ' '],
    ['L', 'I', 'M', 'I', 'T', ' ', '1', '0', '0'],
]

query = ''.join(reconstruct_from_chars(part) for part in query_parts)
print(f"Cookie query: {query}")
```

---

## 📊 Pontuação

| Critério | Pontos |
|----------|--------|
| Identificar método `bs()` | 20 |
| Reconstruir 3+ paths de browsers | 25 |
| Reverter query SQL completa | 30 |
| Mapeamento serde completo | 25 |
| **Total** | **100** |

---

## 🏆 Entrega

Submeta um relatório contendo:

1. **Explicação técnica** de como `bs()` funciona
2. **Lista de paths** de browsers reconstruídos
3. **Queries SQL** completas reconstruídas
4. **Tabela de mapeamento** serde completa
5. **Screenshots** do disassembly mostrando os padrões

---

## 📚 Referências

- [Rust std::hint::black_box](https://doc.rust-lang.org/std/hint/fn.black_box.html)
- [Anti-Static Analysis Techniques](https://attack.mitre.org/techniques/T1027/)
- [Serde Rename Documentation](https://serde.rs/field-attrs.html)

---

*Challenge criado para treinamento de IR e Threat Hunting - v0.3.1* 🛡️
