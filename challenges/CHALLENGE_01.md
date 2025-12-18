# 🎯 Desafio 01: Análise Básica

**Dificuldade**: ⭐ Fácil  
**Pontos**: 40  
**Versão**: v0.3.1 (Stealth Edition)

---

## ⚠️ Nota sobre Ofuscação

A partir da versão 0.3.1, o MyStealer utiliza **ofuscação inteligente de strings**. Isso significa que técnicas tradicionais de análise estática (como `strings | grep`) **podem não revelar informações úteis**.

Este challenge foi atualizado para refletir essa realidade.

---

## Objetivo

Analise o binário compilado e encontre as flags escondidas.

## Contexto

Você recebeu um sample de malware suspeito. Sua missão é analisá-lo estaticamente e encontrar informações sobre seu funcionamento.

---

## Tarefas

### Tarefa 1: Identificação (10 pts)

Identifique as seguintes informações sobre o binário:

- Qual linguagem foi usada para compilar?
- Qual arquitetura alvo?
- Quais bibliotecas são linkadas?

```bash
file target/release/mystealer
ldd target/release/mystealer  # Linux
```

**FLAG**: `CTF{tipo_arquivo_arquitetura}`

---

### Tarefa 2: Análise de Strings - O Vazio (15 pts)

**NOVA ABORDAGEM**: Execute análise de strings e documente o que você **NÃO** encontra:

```bash
# Tente encontrar browsers
strings target/release/mystealer | grep -iE "Chrome|Firefox|Edge"

# Tente encontrar URLs
strings target/release/mystealer | grep -iE "http|localhost"

# Tente encontrar SQL
strings target/release/mystealer | grep -iE "SELECT|FROM|WHERE"

# Tente encontrar paths
strings target/release/mystealer | grep -iE "\.config|AppData"
```

**Pergunta**: Quantas dessas buscas retornaram resultados úteis?

**FLAG**: `CTF{numero_resultados}` (provavelmente `CTF{0}`)

**Conclusão**: O malware usa **ofuscação de strings**. Você precisará de técnicas mais avançadas (Challenge 06).

---

### Tarefa 3: Imports e Símbolos (15 pts)

Mesmo com strings ofuscadas, os imports de bibliotecas podem revelar funcionalidades:

```bash
# Listar símbolos dinâmicos
nm -D target/release/mystealer 2>/dev/null | head -50

# Ou usar objdump
objdump -T target/release/mystealer 2>/dev/null | head -50

# Verificar dependências
ldd target/release/mystealer 2>/dev/null
```

Identifique 3 funcionalidades suspeitas baseadas nos imports:
- Relacionadas a acesso a arquivos
- Relacionadas a rede
- Relacionadas a criptografia

**FLAG**: `CTF{funcao1_funcao2_funcao3}`

---

### Tarefa 4: Análise de Entropia (BONUS - 10 pts)

A ofuscação pode aumentar a entropia de seções do binário:

```bash
# Usando binwalk (se disponível)
binwalk -E target/release/mystealer

# Ou usando Python
python3 << 'EOF'
import math
with open('target/release/mystealer', 'rb') as f:
    data = f.read()
    freq = [data.count(i) for i in range(256)]
    total = len(data)
    entropy = -sum((f/total) * math.log2(f/total) for f in freq if f > 0)
    print(f"Entropy: {entropy:.2f} bits/byte")
    # 7.0+ = altamente comprimido/criptografado
    # 5.0-7.0 = código compilado normal
    # <5.0 = muitos dados estruturados
EOF
```

**FLAG**: `CTF{entropia_arredondada}` (ex: `CTF{6.5}`)

---

## Ferramentas Recomendadas

| Ferramenta | Uso |
|------------|-----|
| `file` | Identificar tipo de arquivo |
| `strings` | Extrair strings (limitado com ofuscação) |
| `nm` | Listar símbolos |
| `objdump` | Disassembly |
| `ltrace` | Trace de library calls |
| `binwalk` | Análise de entropia |
| `readelf` | Headers ELF |

---

## Dicas

1. **Strings vazia não significa sem funcionalidade** - significa ofuscação
2. Quando `strings` falha, mude para análise dinâmica (Challenge 02)
3. Compare binário release vs debug - o debug tem mais informação
4. Analise as bibliotecas linkadas - elas revelam funcionalidades

---

## Por que as strings estão escondidas?

O MyStealer v0.3.1 usa a técnica `bs()` (build string):

```rust
// Ao invés de:
let browser = "Chrome";  // ← Detectável com strings

// O malware usa:
fn bs(chars: &[char]) -> String {
    let mut s = String::with_capacity(chars.len());
    for &c in chars { s.push(c); }
    std::hint::black_box(s)
}
let browser = bs(&['C', 'h', 'r', 'o', 'm', 'e']);  // ← Invisível
```

Para reverter isso, veja o **Challenge 06**.

---

## Solução

<details>
<summary>Clique para ver as respostas (SPOILER)</summary>

### Tarefa 1
```bash
file target/release/mystealer
# ELF 64-bit LSB pie executable, x86-64...
```
**FLAG**: `CTF{elf64_x86_64}`

### Tarefa 2
```bash
strings target/release/mystealer | grep -iE "Chrome|Firefox" | wc -l
# 0 (zero resultados)
```
**FLAG**: `CTF{0}`

**Explicação**: A ofuscação bs() esconde todas as strings sensíveis.

### Tarefa 3
```bash
nm -D target/release/mystealer | grep -E "open|send|encrypt"
# Procure por: open, socket, aes, gcm, sqlite
```
**FLAG**: `CTF{sqlite_socket_aes}` (varia)

### Tarefa 4 (Bonus)
```bash
# Entropia típica de binário Rust otimizado: 5.5-6.5
```
**FLAG**: `CTF{6.0}` (aproximado)

</details>

---

## 📊 Resumo de Pontuação

| Tarefa | Pontos |
|--------|--------|
| 1 - Identificação | 10 |
| 2 - Strings (Vazio) | 15 |
| 3 - Imports | 15 |
| 4 - Entropia (Bonus) | +10 |
| **Total** | **40 (+10)** |

---

## 🔗 Próximo Challenge

A análise estática revelou que o binário é **ofuscado**. Para extrair informações úteis, você precisará:

- **Challenge 02**: Análise Dinâmica (comportamento em runtime)
- **Challenge 06**: Reverter a ofuscação de strings

---

*Atualizado para MyStealer v0.3.1 - Stealth Edition* 🕵️
