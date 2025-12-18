# 🎯 Desafio 03: Engenharia Reversa

**Dificuldade**: ⭐⭐⭐ Difícil  
**Pontos**: 100  
**Versão**: v0.3.1 (Stealth Edition)

---

## ⚠️ Nota sobre Ofuscação

Na versão 0.3.1, strings estão ofuscadas. No entanto, a **criptografia** ainda pode ser identificada via:
- Análise de bibliotecas linkadas
- Padrões de bytecode (S-box AES)
- Código fonte (se disponível)
- Debugging dinâmico

---

## Objetivo

Faça engenharia reversa do binário para entender a criptografia usada.

## Contexto

O malware criptografa os dados antes de exfiltrar. Você precisa entender o algoritmo e descriptografar uma amostra de dados capturada.

## Tarefas

### Tarefa 1: Identificar Criptografia (15 pts)

Analise o código para identificar:

1. Qual algoritmo de criptografia é usado?
2. Qual tamanho de chave?
3. Qual modo de operação?

```bash
# Buscar símbolos relacionados a crypto (pode estar stripped)
nm target/release/mystealer 2>/dev/null | grep -i "aes\|encrypt\|gcm"

# Verificar bibliotecas linkadas
ldd target/release/mystealer | grep -i "ssl\|crypto"

# Buscar padrões de S-box AES no binário (sempre funciona!)
xxd target/release/mystealer | grep -i "637c 777b"

# Ou analisar o código fonte
grep -r "Aes\|encrypt\|gcm\|Argon2" src/
```

> **💡 Dica**: Mesmo com símbolos stripped, o padrão S-box do AES (`63 7c 77 7b f2 6b...`) é detectável no binário.

**FLAG**: `CTF{algoritmo_bits_modo}`

### Tarefa 2: Derivação de Chave (25 pts)

A chave é derivada de informações do sistema. Descubra:

1. Qual função de derivação é usada?
2. Quais inputs são usados?
3. Qual o salt?

Analise `src/crypto/mod.rs`:

```rust
// Encontre a função de derivação
// Identifique os parâmetros
```

**FLAG**: `CTF{kdf_input1_input2}`

### Tarefa 3: Descriptografar Dados (30 pts)

Dado o seguinte arquivo criptografado (base64):

```
AQAAAAAAAABIZWxsbywgQ1RGIFBsYXllciE=
```

E sabendo que:
- Versão: 0x01
- Nonce: primeiros 12 bytes após versão
- Chave de teste: `0x42` repetido 32 vezes

Escreva um script para descriptografar:

```python
# decrypt.py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

def decrypt(ciphertext_b64, key):
    data = base64.b64decode(ciphertext_b64)
    version = data[0]
    nonce = data[1:13]
    ciphertext = data[13:]
    
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    
    return plaintext.decode()

# Sua solução aqui
key = bytes([0x42] * 32)
result = decrypt("...", key)
print(result)
```

**FLAG**: O texto descriptografado contém a flag

### Tarefa 4: Criar Decryptor (30 pts)

Crie uma ferramenta em Rust que:

1. Leia um arquivo `.bin` criptografado
2. Derive a chave da mesma forma que o malware
3. Descriptografe e exiba o conteúdo

```rust
// decryptor/src/main.rs
use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let encrypted = fs::read("captured_data.bin")?;
    
    // Implementar derivação de chave
    // Implementar descriptografia
    // Exibir resultado
    
    Ok(())
}
```

**FLAG**: Execute seu decryptor e capture: `CTF{???}`

## Ferramentas Recomendadas

- `Ghidra` - Disassembler/Decompiler
- `radare2` / `rizin` - Análise binária
- `gdb` - Debugger
- Python + `cryptography` - Para scripts

## Dicas

1. Comece pelo código fonte antes do binário
2. Use breakpoints nas funções de crypto
3. Compare implementação com documentação do AES-GCM
4. O formato é: `version(1) || nonce(12) || ciphertext`

## Material de Referência

- [AES-GCM RFC 5116](https://tools.ietf.org/html/rfc5116)
- [Argon2 Spec](https://github.com/P-H-C/phc-winner-argon2)
- [Rust AES-GCM Docs](https://docs.rs/aes-gcm/)

## Solução

<details>
<summary>Clique para ver as respostas (SPOILER)</summary>

### Tarefa 1
- Algoritmo: AES-256-GCM
- Chave: 256 bits
- Modo: GCM (Galois/Counter Mode)

FLAG: `CTF{aes_256_gcm}`

### Tarefa 2
- KDF: Argon2
- Inputs: machine_id, username
- Salt: fixo baseado em string do projeto

FLAG: `CTF{argon2_machineid_salt}`

### Tarefa 3
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

data = base64.b64decode("AQAAAAAAAABIZWxsbywgQ1RGIFBsYXllciE=")
# Nota: Este é um exemplo simplificado
# A flag real estaria no ciphertext correto
```

### Tarefa 4
```rust
use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead, Nonce};

fn decrypt(encrypted: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = Nonce::from_slice(&encrypted[1..13]);
    cipher.decrypt(nonce, &encrypted[13..]).unwrap()
}
```

</details>

---

**Pontuação Total**: 100 pontos
**Dificuldade**: ⭐⭐⭐ Difícil

