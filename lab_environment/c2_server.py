#!/usr/bin/env python3
"""
Mock C2 Server for MyStealer CTF Lab

Este servidor simula um Command & Control server para fins educacionais.
APENAS para uso em ambiente de laboratório isolado.
"""

import os
import json
import base64
import logging
from datetime import datetime
from pathlib import Path

from flask import Flask, request, jsonify
from flask_cors import CORS

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
        logging.FileHandler(LOG_DIR / "c2_server.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


@app.route('/health', methods=['GET'])
def health_check():
    """Endpoint de health check"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "mystealer-c2-mock"
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
        logger.info(f"Recebido dados de sessão: {session_id}")
        logger.debug(f"Headers: {dict(request.headers)}")
        
        # Obter dados
        data = request.get_data()
        
        # Criar diretório para sessão
        session_dir = DATA_DIR / session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        
        # Nome do arquivo
        if chunk_index:
            filename = f"chunk_{chunk_index}_{total_chunks}.bin"
        else:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
            filename = f"data_{timestamp}.bin"
        
        # Salvar dados
        filepath = session_dir / filename
        with open(filepath, 'wb') as f:
            f.write(data)
        
        logger.info(f"Dados salvos em: {filepath}")
        
        # Tentar decodificar e analisar
        try:
            decoded = base64.b64decode(data)
            analysis_path = session_dir / f"{filename}.analysis.txt"
            with open(analysis_path, 'w') as f:
                f.write(f"Timestamp: {datetime.utcnow().isoformat()}\n")
                f.write(f"Session ID: {session_id}\n")
                f.write(f"Data Size: {len(decoded)} bytes\n")
                f.write(f"Base64 Size: {len(data)} bytes\n")
                f.write("-" * 50 + "\n")
                
                # Se parece JSON, formatar
                try:
                    json_data = json.loads(decoded)
                    f.write("Type: JSON\n")
                    f.write(json.dumps(json_data, indent=2))
                except:
                    f.write("Type: Binary/Encrypted\n")
                    f.write(f"Preview (hex): {decoded[:100].hex()}\n")
        except Exception as e:
            logger.warning(f"Não foi possível analisar dados: {e}")
        
        return jsonify({
            "status": "received",
            "session_id": session_id,
            "size": len(data),
            "filename": filename
        }), 200
        
    except Exception as e:
        logger.error(f"Erro ao processar dados: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/beacon', methods=['POST'])
def beacon():
    """
    Endpoint de beacon para check-in de agentes.
    """
    try:
        data = request.get_json() or {}
        session_id = data.get('session_id', 'unknown')
        
        logger.info(f"Beacon recebido de: {session_id}")
        
        # Log do beacon
        beacon_file = DATA_DIR / "beacons.log"
        with open(beacon_file, 'a') as f:
            f.write(json.dumps({
                "timestamp": datetime.utcnow().isoformat(),
                "session_id": session_id,
                "data": data,
                "remote_ip": request.remote_addr
            }) + "\n")
        
        # Resposta (poderia conter comandos em C2 real)
        return jsonify({
            "status": "ok",
            "commands": [],  # Em C2 real, teria comandos aqui
            "sleep": 60  # Intervalo até próximo beacon
        })
        
    except Exception as e:
        logger.error(f"Erro no beacon: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/sessions', methods=['GET'])
def list_sessions():
    """
    Lista todas as sessões recebidas.
    Útil para análise do lab.
    """
    sessions = []
    
    for session_dir in DATA_DIR.iterdir():
        if session_dir.is_dir():
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
            files.append({
                "name": f.name,
                "size": f.stat().st_size,
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat()
            })
    
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


@app.route('/', methods=['GET'])
def index():
    """Página inicial"""
    return """
    <html>
    <head>
        <title>MyStealer CTF Lab - Mock C2</title>
        <style>
            body { 
                font-family: 'Courier New', monospace; 
                background: #1a1a2e; 
                color: #0f0; 
                padding: 40px; 
            }
            h1 { color: #ff0; }
            a { color: #0ff; }
            pre { background: #000; padding: 20px; border-radius: 5px; }
            .warning { color: #f00; }
        </style>
    </head>
    <body>
        <h1>🎯 MyStealer CTF Lab - Mock C2 Server</h1>
        <p class="warning">⚠️ APENAS PARA FINS EDUCACIONAIS</p>
        
        <h2>Endpoints Disponíveis:</h2>
        <pre>
GET  /health          - Health check
POST /collect         - Receber dados exfiltrados
POST /beacon          - Check-in de agentes
GET  /sessions        - Listar sessões
GET  /sessions/{id}   - Detalhes de sessão
GET  /download/{id}/{file} - Download de arquivo
        </pre>
        
        <h2>Sessões Ativas:</h2>
        <p><a href="/sessions">Ver todas as sessões</a></p>
        
        <hr>
        <p>MyStealer CTF Lab - Educational Purposes Only</p>
    </body>
    </html>
    """


if __name__ == '__main__':
    # Criar diretórios
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    logger.info("=== MyStealer Mock C2 Server ===")
    logger.info("Starting server on port 8080...")
    logger.info("Data directory: " + str(DATA_DIR))
    
    app.run(host='0.0.0.0', port=8080, debug=True)

