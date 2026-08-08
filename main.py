import base64
import io
import json
import logging
import os
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Optional

from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
import httpx
from sqlalchemy.orm import Session

from database import Base, SessionLocal, ClientModel, TrafficLogModel, cipher, engine, init_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [GATEWAY] %(message)s")
logger = logging.getLogger("EnterpriseSecurityGateway")

app = FastAPI(title="Enterprise Cloud AI Gateway & Control Plane", version="3.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.on_event("startup")
def startup_event():
    init_db()
    logger.info("Database initialized successfully.")

@app.get("/")
def serve_dashboard():
    return HTMLResponse(DASHBOARD_HTML)

@app.post("/log-traffic")
async def log_traffic(request: Request, db: Session = Depends(get_db)):
    body = await request.json()
    hw_id = body.get("hw_id")
    if not hw_id:
        raise HTTPException(status_code=400, detail="Missing hardware identifier")

    client = db.query(ClientModel).filter(ClientModel.hw_id == hw_id).first()
    if not client:
        client = ClientModel(
            hw_id=hw_id,
            api_key=f"sk_tenant_{secrets.token_hex(16)}",
            status="APPROVED",
            subscription_tier="PRO",
            balance_tokens=50000,
            metadata_json=json.dumps({"registered_via": "daemon"})
        )
        db.add(client)
        db.commit()

    total_tokens = int(body.get("prompt_tokens", 0)) + int(body.get("completion_tokens", 0))
    client.balance_tokens = max(0, client.balance_tokens - total_tokens)

    payload_data = {
        "provider": body.get("provider", "Universal Local Interceptor"),
        "m": body.get("model", "gemini-2.5-flash"),
        "query": body.get("payload", ""),
        "response": "Processed securely",
        "i": body.get("prompt_tokens", 0),
        "o": body.get("completion_tokens", 0),
        "latency": body.get("latency_ms", 120),
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    }

    encrypted_db_payload = cipher.encrypt(json.dumps(payload_data).encode()).decode()
    
    log_entry = TrafficLogModel(
        hw_id=hw_id,
        provider=payload_data["provider"],
        model=payload_data["m"],
        prompt_tokens=payload_data["i"],
        completion_tokens=payload_data["o"],
        latency_ms=payload_data["latency"],
        payload_json=encrypted_db_payload
    )
    db.add(log_entry)
    db.commit()

    return {"status": "success", "remaining_balance": client.balance_tokens}

@app.get("/api/dashboard-data")
def dashboard_data(db: Session = Depends(get_db)):
    client_rows = db.query(ClientModel).all()
    log_rows = db.query(TrafficLogModel).order_by(TrafficLogModel.id.desc()).limit(100).all()

    clients = [{
        "hw_id": c.hw_id,
        "status": c.status,
        "subscription_tier": c.subscription_tier,
        "balance_tokens": c.balance_tokens,
        "created_at": str(c.created_at),
    } for c in client_rows]

    logs = []
    for l in log_rows:
        try:
            payload = json.loads(cipher.decrypt(l.payload_json.encode()).decode())
        except:
            payload = {"query": "Encrypted", "response": "Encrypted"}
        logs.append({
            "id": l.id,
            "hw_id": l.hw_id,
            "timestamp_utc": payload.get("timestamp_utc", str(l.created_at)),
            "provider": f"{l.provider} / {l.model}",
            "tokens": (l.prompt_tokens or 0) + (l.completion_tokens or 0),
            "latency_ms": l.latency_ms,
            "prompt": payload.get("query", ""),
            "response": payload.get("response", "")
        })

    return {"clients": clients, "logs": logs}

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Enterprise Cloud AI Gateway & Control Plane</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 p-6 min-h-screen">
    <div class="max-w-6xl mx-auto space-y-6">
        <header class="flex justify-between items-center border-b border-slate-800 pb-4">
            <h1 class="text-xl font-bold">Enterprise Cloud AI Gateway & Control Plane</h1>
            <button onclick="loadData()" class="px-4 py-2 bg-indigo-600 rounded-lg text-xs font-semibold">Refresh Telemetry</button>
        </header>
        <div class="grid grid-cols-2 gap-4">
            <div class="bg-slate-900 border border-slate-800 p-4 rounded-xl">
                <h3 class="text-xs uppercase text-slate-400">Total Tenants</h3>
                <p id="total-tenants" class="text-2xl font-bold mt-1">0</p>
            </div>
            <div class="bg-slate-900 border border-slate-800 p-4 rounded-xl">
                <h3 class="text-xs uppercase text-slate-400">Approved Nodes</h3>
                <p id="approved-nodes" class="text-2xl font-bold text-emerald-400 mt-1">0</p>
            </div>
        </div>
        <div class="bg-slate-900 border border-slate-800 p-4 rounded-xl">
            <h3 class="text-xs font-bold uppercase mb-3">Live Telemetry Log</h3>
            <div class="overflow-x-auto">
                <table class="w-full text-left text-xs font-mono">
                    <thead class="border-b border-slate-800 text-slate-400">
                        <tr>
                            <th class="p-2">Timestamp</th>
                            <th class="p-2">Hardware ID</th>
                            <th class="p-2">Provider / Model</th>
                            <th class="p-2">Tokens</th>
                            <th class="p-2">Latency</th>
                            <th class="p-2">Prompt</th>
                        </tr>
                    </thead>
                    <tbody id="log-table" class="divide-y divide-slate-800">
                        <tr><td colspan="6" class="p-4 text-center text-slate-500">Loading logs...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    <script>
        async function loadData() {
            const res = await fetch('/api/dashboard-data');
            const data = await res.json();
            document.getElementById('total-tenants').innerText = data.clients.length;
            document.getElementById('approved-nodes').innerText = data.clients.filter(c => c.status === 'APPROVED').length;
            const tbody = document.getElementById('log-table');
            if(!data.logs.length) { tbody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-slate-500">No logs found</td></tr>`; return; }
            tbody.innerHTML = data.logs.map(l => `
                <tr class="hover:bg-slate-800/40">
                    <td class="p-2 text-slate-400">${l.timestamp_utc}</td>
                    <td class="p-2 text-indigo-400 font-bold">${l.hw_id}</td>
                    <td class="p-2">${l.provider}</td>
                    <td class="p-2 text-emerald-400">${l.tokens}</td>
                    <td class="p-2 text-amber-400">${l.latency_ms}ms</td>
                    <td class="p-2 text-slate-300 truncate max-w-xs">${l.prompt}</td>
                </tr>
            `).join('');
        }
        loadData();
        setInterval(loadData, 5000);
    </script>
</body>
</html>
"""