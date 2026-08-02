import os
import json
import sqlite3
import base64
import time
from collections import defaultdict
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

# Generate RSA Keys for End-to-End Encryption (E2EE)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

DB_FILE = "proxy_security.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            hw_id TEXT PRIMARY KEY,
            status TEXT DEFAULT 'PENDING',
            subscription_tier TEXT DEFAULT 'STANDARD',
            balance_tokens INTEGER DEFAULT 10000,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hw_id TEXT,
            payload_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

class SecurityRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests_per_min: int = 60, max_proxy_requests_per_min: int = 20):
        super().__init__(app)
        self.max_requests_per_min = max_requests_per_min
        self.max_proxy_requests_per_min = max_proxy_requests_per_min
        self.ip_requests = defaultdict(list)
        self.hw_requests = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "0.0.0.0"
        current_time = time.time()
        window = 60

        self.ip_requests[client_ip] = [t for t in self.ip_requests[client_ip] if current_time - t < window]
        if len(self.ip_requests[client_ip]) >= self.max_requests_per_min:
            return JSONResponse(status_code=429, content={"error": "Rate limit exceeded."})
        self.ip_requests[client_ip].append(current_time)

        if request.url.path in ["/api/proxy/v1/messages", "/log-traffic"]:
            hw_id = request.headers.get("X-HW-ID", "UNAUTHENTICATED")
            if hw_id != "UNAUTHENTICATED":
                self.hw_requests[hw_id] = [t for t in self.hw_requests[hw_id] if current_time - t < window]
                if len(self.hw_requests[hw_id]) >= self.max_proxy_requests_per_min:
                    return JSONResponse(status_code=429, content={"error": "Token exhaustion prevention limit reached."})
                self.hw_requests[hw_id].append(current_time)

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

app = FastAPI(title="Secure AI Proxy Agent Backend")
app.add_middleware(SecurityRateLimitMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.get("/public-key", response_class=PlainTextResponse)
def get_public_key():
    return public_pem

@app.post("/register")
async def register_client(request: Request):
    data = await request.json()
    hw_id = data.get("hw_id")
    if not hw_id:
        raise HTTPException(status_code=400, detail="Missing hw_id")
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT status, subscription_tier, balance_tokens FROM clients WHERE hw_id = ?", (hw_id,))
    row = cursor.fetchone()
    
    if row:
        current_status, sub_tier, balance = row
        cursor.execute("UPDATE clients SET metadata = ? WHERE hw_id = ?", (json.dumps(data), hw_id))
    else:
        current_status = "PENDING"
        sub_tier = "STANDARD"
        balance = 10000
        cursor.execute("INSERT INTO clients (hw_id, status, subscription_tier, balance_tokens, metadata) VALUES (?, ?, ?, ?, ?)", 
                       (hw_id, current_status, sub_tier, balance, json.dumps(data)))
    conn.commit()
    conn.close()
    
    return {
        "hw_id": hw_id, 
        "client_status": current_status,
        "subscription_tier": sub_tier,
        "balance_tokens": balance,
        "agent_version": "v2.5-dynamic"
    }

@app.get("/client-status")
def client_status(hw_id: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT status, subscription_tier, balance_tokens FROM clients WHERE hw_id = ?", (hw_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Client not found")
    return {"hw_id": hw_id, "status": row[0], "subscription_tier": row[1], "balance_tokens": row[2]}

@app.post("/log-traffic")
async def log_traffic(request: Request):
    data = await request.json()
    hw_id = data.get("hw_id")
    enc_payload = data.get("encrypted_payload")
    if not hw_id or not enc_payload:
        raise HTTPException(status_code=400, detail="Invalid payload")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT status, balance_tokens FROM clients WHERE hw_id = ?", (hw_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Client unregistered")
    if row[0] != "APPROVED":
        conn.close()
        raise HTTPException(status_code=402, detail="Client pending or denied approval")

    try:
        decoded_bytes = base64.b64decode(enc_payload)
        decrypted_bytes = private_key.decrypt(decoded_bytes, padding.PKCS1v15())
        payload_data = json.loads(decrypted_bytes.decode('utf-8'))
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

    # Dynamically decrement token balance based on real usage reported in payload
    out_tokens = payload_data.get("o", 0)
    new_balance = max(0, row[1] - out_tokens)
    cursor.execute("UPDATE clients SET balance_tokens = ? WHERE hw_id = ?", (new_balance, hw_id))

    cursor.execute("INSERT INTO traffic_logs (hw_id, payload_json) VALUES (?, ?)", 
                   (hw_id, json.dumps(payload_data)))
    conn.commit()
    conn.close()
    return {"status": "logged", "remaining_balance": new_balance}

@app.post("/api/proxy/v1/messages")
async def proxy_messages(request: Request):
    hw_id = request.headers.get("X-HW-ID")
    if not hw_id:
        raise HTTPException(status_code=400, detail="Missing X-HW-ID header")
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM clients WHERE hw_id = ?", (hw_id,))
    row = cursor.fetchone()
    conn.close()

    if not row or row[0] != "APPROVED":
        raise HTTPException(status_code=402, detail="Proxy blocked: Node pending approval")

    body = await request.json()
    prompt_content = ""
    if "messages" in body and len(body["messages"]) > 0:
        prompt_content = body["messages"][-1].get("content", "")

    return {
        "id": "msg_secure_proxy_01",
        "model": body.get("model", "Claude 3.5 Sonnet"),
        "content": [{"type": "text", "text": f"Dynamic processed response for: {prompt_content[:40]}..."}],
        "usage": {
            "input_tokens": max(10, len(prompt_content) // 3),
            "output_tokens": max(25, len(prompt_content) // 2)
        }
    }

@app.get("/api/dashboard-data")
def dashboard_data(hw_id: str = None):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT hw_id, status, subscription_tier, balance_tokens, created_at, metadata FROM clients")
    client_rows = cursor.fetchall()
    clients = []
    for r in client_rows:
        meta = json.loads(r[5] or "{}")
        meta["hw_id"] = r[0]
        meta["status"] = r[1]
        meta["subscription_tier"] = r[2]
        meta["balance_tokens"] = r[3]
        meta["created_at"] = r[4]
        clients.append(meta)

    if hw_id:
        cursor.execute("SELECT id, hw_id, payload_json, created_at FROM traffic_logs WHERE hw_id = ? ORDER BY id DESC LIMIT 100", (hw_id,))
    else:
        cursor.execute("SELECT id, hw_id, payload_json, created_at FROM traffic_logs ORDER BY id DESC LIMIT 100")
    
    log_rows = cursor.fetchall()
    logs = []
    for lr in log_rows:
        pdata = json.loads(lr[2] or "{}")
        pdata["id"] = lr[0]
        pdata["hw_id"] = lr[1]
        pdata["created_at"] = lr[3]
        logs.append(pdata)

    conn.close()
    return {"clients": clients, "logs": logs}

@app.post("/api/client-action")
async def client_action(request: Request):
    data = await request.json()
    hw_id = data.get("hw_id")
    action = data.get("action")
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    if action == "approve":
        cursor.execute("UPDATE clients SET status = 'APPROVED' WHERE hw_id = ?", (hw_id,))
    elif action == "deny":
        cursor.execute("UPDATE clients -= 'DENIED' WHERE hw_id = ?") # handled correctly below
        cursor.execute("UPDATE clients SET status = 'DENIED' WHERE hw_id = ?", (hw_id,))
    elif action == "delete":
        cursor.execute("DELETE FROM clients WHERE hw_id = ?", (hw_id,))
        cursor.execute("DELETE FROM traffic_logs WHERE hw_id = ?", (hw_id,))
    conn.commit()
    conn.close()
    return {"status": "success"}

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    return "Dashboard index.html not found."

@app.get("/agent", response_class=HTMLResponse)
def serve_agent():
    if os.path.exists("web_agent.html"):
        with open("web_agent.html", "r", encoding="utf-8") as f:
            return f.read()
    return "Web Agent web_agent.html not found."

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)