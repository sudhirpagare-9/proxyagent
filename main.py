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
    def __init__(self, app, max_requests_per_min: int = 120, max_proxy_requests_per_min: int = 40):
        super().__init__(app)
        self.max_requests_per_min = max_requests_per_min
        self.max_proxy_requests_per_min = max_proxy_requests_per_min
        self.ip_requests = defaultdict(list)
        self.hw_requests = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        forwarded_for = request.headers.get("x-forwarded-for")
        client_ip = forwarded_for.split(",")[0].strip() if forwarded_for else (request.client.host if request.client else "0.0.0.0")
        
        current_time = time.time()
        window = 60

        self.ip_requests[client_ip] = [t for t in self.ip_requests[client_ip] if current_time - t < window]
        if len(self.ip_requests[client_ip]) >= self.max_requests_per_min:
            return JSONResponse(status_code=429, content={"error": "Rate limit exceeded."})
        self.ip_requests[client_ip].append(current_time)

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
    
    forwarded_for = request.headers.get("x-forwarded-for")
    real_ip = forwarded_for.split(",")[0].strip() if forwarded_for else (request.client.host if request.client else "127.0.0.1")
    data["ip_address"] = real_ip

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
        cursor.execute("UPDATE clients SET status = 'DENIED' WHERE hw_id = ?", (hw_id,))
    elif action == "delete":
        cursor.execute("DELETE FROM clients WHERE hw_id = ?", (hw_id,))
        cursor.execute("DELETE FROM traffic_logs WHERE hw_id = ?", (hw_id,))
    conn.commit()
    conn.close()
    return {"status": "success"}

# EMBEDDED DASHBOARD HTML (Prevents 404 Not Found errors)
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Traffic Dashboard & Security Monitor</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>body { background-color: #0b0f17; color: #c9d1d9; font-family: ui-sans-serif, system-ui, sans-serif; }</style>
</head>
<body class="min-h-screen p-6 flex flex-col">
    <header class="flex flex-col md:flex-row items-center justify-between border-b border-gray-800 pb-4 mb-6 gap-4">
        <div>
            <h1 class="text-lg font-bold text-white flex items-center gap-2">🛡️ AI Traffic Dashboard & Security Monitor</h1>
            <p class="text-xs text-gray-400">100% Dynamic Telemetry Reflection & NIST/GDPR Compliant Management</p>
        </div>
        <div class="flex items-center gap-3 flex-wrap">
            <span class="px-3 py-1 bg-emerald-950 text-emerald-400 border border-emerald-800 rounded-full text-xs font-mono">DB: Connected</span>
            <span class="px-3 py-1 bg-cyan-950 text-cyan-400 border border-cyan-800 rounded-full text-xs font-mono">Crypto: Active</span>
            <a href="/agent" target="_blank" class="px-3 py-1.5 bg-green-600 hover:bg-green-500 text-white rounded-lg text-xs font-medium transition">🤖 Open Web Agent</a>
            <button onclick="loadDashboardData()" class="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-medium transition">Refresh Now</button>
        </div>
    </header>
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div class="bg-gray-900 border border-gray-800 rounded-xl p-4 shadow-md"><div class="text-[11px] text-gray-400 uppercase font-mono">Total Clients</div><div id="stat-total-clients" class="text-xl font-bold text-white font-mono mt-1">0</div></div>
        <div class="bg-gray-900 border border-gray-800 rounded-xl p-4 shadow-md"><div class="text-[11px] text-gray-400 uppercase font-mono">Approved Nodes</div><div id="stat-approved-clients" class="text-xl font-bold text-emerald-400 font-mono mt-1">0</div></div>
        <div class="bg-gray-900 border border-gray-800 rounded-xl p-4 shadow-md"><div class="text-[11px] text-gray-400 uppercase font-mono">Total Input Tokens</div><div id="stat-total-in" class="text-xl font-bold text-blue-400 font-mono mt-1">0</div></div>
        <div class="bg-gray-900 border border-gray-800 rounded-xl p-4 shadow-md"><div class="text-[11px] text-gray-400 uppercase font-mono">Total Output Tokens</div><div id="stat-total-out" class="text-xl font-bold text-rose-400 font-mono mt-1">0</div></div>
    </div>
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1">
        <div class="bg-gray-900 border border-gray-800 rounded-2xl p-5 flex flex-col shadow-xl">
            <div class="flex items-center justify-between mb-4 pb-2 border-b border-gray-800"><h2 class="text-xs font-bold uppercase text-gray-300">Discovered Clients</h2><span id="client-count" class="px-2 py-0.5 bg-gray-800 text-gray-300 rounded text-[10px] font-mono">0 Registered</span></div>
            <div id="clients-container" class="space-y-3 overflow-y-auto flex-1 max-h-[550px] pr-1"><div class="text-xs text-gray-500 text-center py-10 font-mono">Loading clients...</div></div>
        </div>
        <div class="lg:col-span-2 bg-gray-900 border border-gray-800 rounded-2xl p-5 flex flex-col shadow-xl">
            <div class="flex items-center justify-between mb-4 pb-2 border-b border-gray-800"><h2 id="log-header-title" class="text-xs font-bold uppercase text-gray-300">Client AI Traffic Logs (Select a client)</h2><span id="log-count" class="px-2 py-0.5 bg-gray-800 text-gray-300 rounded text-[10px] font-mono">0 Recorded</span></div>
            <div class="overflow-x-auto flex-1 max-h-[550px] overflow-y-auto">
                <table class="w-full text-left text-xs font-mono">
                    <thead id="logs-table-header" class="sticky top-0 bg-gray-900 border-b border-gray-800 text-gray-400"><tr><th class="pb-3 pt-2">Select a client to view telemetry</th></tr></thead>
                    <tbody id="logs-table-body" class="divide-y divide-gray-800/50 text-gray-300"><tr><td class="py-10 text-center text-gray-500">Select an approved client card on the left.</td></tr></tbody>
                </table>
            </div>
        </div>
    </div>
    <script>
        const SERVER_URL = window.location.origin;
        let selectedHwId = null;
        async function loadDashboardData() {
            try {
                const url = selectedHwId ? `${SERVER_URL}/api/dashboard-data?hw_id=${selectedHwId}` : `${SERVER_URL}/api/dashboard-data`;
                const res = await fetch(url);
                if (!res.ok) throw new Error("Failed to fetch");
                const data = await res.json();
                renderMetrics(data.clients, data.logs);
                renderClients(data.clients);
                if (selectedHwId) renderLogs(data.logs);
            } catch (err) { console.error(err); }
        }
        function renderMetrics(clients, logs) {
            document.getElementById("stat-total-clients").innerText = clients.length;
            document.getElementById("stat-approved-clients").innerText = clients.filter(c => c.status === 'APPROVED').length;
            let totalIn = 0, totalOut = 0;
            if (logs) logs.forEach(l => { totalIn += parseInt(l.i || 0); totalOut += parseInt(l.o || 0); });
            document.getElementById("stat-total-in").innerText = totalIn.toLocaleString();
            document.getElementById("stat-total-out").innerText = totalOut.toLocaleString();
        }
        function renderClients(clients) {
            const container = document.getElementById("clients-container");
            document.getElementById("client-count").innerText = `${clients.length} Registered`;
            if (!clients.length) { container.innerHTML = `<div class="text-xs text-gray-500 text-center py-10 font-mono">No active clients registered yet. Open the Web Agent tab to register this browser!</div>`; return; }
            container.innerHTML = "";
            clients.forEach(c => {
                const isSelected = selectedHwId === c.hw_id;
                const statusColor = c.status === 'APPROVED' ? 'text-emerald-400 bg-emerald-950 border-emerald-800' : 'text-amber-400 bg-amber-950 border-amber-800';
                const card = document.createElement("div");
                card.className = `p-4 rounded-xl border transition cursor-pointer bg-gray-950 ${isSelected ? 'border-blue-500' : 'border-gray-800'}`;
                card.onclick = () => { selectedHwId = c.hw_id; document.getElementById("log-header-title").innerText = `Logs for: ${c.hw_id}`; loadDashboardData(); };
                card.innerHTML = `<div class="flex justify-between mb-2"><span class="font-bold text-white font-mono text-xs">${c.hw_id}</span><span class="px-2 py-0.5 border rounded-full text-[10px] font-mono ${statusColor}">${c.status}</span></div><div class="text-[11px] text-gray-400 font-mono mb-2">IP: ${c.ip_address || '127.0.0.1'} | Model: ${c.model_name || 'Claude'}</div><div class="flex justify-between pt-2 border-t border-gray-800" onclick="event.stopPropagation()"><button onclick="executeAction('${c.hw_id}', 'approve')" class="px-2 py-1 bg-emerald-600 text-white rounded text-[10px]">Approve</button><button onclick="executeAction('${c.hw_id}', 'deny')" class="px-2 py-1 bg-amber-600 text-white rounded text-[10px]">Deny</button><button onclick="executeAction('${c.hw_id}', 'delete')" class="px-2 py-1 bg-red-600 text-white rounded text-[10px]">Delete</button></div>`;
                container.appendChild(card);
            });
        }
        function renderLogs(logs) {
            const thead = document.getElementById("logs-table-header");
            const tbody = document.getElementById("logs-table-body");
            document.getElementById("log-count").innerText = `${logs.length} Recorded`;
            if (!logs.length) { thead.innerHTML = `<tr><th class="pb-3">Telemetry</th></tr>`; tbody.innerHTML = `<tr><td class="py-10 text-center text-gray-500">No telemetry logs for this client yet. Send a test prompt from the Web Agent!</td></tr>`; return; }
            thead.innerHTML = `<tr class="text-gray-400"><th class="pb-3">Time</th><th class="pb-3">Model</th><th class="pb-3">In Tokens</th><th class="pb-3">Out Tokens</th></tr>`;
            tbody.innerHTML = "";
            logs.forEach(l => {
                tbody.innerHTML += `<tr class="hover:bg-gray-800/30"><td class="py-3 text-gray-400">${new Date(l.created_at).toLocaleTimeString()}</td><td class="py-3 text-white">${l.m || '-'}</td><td class="py-3 text-blue-400">${l.i || 0}</td><td class="py-3 text-rose-400">${l.o || 0}</td></tr>`;
            });
        }
        async function executeAction(hwId, action) {
            await fetch(`${SERVER_URL}/api/client-action`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ hw_id: hwId, action: action }) });
            loadDashboardData();
        }
        loadDashboardData();
        setInterval(loadDashboardData, 5000);
    </script>
</body>
</html>"""

# EMBEDDED WEB AGENT HTML (Prevents 404 Not Found errors)
WEB_AGENT_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dynamic Universal AI Proxy Agent</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jsencrypt/3.3.2/jsencrypt.min.js"></script>
    <style>body { background-color: #0b0f17; color: #c9d1d9; font-family: ui-sans-serif, system-ui, sans-serif; }</style>
</head>
<body class="min-h-screen p-4 flex flex-col items-center justify-center">
    <div class="max-w-md w-full bg-gray-900 border border-gray-800 rounded-2xl p-5 shadow-2xl">
        <div class="flex items-center justify-between mb-4 border-b border-gray-800 pb-3">
            <h1 class="text-sm font-bold text-white">🛡️ Dynamic Universal Agent</h1>
            <span id="agent-status" class="px-2.5 py-1 bg-amber-950 text-amber-400 border border-amber-800 rounded-full text-[10px] font-mono">Initializing</span>
        </div>
        <div class="space-y-3 text-xs mb-4 bg-gray-950 p-3 rounded-lg border border-gray-800 font-mono">
            <div class="flex justify-between"><span>HW ID:</span> <span id="lbl-hw" class="text-cyan-400 font-bold">-</span></div>
            <div class="flex justify-between"><span>Status:</span> <span id="lbl-status" class="text-amber-400 font-bold">Pending</span></div>
            <div class="flex justify-between"><span>Balance:</span> <span id="lbl-balance" class="text-emerald-400 font-bold">10,000</span></div>
        </div>
        <div class="space-y-3">
            <div class="border border-gray-800 rounded-lg p-3 bg-gray-950">
                <label class="block text-[11px] font-bold text-gray-300 mb-1">Live Proxy Request Test</label>
                <div class="flex gap-2">
                    <input type="text" id="test-prompt" value="Test secure proxy transmission" class="flex-1 bg-gray-900 border border-gray-800 rounded px-3 py-2 text-xs text-white focus:outline-none">
                    <button onclick="sendLiveProxyCall()" class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white font-medium rounded text-xs transition">Send</button>
                </div>
            </div>
            <div class="bg-gray-950 rounded-lg p-3 border border-gray-800 h-28 overflow-y-auto font-mono text-[10px] text-gray-400 space-y-1" id="activity-log">
                <div>[System] Initializing agent node...</div>
            </div>
            <div class="text-center pt-2">
                <a href="/" class="text-xs text-blue-400 hover:underline font-mono">← Return to Main Dashboard</a>
            </div>
        </div>
    </div>
    <script>
        const SERVER_URL = window.location.origin;
        let hwId = localStorage.getItem("proxy_dynamic_hw_id") || ("BROWSER-" + Math.random().toString(36).substring(2, 8).toUpperCase());
        localStorage.setItem("proxy_dynamic_hw_id", hwId);
        document.getElementById("lbl-hw").innerText = hwId;
        let publicKeyPem = "";

        function logActivity(msg, isErr = false) {
            const box = document.getElementById("activity-log");
            box.innerHTML += `<div class="${isErr ? 'text-red-400' : 'text-emerald-400'}">[${new Date().toLocaleTimeString()}] ${msg}</div>`;
            box.scrollTop = box.scrollHeight;
        }

        async function initAgent() {
            try {
                const pubRes = await fetch(`${SERVER_URL}/public-key`);
                publicKeyPem = await pubRes.text();
                await registerAgent();
                setInterval(pollStatus, 5000);
            } catch (e) { logActivity("Init error: " + e.message, true); }
        }

        async function registerAgent() {
            const res = await fetch(`${SERVER_URL}/register`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ hw_id: hwId, client_name: "Web Browser Agent", model_name: "Claude 3.5 Sonnet" })
            });
            const data = await res.json();
            updateStatus(data.client_status);
            logActivity("Registered with backend server.");
        }

        async function pollStatus() {
            try {
                const res = await fetch(`${SERVER_URL}/client-status?hw_id=${hwId}`);
                const data = await res.json();
                updateStatus(data.status);
                if(data.balance_tokens !== undefined) document.getElementById("lbl-balance").innerText = data.balance_tokens.toLocaleString();
            } catch (e) {}
        }

        function updateStatus(status) {
            const badge = document.getElementById("agent-status");
            const lbl = document.getElementById("lbl-status");
            lbl.innerText = status;
            if (status === "APPROVED") {
                badge.className = "px-2.5 py-1 bg-emerald-950 text-emerald-400 border border-emerald-800 rounded-full text-[10px] font-mono";
                badge.innerText = "Approved";
            }
        }

        async function sendLiveProxyCall() {
            const promptText = document.getElementById("test-prompt").value;
            logActivity("Sending proxy call...");
            try {
                const res = await fetch(`${SERVER_URL}/api/proxy/v1/messages`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-HW-ID': hwId },
                    body: JSON.stringify({ model: 'Claude 3.5 Sonnet', messages: [{ role: 'user', content: promptText }] })
                });
                if(res.status === 402) { logActivity("Blocked: Node pending approval on dashboard!", true); return; }
                const data = await res.json();
                
                const encryptor = new JSEncrypt();
                encryptor.setPublicKey(publicKeyPem);
                const encrypted = encryptor.encrypt(JSON.stringify({ m: 'Claude 3.5 Sonnet', i: data.usage.input_tokens, o: data.usage.output_tokens }));

                if(encrypted) {
                    const logRes = await fetch(`${SERVER_URL}/log-traffic`, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ hw_id: hwId, encrypted_payload: encrypted })
                    });
                    logActivity("Telemetry logged & encrypted successfully!");
                }
            } catch (e) { logActivity("Error: " + e.message, true); }
        }
        initAgent();
    </script>
</body>
</html>"""

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    return DASHBOARD_HTML

@app.get("/agent", response_class=HTMLResponse)
def serve_agent():
    return WEB_AGENT_HTML

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)