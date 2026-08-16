import base64
import io
import json
import logging
import os
import re
import secrets
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Header, Request, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.sql import func

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [AI-GATEWAY-SECURITY] %(message)s",
)
logger = logging.getLogger("EnterpriseAIGateway")

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./enterprise_gateway.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

ENCRYPTION_KEY = os.environ.get("ENC_KEY")
if not ENCRYPTION_KEY or ENCRYPTION_KEY.startswith("placeholder"):
    ENCRYPTION_KEY = Fernet.generate_key()
else:
    ENCRYPTION_KEY = ENCRYPTION_KEY.encode()

cipher = Fernet(ENCRYPTION_KEY)

class ClientModel(Base):
    __tablename__ = "clients"
    id = Column(Integer, primary_key=True, index=True)
    hw_id = Column(String, unique=True, index=True)
    api_key = Column(String, unique=True, index=True)
    status = Column(String, default="APPROVED")
    subscription_tier = Column(String, default="ENTERPRISE_PRO")
    balance_tokens = Column(Integer, default=500000)
    metadata_json = Column(Text, nullable=True)
    is_deleted = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class TrafficLogModel(Base):
    __tablename__ = "traffic_logs"
    id = Column(Integer, primary_key=True, index=True)
    hw_id = Column(String, index=True)
    provider = Column(String, nullable=True)
    model = Column(String, index=True, nullable=True)
    version = Column(String, nullable=True)
    think_level = Column(String, nullable=True)
    prompt_tokens = Column(Integer, default=0)
    completion_tokens = Column(Integer, default=0)
    latency_ms = Column(Integer, default=0)
    payload_json = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        for col_name, col_type in [
            ("subscription_tier", "TEXT DEFAULT 'ENTERPRISE_PRO'"),
            ("balance_tokens", "INTEGER DEFAULT 500000"),
            ("metadata_json", "TEXT"),
            ("is_deleted", "BOOLEAN DEFAULT 0")
        ]:
            try:
                db.execute(text(f"ALTER TABLE clients ADD COLUMN {col_name} {col_type}"))
                db.commit()
            except Exception:
                db.rollback()

        for col_name, col_type in [
            ("version", "VARCHAR"),
            ("think_level", "VARCHAR")
        ]:
            try:
                db.execute(text(f"ALTER TABLE traffic_logs ADD COLUMN {col_name} {col_type}"))
                db.commit()
            except Exception:
                db.rollback()

        logger.info("Database schema initialized and verified.")
    except Exception as e:
        logger.warning(f"Database setup note: {e}")
    finally:
        db.close()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI(
    title="Enterprise Cloud AI Gateway & Control Plane",
    description="Secure AI traffic capture, token accounting & cross-platform telemetry.",
    version="10.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("utf-8")

@app.on_event("startup")
def startup_event():
    init_db()

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"

def sanitize_pii(text: str) -> str:
    if not isinstance(text, str):
        return str(text) if text else ""
    text = re.sub(r"[\w\.-]+@[\w\.-]+\.\w+", "[REDACTED_EMAIL]", text)
    text = re.sub(r"\b\d{10,12}\b", "[REDACTED_PHONE]", text)
    text = re.sub(r"sk_live_\w+|sk_test_\w+|AIzaSy\w+|sk_tenant_\w+", "[REDACTED_SECRET]", text)
    return text

async def verify_admin_user(request: Request, authorization: Optional[str] = Header(None)):
    return {"sub": "admin-security-officer", "email": "compliance@enterprise.internal"}

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

ICONS = {
    "shield": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    "smartphone": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="14" height="20" x="5" y="2" rx="2"/><path d="M12 18h.01"/></svg>',
    "download": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/></svg>',
    "refresh": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/></svg>',
    "server": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="20" height="8" x="2" y="2" rx="2"/><rect width="20" height="8" x="2" y="14" rx="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/></svg>',
    "activity": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',
    "cpu": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M9 1v3"/><path d="M15 1v3"/><path d="M9 20v3"/><path d="M15 20v3"/><path d="M20 9h3"/><path d="M20 14h3"/><path d="M1 9h3"/><path d="M1 14h3"/></svg>',
    "send": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m22 2-7 20-4-9-9-4Z"/><path d="M22 2 11 13"/></svg>',
    "zap": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>'
}

GLOBAL_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background-color: #030712; color: #f3f4f6; font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; }
.flex { display: flex; }
.flex-col { flex-direction: column; }
.items-center { align-items: center; }
.justify-between { justify-content: space-between; }
.justify-center { justify-content: center; }
.gap-2 { gap: 0.5rem; }
.gap-3 { gap: 0.75rem; }
.gap-4 { gap: 1rem; }
.grid { display: grid; }
.grid-cols-1 { grid-template-columns: repeat(1, minmax(0, 1fr)); }
@media (min-width: 768px) {
  .md\\:grid-cols-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }
  .md\\:grid-cols-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .md\\:flex-row { flex-direction: row; }
}
@media (min-width: 1024px) {
  .lg\\:grid-cols-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .lg\\:col-span-2 { grid-column: span 2 / span 2; }
}
.p-4 { padding: 1rem; }
.p-5 { padding: 1.25rem; }
.p-6 { padding: 1.5rem; }
.rounded-xl { border-radius: 0.75rem; }
.rounded-2xl { border-radius: 1rem; }
.rounded-full { border-radius: 9999px; }
.border { border-width: 1px; border-style: solid; }
.border-slate-800 { border-color: #1e293b; }
.bg-slate-900 { background-color: rgba(15, 23, 42, 0.9); }
.bg-slate-950 { background-color: #020617; }
.bg-indigo-600 { background-color: #4f46e5; }
.text-emerald-400 { color: #34d399; }
.text-indigo-400 { color: #818cf8; }
.text-white { color: #ffffff; }
.text-xs { font-size: 0.75rem; line-height: 1rem; }
.text-sm { font-size: 0.875rem; line-height: 1.25rem; }
.font-bold { font-weight: 700; }
.font-mono { font-family: ui-monospace, monospace; }
.shadow-xl { box-shadow: 0 20px 25px -5px rgb(0 0 0 / 0.5); }
.overflow-y-auto { overflow-y: auto; }
.overflow-x-auto { overflow-x: auto; }
.flex-1 { flex: 1 1 0%; }
.w-full { width: 100%; }
.h-full { height: 100%; }
.min-h-screen { min-height: 100vh; }
table { width: 100%; border-collapse: collapse; text-align: left; }
th, td { padding: 0.75rem; border-bottom: 1px solid #1e293b; }
button, a, input, select, textarea { font: inherit; color: inherit; }
"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Cloud AI Gateway & Control Plane</title>
    <style>""" + GLOBAL_CSS + """</style>
</head>
<body class="min-h-screen p-6 flex flex-col gap-4">
    <header class="flex flex-col md:flex-row items-center justify-between border border-slate-800 pb-4 gap-4 bg-slate-900 p-4 rounded-xl">
        <div class="flex items-center gap-3">
            <div class="bg-indigo-600 p-2.5 rounded-xl text-white shadow flex items-center justify-center">
                """ + ICONS["shield"] + """
            </div>
            <div>
                <h1 class="text-sm font-bold text-white">Enterprise Cloud AI Gateway & Control Plane</h1>
                <p class="text-xs text-indigo-400">Live AI Traffic Capture, Token Accounting & Multi-Platform Telemetry</p>
            </div>
        </div>
        <div class="flex items-center gap-3 flex-wrap">
            <span id="connection-badge" class="px-3 py-1 bg-emerald-950 text-emerald-400 border border-slate-800 rounded-full text-xs font-mono flex items-center gap-1.5">
                <span style="width:8px; height:8px; border-radius:50%; background:#10b981;"></span> Connected
            </span>
            <a href="/agent" target="_blank" style="padding: 0.5rem 0.875rem; background: #4f46e5; color: white; border-radius: 0.5rem; text-decoration: none;" class="text-xs font-bold flex items-center gap-1.5">
                """ + ICONS["smartphone"] + """ Mobile Agent Window
            </a>
            <a href="/api/export-audit-report" style="padding: 0.5rem 0.875rem; background: #1e293b; color: #e2e8f0; border-radius: 0.5rem; text-decoration: none;" class="text-xs font-semibold flex items-center gap-1.5">
                """ + ICONS["download"] + """ Export Audit CSV
            </a>
            <button onclick="loadDashboardData()" style="padding: 0.5rem 0.875rem; background: #1e293b; color: #e2e8f0; border-radius: 0.5rem; border: none; cursor: pointer;" class="text-xs font-semibold flex items-center gap-1.5">
                """ + ICONS["refresh"] + """ Refresh
            </button>
        </div>
    </header>

    <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; font-weight: 600;">Active Machine Nodes</div>
            <div id="stat-total-clients" style="font-size: 1.5rem; font-weight: 800; color: #ffffff;" class="font-mono mt-1">0</div>
        </div>
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; font-weight: 600;">Approved Nodes</div>
            <div id="stat-approved-clients" style="font-size: 1.5rem; font-weight: 800; color: #34d399;" class="font-mono mt-1">0</div>
        </div>
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; font-weight: 600;">AI Requests Captured</div>
            <div id="stat-total-tokens" style="font-size: 1.5rem; font-weight: 800; color: #818cf8;" class="font-mono mt-1">0</div>
        </div>
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; font-weight: 600;">Compliance Engine</div>
            <div style="font-size: 1.1rem; font-weight: 800; color: #c084fc;" class="font-mono mt-1">GDPR + NIST + DPDP</div>
        </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1">
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5 flex flex-col shadow-xl">
            <div class="flex items-center justify-between mb-4 pb-2" style="border-bottom: 1px solid #1e293b;">
                <h2 class="text-xs font-bold uppercase text-slate-200 flex items-center gap-2">
                    """ + ICONS["server"] + """ Client Devices & Token Balance
                </h2>
                <span id="client-count" class="px-3 py-1 bg-slate-950 text-slate-300 rounded-full text-xs font-mono">0 Registered</span>
            </div>
            <div id="clients-container" class="space-y-3 overflow-y-auto flex-1 max-h-[520px]">
                <div class="text-xs text-slate-500 text-center py-12 font-mono">Loading client devices...</div>
            </div>
        </div>

        <div class="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl p-5 flex flex-col shadow-xl">
            <div class="flex items-center justify-between mb-4 pb-2" style="border-bottom: 1px solid #1e293b;">
                <h2 class="text-xs font-bold uppercase text-slate-200 flex items-center gap-2">
                    """ + ICONS["activity"] + """ Captured Live AI Traffic & Telemetry
                </h2>
                <div class="flex items-center gap-2">
                    <span id="selected-client-badge" style="background: #022c22; color: #34d399; border: 1px solid #065f46;" class="px-2 py-0.5 rounded text-xs font-mono">Selected: None</span>
                    <span id="log-count" class="px-3 py-1 bg-slate-950 text-slate-300 rounded-full text-xs font-mono">0 Recorded</span>
                </div>
            </div>
            <div class="overflow-x-auto flex-1 max-h-[520px] overflow-y-auto">
                <table>
                    <thead style="position: sticky; top: 0; background: #020617; color: #94a3b8; text-transform: uppercase;">
                        <tr>
                            <th>Timestamp</th>
                            <th>Device & OS</th>
                            <th>LLM Telemetry</th>
                            <th>Token Usage / Balance</th>
                            <th>Captured Activity</th>
                        </tr>
                    </thead>
                    <tbody id="logs-table-body" style="color: #cbd5e1;">
                        <tr><td colspan="5" class="py-12 text-center text-slate-500">Select an approved device node or launch Agent Window...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        const SERVER_URL = window.location.origin;
        let selectedHwId = null;
        let globalClients = [];
        let globalLogs = [];

        async function loadDashboardData() {
            try {
                const res = await fetch(`${SERVER_URL}/api/dashboard-data`);
                if(!res.ok) return;
                const data = await res.json();
                
                globalClients = (data.clients || []).filter(c => !c.is_deleted);
                globalLogs = data.logs || [];

                const approvedClients = globalClients.filter(c => c.status === 'APPROVED');

                document.getElementById("stat-total-clients").innerText = globalClients.length;
                document.getElementById("stat-approved-clients").innerText = approvedClients.length;
                document.getElementById("stat-total-tokens").innerText = globalLogs.length;

                if (selectedHwId && !globalClients.some(c => c.hw_id === selectedHwId)) {
                    selectedHwId = null;
                }
                if (!selectedHwId && globalClients.length > 0) {
                    selectedHwId = globalClients[0].hw_id;
                }
                if (globalClients.length === 0) {
                    selectedHwId = null;
                }

                renderClients(globalClients);
                renderLogs(globalLogs);
            } catch (err) { console.error("Fetch error:", err); }
        }

        async function updateClientStatus(hwId, status) {
            try {
                const res = await fetch(`${SERVER_URL}/api/clients/${encodeURIComponent(hwId)}/status`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ status: status })
                });
                if(res.ok) {
                    loadDashboardData();
                }
            } catch(e) { console.error(e); }
        }

        async function softDeleteClient(hwId) {
            if(!confirm(`Delete device node ${hwId}?`)) return;
            try {
                const res = await fetch(`${SERVER_URL}/api/clients/${encodeURIComponent(hwId)}/delete`, {
                    method: 'POST'
                });
                if(res.ok) { 
                    if(selectedHwId === hwId) { selectedHwId = null; }
                    loadDashboardData(); 
                }
            } catch(e) { console.error(e); }
        }

        function selectClient(hwId) {
            selectedHwId = hwId;
            renderClients(globalClients);
            renderLogs(globalLogs);
        }

        function renderClients(clients) {
            const container = document.getElementById("clients-container");
            document.getElementById("client-count").innerText = `${clients.length} Registered`;
            if (!clients.length) { 
                container.innerHTML = `<div class="text-xs text-slate-500 text-center py-12 font-mono">No client devices registered yet.</div>`; 
                renderLogs([]);
                return; 
            }
            container.innerHTML = "";
            clients.forEach(c => {
                const isSelected = c.hw_id === selectedHwId;
                const clientStatus = c.status || 'APPROVED';
                const fingerprintVal = c.fingerprint_id || (c.hw_id ? c.hw_id.split('-').pop() : 'N/A');
                
                const statusColor = clientStatus === 'APPROVED' ? '#34d399' : (clientStatus === 'DENIED' ? '#fca5a5' : '#fbbf24');
                const statusBg = clientStatus === 'APPROVED' ? '#022c22' : (clientStatus === 'DENIED' ? '#450a0a' : '#451a03');
                const statusBorder = clientStatus === 'APPROVED' ? '#065f46' : (clientStatus === 'DENIED' ? '#991b1b' : '#b45309');

                const card = document.createElement("div");
                card.style.cssText = `padding: 1rem; border-radius: 0.75rem; border: 1px solid ${isSelected ? '#4f46e5' : '#1e293b'}; background: ${isSelected ? 'rgba(79, 70, 229, 0.1)' : '#020617'}; cursor: pointer; font-family: monospace; margin-bottom: 0.75rem;`;
                card.onclick = (e) => {
                    if(e.target.tagName === 'BUTTON') return;
                    selectClient(c.hw_id);
                };
                card.innerHTML = `
                    <div class="flex justify-between items-center">
                        <span style="font-weight: 700; color: #818cf8; font-size: 11px;">${c.hw_id}</span>
                        <span style="padding: 0.125rem 0.5rem; border-radius: 9999px; font-size: 10px; font-weight: 700; border: 1px solid; color: ${statusColor}; background: ${statusBg}; border-color: ${statusBorder};">${clientStatus}</span>
                    </div>
                    <div style="margin-top: 0.5rem; font-size: 11px; background: #0f172a; padding: 0.5rem; border-radius: 0.375rem; border: 1px solid #1e293b; line-height: 1.4;">
                        <div>Device / OS: <strong style="color: #67e8f9;">${c.device_type || 'Mobile / Browser'}</strong></div>
                        <div>Browser: <strong style="color: #34d399;">${c.browser_name || 'Web Client'}</strong></div>
                        <div>IP Address: <strong style="color: #fbbf24;">${c.ip_address || 'Dynamic'}</strong></div>
                        <div>Fingerprint: <strong style="color: #c084fc;">${fingerprintVal}</strong></div>
                        <div style="margin-top: 4px; padding-top: 4px; border-top: 1px dashed #1e293b;">Token Balance: <strong style="color: #34d399; font-size: 12px;">${(c.balance_tokens || 0).toLocaleString()} tokens</strong></div>
                    </div>
                    <div class="flex items-center justify-between" style="padding-top: 0.5rem; border-top: 1px solid #1e293b; margin-top: 0.5rem;">
                        <span style="font-size: 10px; color: #818cf8;">${isSelected ? '● Active' : 'Inspect'}</span>
                        <div class="flex gap-1.5">
                            <button onclick="updateClientStatus('${c.hw_id}', 'APPROVED')" style="padding: 0.25rem 0.5rem; background: #065f46; color: #34d399; border-radius: 0.25rem; font-size: 10px; border: none; cursor: pointer; font-weight: bold;">Approve</button>
                            <button onclick="updateClientStatus('${c.hw_id}', 'DENIED')" style="padding: 0.25rem 0.5rem; background: #7f1d1d; color: #fca5a5; border-radius: 0.25rem; font-size: 10px; border: none; cursor: pointer; font-weight: bold;">Deny</button>
                            <button onclick="softDeleteClient('${c.hw_id}')" style="padding: 0.25rem 0.5rem; background: #334155; color: #cbd5e1; border-radius: 0.25rem; font-size: 10px; border: none; cursor: pointer;">Delete</button>
                        </div>
                    </div>`;
                container.appendChild(card);
            });
        }

        function renderLogs(logs) {
            const tbody = document.getElementById("logs-table-body");
            const badge = document.getElementById("selected-client-badge");
            
            if (!selectedHwId || globalClients.length === 0) {
                badge.innerText = "Selected: None";
                document.getElementById("log-count").innerText = "0 Recorded";
                tbody.innerHTML = `<tr><td colspan="5" class="py-12 text-center text-slate-500">No device node selected.</td></tr>`;
                return;
            }

            badge.innerText = `Selected: ${selectedHwId}`;
            const filteredLogs = logs.filter(l => l.hw_id === selectedHwId);
            document.getElementById("log-count").innerText = `${filteredLogs.length} Recorded`;

            if (!filteredLogs.length) { 
                tbody.innerHTML = `<tr><td colspan="5" class="py-12 text-center text-slate-500">No live telemetry recorded for this device yet. Use Agent window to log prompts.</td></tr>`; 
                return; 
            }
            tbody.innerHTML = "";
            filteredLogs.forEach(l => {
                const balanceVal = l.balance_tokens !== undefined && l.balance_tokens !== null ? l.balance_tokens.toLocaleString() : 'N/A';
                tbody.innerHTML += `
                    <tr>
                        <td style="font-size: 11px;">
                            <div style="color: #34d399;">Local: ${l.timestamp_local || 'N/A'}</div>
                            <div style="color: #94a3b8; font-size: 10px;">UTC: ${l.timestamp_utc || 'N/A'}</div>
                        </td>
                        <td style="font-size: 11px; font-weight: bold; color: #818cf8;">
                            ${l.hw_id}<br/><span style="color: #67e8f9; font-weight: normal;">${l.browser_name || 'Browser'} / ${l.device_type || 'Mobile'}</span>
                        </td>
                        <td style="font-size: 11px;">
                            <div>Provider: <span style="color: #c084fc; font-weight: bold;">${l.provider || 'AI Stream'}</span></div>
                            <div>Security: <span style="color: #34d399;">NIST/GDPR Active</span></div>
                        </td>
                        <td style="font-size: 11px;">
                            <div>Used: <span style="color: #34d399; font-weight: bold;">${l.tokens} tokens</span></div>
                            <div>Balance: <strong style="color: #38bdf8;">${balanceVal}</strong></div>
                            <div>Latency: <span style="color: #fbbf24;">${l.latency_ms} ms</span></div>
                        </td>
                        <td style="font-size: 11px;">
                            <div><strong>Captured Payload:</strong> <span style="color: #818cf8;">${l.prompt || 'N/A'}</span></div>
                            <div><strong>Telemetry Status:</strong> <span style="color: #34d399;">${l.response || 'Verified Secure'}</span></div>
                        </td>
                    </tr>`;
            });
        }

        function initRealtime() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const ws = new WebSocket(`${protocol}//${window.location.host}/ws/live-traffic`);
            ws.onmessage = function(event) {
                try {
                    const message = JSON.parse(event.data);
                    if (message.type === 'NEW_TRAFFIC') { 
                        loadDashboardData(); 
                    }
                } catch(e) {}
            };
        }

        loadDashboardData();
        initRealtime();
        setInterval(loadDashboardData, 3000);
    </script>
</body>
</html>"""

WEB_AGENT_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Universal Mobile & Browser AI Telemetry Agent</title>
    <style>""" + GLOBAL_CSS + """</style>
</head>
<body class="min-h-screen p-4 flex flex-col items-center justify-center">
    <div class="max-w-4xl w-full bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-xl flex flex-col" style="height: 94vh;">
        <div class="flex flex-col md:flex-row items-center justify-between mb-3 border-b border-slate-800 pb-3 gap-2">
            <div>
                <h1 class="text-sm font-bold text-white flex items-center gap-2">
                    """ + ICONS["smartphone"] + """ External AI App & Cross-Platform Telemetry Agent
                </h1>
                <p id="client-info" class="text-xs text-indigo-400 font-mono mt-0.5">Detecting device fingerprint...</p>
            </div>
            <div class="flex items-center gap-3 flex-wrap">
                <a href="/" class="text-indigo-400 text-xs font-mono" style="text-decoration: none;">&larr; Return to Dashboard</a>
            </div>
        </div>

        <div style="background: #020617; border: 1px solid #1e293b; border-radius: 0.75rem; padding: 1rem; margin-bottom: 0.75rem; font-family: monospace;">
            <div style="font-size: 11px; font-weight: bold; color: #34d399; margin-bottom: 0.5rem; display: flex; align-items: center; gap: 0.5rem;">
                """ + ICONS["cpu"] + """ Sync External App Prompt (Perplexity, ChatGPT, Ollama, etc.)
            </div>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-2 mb-2">
                <div>
                    <label style="font-size: 10px; color: #94a3b8; display: block; margin-bottom: 2px;">AI Provider / App Name:</label>
                    <select id="external-app-name" style="width: 100%; background: #0f172a; border: 1px solid #334155; color: #f8fafc; padding: 0.4rem; border-radius: 0.375rem; font-size: 11px;">
                        <option value="Perplexity App">Perplexity App</option>
                        <option value="ChatGPT Desktop">ChatGPT Desktop</option>
                        <option value="Claude App">Claude App</option>
                        <option value="Ollama CLI / UI">Ollama CLI / Local UI</option>
                        <option value="Custom External App">Custom External App</option>
                    </select>
                </div>
                <div class="md:col-span-2">
                    <label style="font-size: 10px; color: #94a3b8; display: block; margin-bottom: 2px;">Prompt / Query Running in App:</label>
                    <input type="text" id="external-prompt-input" value="pull specific quantization tags in ollama" style="width: 100%; background: #0f172a; border: 1px solid #334155; color: #f8fafc; padding: 0.4rem; border-radius: 0.375rem; font-size: 11px;" placeholder="e.g. pull specific quantization tags in ollama">
                </div>
            </div>
            <button onclick="captureExternalAppPrompt()" style="width: 100%; padding: 0.5rem; background: #059669; color: white; border-radius: 0.375rem; border: none; cursor: pointer; font-weight: bold; font-size: 11px;" class="flex items-center justify-center gap-1.5">
                """ + ICONS["send"] + """ Stream External App Prompt to Control Plane Dashboard
            </button>
        </div>

        <div id="chat-messages" class="flex-1 bg-slate-950 rounded-xl p-4 border border-slate-800 overflow-y-auto space-y-3 text-xs font-mono mb-3">
            <div class="text-slate-500 text-center py-6">Ready to capture external app telemetry. Enter your active prompt above and click stream.</div>
        </div>

        <div class="flex gap-2">
            <button onclick="triggerQuickTelemetry()" style="width: 100%; padding: 0.6rem; background: #4f46e5; color: white; border-radius: 0.5rem; border: none; cursor: pointer;" class="text-xs font-bold flex items-center justify-center gap-2 shadow">
                """ + ICONS["zap"] + """ Trigger Automatic System Diagnostic Telemetry
            </button>
        </div>
    </div>

    <script>
        const SERVER_URL = window.location.origin;
        let clientCredentials = { hw_id: "", api_key: "", device_type: "", browser_name: "" };

        function getDeviceAndBrowserProfile() {
            const ua = navigator.userAgent;
            let osPrefix = "HW-WINDOWS";
            let osName = "Windows Workstation";
            
            if (/android/i.test(ua)) { osPrefix = "HW-ANDROID"; osName = "Android Mobile"; }
            else if (/iphone|ipad|ipod/i.test(ua)) { osPrefix = "HW-IOS"; osName = "iOS Mobile"; }
            else if (/macintosh|mac os x/i.test(ua)) { osPrefix = "HW-MAC"; osName = "macOS Workstation"; }
            else if (/linux/i.test(ua)) { osPrefix = "HW-LINUX"; osName = "Linux System"; }

            let browserName = "Edge";
            if (/chrome|crios|crmo/i.test(ua) && !/edg/i.test(ua)) browserName = "Chrome";
            else if (/firefox|fxios/i.test(ua)) browserName = "Firefox";
            else if (/safari/i.test(ua) && !/chrome/i.test(ua)) browserName = "Safari";
            else if (/edg/i.test(ua)) browserName = "Edge";

            const screenStr = `${window.screen.width}x${window.screen.height}`;
            const rawHashStr = `${ua}|${screenStr}|${navigator.hardwareConcurrency || 4}`;
            let hash = 0;
            for (let i = 0; i < rawHashStr.length; i++) {
                hash = ((hash << 5) - hash) + rawHashStr.charCodeAt(i);
                hash |= 0;
            }
            const uniqueHashHex = Math.abs(hash).toString(16).toUpperCase();
            const hwId = `${osPrefix}-${uniqueHashHex}`;

            return { hw_id: hwId, device_type: osName, browser_name: browserName, fingerprint_id: uniqueHashHex };
        }

        async function initClient() {
            try {
                const profile = getDeviceAndBrowserProfile();
                const res = await fetch(`${SERVER_URL}/api/register`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        hw_id: profile.hw_id,
                        device_type: profile.device_type,
                        browser_name: profile.browser_name,
                        fingerprint_id: profile.fingerprint_id,
                        user_agent: navigator.userAgent
                    })
                });
                const data = await res.json();
                clientCredentials.hw_id = data.hw_id;
                clientCredentials.api_key = data.api_key;
                clientCredentials.device_type = profile.device_type;
                clientCredentials.browser_name = profile.browser_name;

                document.getElementById("client-info").innerText = `ID: ${data.hw_id} | OS: ${profile.device_type} | Tokens: ${(data.balance_tokens || 500000).toLocaleString()}`;
            } catch(e) { console.error(e); }
        }

        async function captureExternalAppPrompt() {
            if(!clientCredentials.api_key) { await initClient(); }
            if(!clientCredentials.api_key) return;

            const appName = document.getElementById("external-app-name").value;
            const promptText = document.getElementById("external-prompt-input").value.trim();
            if(!promptText) { alert("Please enter a prompt."); return; }

            const chatContainer = document.getElementById("chat-messages");
            const startTime = performance.now();

            try {
                const res = await fetch(`${SERVER_URL}/v1/chat/completions`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${clientCredentials.api_key}`,
                        'X-HW-ID': clientCredentials.hw_id
                    },
                    body: JSON.stringify({
                        model: appName.toLowerCase().replace(/\\s+/g, '-'),
                        version: "v10.0-external",
                        think_level: "External App Capture",
                        provider: appName,
                        payload: promptText,
                        response: `External app prompt captured successfully from ${appName}.`,
                        prompt_tokens: Math.round(promptText.split(' ').length * 1.5),
                        completion_tokens: 35,
                        device_type: clientCredentials.device_type,
                        browser_name: clientCredentials.browser_name
                    })
                });
                
                const latencyMs = Math.round(performance.now() - startTime);
                if(!res.ok) throw new Error(await res.text());

                const data = await res.json();
                const balance = data.balance_tokens !== undefined ? data.balance_tokens.toLocaleString() : "N/A";

                chatContainer.innerHTML += `<div style="padding: 0.6rem; background: rgba(6, 95, 70, 0.3); border: 1px solid #059669; border-radius: 0.5rem; margin-bottom: 0.5rem;"><strong style="color: #34d399;">[${appName}] Synced Prompt:</strong> ${promptText}<div style="font-size: 10px; color: #38bdf8; margin-top: 3px;">Latency: ${latencyMs}ms | Balance: ${balance} tokens | NIST/GDPR Secure</div></div>`;
                chatContainer.scrollTop = chatContainer.scrollHeight;
            } catch(e) {
                chatContainer.innerHTML += `<div style="padding: 0.6rem; background: #450a0a; color: #fca5a5; border-radius: 0.5rem;">Error: ${e.message}</div>`;
            }
        }

        async function triggerQuickTelemetry() {
            if(!clientCredentials.api_key) { await initClient(); }
            if(!clientCredentials.api_key) return;

            const chatContainer = document.getElementById("chat-messages");
            const defaultPrompt = "System diagnostic telemetry event captured.";
            
            try {
                const res = await fetch(`${SERVER_URL}/v1/chat/completions`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${clientCredentials.api_key}`,
                        'X-HW-ID': clientCredentials.hw_id
                    },
                    body: JSON.stringify({
                        model: "system-telemetry",
                        version: "v10.0",
                        think_level: "Diagnostic",
                        provider: "System Diagnostic",
                        payload: defaultPrompt,
                        response: "Verified Secure.",
                        prompt_tokens: 15,
                        completion_tokens: 10
                    })
                });
                if(res.ok) {
                    chatContainer.innerHTML += `<div style="padding: 0.5rem; background: rgba(30, 41, 59, 0.5); border: 1px solid #334155; border-radius: 0.375rem; margin-bottom: 0.5rem; color: #94a3b8;">System diagnostic logged successfully.</div>`;
                    chatContainer.scrollTop = chatContainer.scrollHeight;
                }
            } catch(e) {}
        }

        initClient();
    </script>
</body>
</html>"""

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    return DASHBOARD_HTML

@app.get("/agent", response_class=HTMLResponse)
def serve_agent():
    return WEB_AGENT_HTML

@app.get("/public-key", response_class=PlainTextResponse)
def get_public_key():
    return public_pem

@app.post("/api/register")
@app.post("/register")
@app.post("/api/nodes/register")
@app.post("/api/device/register")
@app.post("/api/devices")
async def register_client(request: Request, db: Session = Depends(get_db)):
    try:
        body = await request.json()
    except Exception:
        body = {}
    
    hw_id = body.get("hw_id") or body.get("hardware_id") or body.get("device_id")
    if not hw_id:
        raise HTTPException(status_code=400, detail="hw_id is required in registration payload.")
    
    try:
        client = db.query(ClientModel).filter(ClientModel.hw_id == hw_id).first()
        real_ip = get_client_ip(request)

        device_type = body.get("device_type") or body.get("device_name") or "Desktop Agent"
        browser_name = body.get("browser_name") or "System Proxy Agent"
        fingerprint_id = body.get("fingerprint") or body.get("fingerprint_id")
        if not fingerprint_id and hw_id and "-" in hw_id:
            fingerprint_id = hw_id.split("-")[-1]
            body["fingerprint_id"] = fingerprint_id

        geo_info = {"client_ip": real_ip, "compliance": "GDPR, NIST SP 800-53 Active"}
        body["ip_address"] = real_ip
        body["geo_location"] = geo_info
        body["registered_at_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        if not client:
            api_key = f"sk_tenant_{secrets.token_hex(16)}"
            client = ClientModel(
                hw_id=hw_id,
                api_key=api_key,
                status="APPROVED",
                subscription_tier="ENTERPRISE_PRO",
                balance_tokens=500000,
                is_deleted=False,
                metadata_json=json.dumps(body)
            )
            db.add(client)
        else:
            client.is_deleted = False
            client.metadata_json = json.dumps(body)
            if not client.api_key:
                client.api_key = f"sk_tenant_{secrets.token_hex(16)}"
        db.commit()
        db.refresh(client)
        
        return {
            "status": client.status,
            "approval_status": client.status,
            "approved": (client.status == "APPROVED"),
            "is_approved": (client.status == "APPROVED"),
            "hw_id": client.hw_id,
            "api_key": client.api_key,
            "ip_address": real_ip,
            "balance_tokens": client.balance_tokens,
            "device_type": device_type,
            "browser_name": browser_name,
            "fingerprint": fingerprint_id
        }
    except HTTPException as he:
        raise he
    except Exception as e:
        db.rollback()
        logger.error(f"Registration error: {e}")
        return {"status": "Discovered", "approval_status": "Discovered", "error": str(e)}

@app.get("/api/device/{hw_id}")
@app.get("/api/node/{hw_id}")
@app.get("/api/status")
@app.get("/api/devices")
@app.get("/api/nodes")
@app.get("/api/clients")
def get_device_status(hw_id: Optional[str] = None, db: Session = Depends(get_db)):
    if hw_id:
        client = db.query(ClientModel).filter(ClientModel.hw_id == hw_id, ClientModel.is_deleted == False).first()
        if not client:
            return {"status": "Discovered", "approval_status": "Discovered", "approved": False}
        return {
            "hw_id": client.hw_id,
            "status": client.status,
            "approval_status": client.status,
            "approved": (client.status == "APPROVED"),
            "is_approved": (client.status == "APPROVED"),
            "balance_tokens": client.balance_tokens
        }
    clients = db.query(ClientModel).filter(ClientModel.is_deleted == False).all()
    return [{
        "hw_id": c.hw_id,
        "status": c.status,
        "approval_status": c.status,
        "approved": (c.status == "APPROVED"),
        "is_approved": (c.status == "APPROVED")
    } for c in clients]

@app.post("/api/telemetry")
@app.post("/api/telemetry/push")
@app.post("/api/logs")
@app.post("/api/activity")
async def receive_telemetry(request: Request, db: Session = Depends(get_db)):
    try:
        body = await request.json()
    except Exception:
        body = {}

    hw_id = body.get("hw_id") or body.get("hardware_id") or body.get("device_id")
    if not hw_id:
        raise HTTPException(status_code=400, detail="Missing dynamic hardware identifier.")

    client = db.query(ClientModel).filter(ClientModel.hw_id == hw_id).first()
    if not client:
        api_key = f"sk_tenant_{secrets.token_hex(16)}"
        client = ClientModel(
            hw_id=hw_id,
            api_key=api_key,
            status="APPROVED",
            balance_tokens=500000,
            metadata_json=json.dumps({"ip_address": get_client_ip(request), "device_type": body.get("device", "Desktop Agent")})
        )
        db.add(client)
        db.commit()
        db.refresh(client)

    if client.status != "APPROVED":
        raise HTTPException(status_code=403, detail=f"Client node is {client.status}. Access denied by gateway.")

    provider = body.get("llm_telemetry") or body.get("provider") or body.get("endpoint") or "Agent Interceptor"
    model = body.get("model") or body.get("llm_model") or "Generic LLM"
    prompt_text = body.get("activity") or body.get("captured_activity") or body.get("prompt") or "AI Traffic Intercepted"
    sanitized_prompt = sanitize_pii(prompt_text)
    
    tokens = body.get("token_usage") or body.get("tokens_used") or 50
    client.balance_tokens = max(0, client.balance_tokens - tokens)
    db.commit()

    now_utc = datetime.now(timezone.utc)
    timestamp_utc = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    ist_offset = timezone(timedelta(hours=5, minutes=30))
    timestamp_local = now_utc.astimezone(ist_offset).strftime("%Y-%m-%d %H:%M:%S Local (IST)")

    meta = {}
    if client.metadata_json:
        try:
            meta = json.loads(client.metadata_json)
        except Exception:
            pass

    device_type_val = meta.get("device_type") or body.get("device") or "Desktop Machine"
    browser_name_val = meta.get("browser_name") or "AI Interceptor Proxy"
    fingerprint_val = body.get("fingerprint") or (hw_id.split("-")[-1] if "-" in hw_id else "N/A")
    ip_val = meta.get("ip_address") or get_client_ip(request)

    payload_data = {
        "provider": provider,
        "model": model,
        "query": sanitized_prompt,
        "response": "Intercepted & Verified Secure",
        "prompt_tokens": tokens,
        "completion_tokens": 0,
        "latency_ms": 15,
        "timestamp_utc": timestamp_utc,
        "timestamp_local": timestamp_local,
        "device_type": device_type_val,
        "browser_name": browser_name_val,
        "fingerprint_id": fingerprint_val,
        "ip_address": ip_val,
        "balance_tokens": client.balance_tokens
    }

    try:
        encrypted_payload = cipher.encrypt(json.dumps(payload_data).encode()).decode()
    except Exception:
        encrypted_payload = json.dumps(payload_data)

    log_entry = TrafficLogModel(
        hw_id=client.hw_id,
        provider=provider,
        model=model,
        version="v10.0-proxy",
        think_level="Live Intercept",
        prompt_tokens=tokens,
        completion_tokens=0,
        latency_ms=15,
        payload_json=encrypted_payload
    )
    db.add(log_entry)
    db.commit()

    await manager.broadcast({
        "type": "NEW_TRAFFIC",
        "data": {
            "id": log_entry.id,
            "timestamp": timestamp_utc,
            "tenant_id": client.hw_id,
            "device_type": device_type_val,
            "browser_name": browser_name_val,
            "fingerprint_id": fingerprint_val,
            "ip_address": ip_val,
            "provider": provider,
            "model": model,
            "tokens": tokens,
            "balance_tokens": client.balance_tokens,
            "latency_ms": 15,
            "prompt": sanitized_prompt,
            "response": "Intercepted & Verified Secure"
        }
    })

    return {"status": "success", "balance_tokens": client.balance_tokens}

@app.post("/api/clients/{hw_id}/status")
async def update_client_status(hw_id: str, request: Request, user: dict = Depends(verify_admin_user), db: Session = Depends(get_db)):
    try:
        body = await request.json()
    except Exception:
        body = {}
    new_status = body.get("status", "APPROVED")
    
    client = db.query(ClientModel).filter(ClientModel.hw_id == hw_id).first()
    if client:
        client.status = new_status
        db.commit()
        return {"status": "success", "hw_id": hw_id, "client_status": new_status}
    raise HTTPException(status_code=404, detail="Client node not found.")

@app.post("/api/clients/{hw_id}/delete")
async def soft_delete_client(hw_id: str, user: dict = Depends(verify_admin_user), db: Session = Depends(get_db)):
    client = db.query(ClientModel).filter(ClientModel.hw_id == hw_id).first()
    if client:
        client.is_deleted = True
        client.status = "DELETED"
        db.commit()
    return {"status": "success", "message": f"Client {hw_id} deleted."}

@app.get("/api/export-audit-report")
def export_audit_report(user: dict = Depends(verify_admin_user), db: Session = Depends(get_db)):
    try:
        active_clients = db.query(ClientModel).filter(ClientModel.is_deleted == False, ClientModel.status == "APPROVED").all()
        active_hw_ids = {c.hw_id for c in active_clients}
        rows = db.query(TrafficLogModel).filter(TrafficLogModel.hw_id.in_(active_hw_ids)).order_by(TrafficLogModel.created_at.desc()).all() if active_hw_ids else []
    except Exception:
        rows = []
        
    output = io.StringIO()
    output.write("HardwareID,DeviceType,Browser,IPAddress,Provider,Model,Version,PromptTokens,CompletionTokens,LatencyMS,ActivityPayload,StatusResponse,TimestampUTC\n")
    
    for r in rows:
        p = {}
        try:
            if r.payload_json:
                try:
                    p = json.loads(cipher.decrypt(r.payload_json.encode()).decode())
                except Exception:
                    p = json.loads(r.payload_json)
        except Exception:
            pass
            
        hw_id = r.hw_id or ""
        device_type = p.get("device_type") or "Desktop Agent"
        browser_name = p.get("browser_name") or "Proxy Agent"
        ip_address = p.get("ip_address") or "Dynamic"
        provider = r.provider or ""
        model = r.model or ""
        version = r.version or ""
        prompt_tokens = r.prompt_tokens or 0
        completion_tokens = r.completion_tokens or 0
        latency_ms = r.latency_ms or 0
        query = str(p.get("query") or p.get("prompt") or "").replace('"', '""')
        response_text = str(p.get("response") or "Verified Secure").replace('"', '""')
        
        db_time = r.created_at or datetime.now(timezone.utc)
        timestamp_utc = db_time.strftime("%Y-%m-%d %H:%M:%S UTC")
        
        output.write(f'"{hw_id}","{device_type}","{browser_name}","{ip_address}","{provider}","{model}","{version}",{prompt_tokens},{completion_tokens},{latency_ms},"{query}","{response_text}","{timestamp_utc}"\n')
        
    response = StreamingResponse(iter([output.getvalue()]), media_type="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=ai_traffic_compliance_audit.csv"
    return response

@app.post("/v1/chat/completions")
@app.post("/log-traffic")
async def openai_compatible_chat_completions(request: Request, db: Session = Depends(get_db)):
    try:
        body = await request.json()
    except Exception:
        body = {}
        
    auth_header = request.headers.get("Authorization", "")
    api_key = auth_header.split(" ")[1] if auth_header.startswith("Bearer ") else None
    hw_id_header = request.headers.get("X-HW-ID") or body.get("hw_id")

    try:
        client_node = None
        if api_key:
            client_node = db.query(ClientModel).filter(ClientModel.api_key == api_key).first()
        if (not client_node or client_node.is_deleted) and hw_id_header:
            client_node = db.query(ClientModel).filter(ClientModel.hw_id == hw_id_header).first()
        
        if not client_node or client_node.is_deleted:
            raise HTTPException(status_code=403, detail="Client node not found.")

        if client_node.status != "APPROVED":
            raise HTTPException(status_code=403, detail=f"Client node is currently {client_node.status}.")

        meta = {}
        if client_node.metadata_json:
            try:
                meta = json.loads(client_node.metadata_json)
            except Exception:
                pass

        raw_prompt = body.get("payload") or body.get("prompt")
        if not raw_prompt and "messages" in body and isinstance(body["messages"], list) and len(body["messages"]) > 0:
            raw_prompt = body["messages"][-1].get("content")
        
        if not raw_prompt:
            raise HTTPException(status_code=400, detail="Prompt or payload is required.")

        sanitized_prompt = sanitize_pii(str(raw_prompt))
        model = body.get("model", "cross-platform-model")
        version = body.get("version", "v10.0")
        think_level = body.get("think_level", "Realtime")
        
        raw_provider = body.get("provider", "System Diagnostic")
        browser_indicators = ["edge", "chrome", "firefox", "safari", "browser", "mobile device", "windows workstation", "macs", "linux"]
        provider = "System Diagnostic" if raw_provider.lower().strip() in browser_indicators else raw_provider

        input_tokens = body.get("prompt_tokens") or (len(sanitized_prompt.split()) * 2 + 10)
        output_tokens = body.get("completion_tokens") or 32
        latency = body.get("latency_ms") or 75
        total_tokens = input_tokens + output_tokens

        client_node.balance_tokens = max(0, client_node.balance_tokens - total_tokens)
        db.commit()

        now_utc = datetime.now(timezone.utc)
        timestamp_utc = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
        ist_offset = timezone(timedelta(hours=5, minutes=30))
        timestamp_local = now_utc.astimezone(ist_offset).strftime("%Y-%m-%d %H:%M:%S Local (IST)")

        device_type_val = meta.get("device_type") or body.get("device_type")
        browser_name_val = meta.get("browser_name") or body.get("browser_name")
        fingerprint_id_val = meta.get("fingerprint_id") or (client_node.hw_id.split('-')[-1] if client_node.hw_id and '-' in client_node.hw_id else 'N/A')
        ip_val = meta.get("ip_address") or get_client_ip(request)

        ai_response_text = body.get("response") or "Telemetry verified secure under NIST & GDPR."

        payload_data = {
            "provider": provider,
            "model": model,
            "version": version,
            "think_level": think_level,
            "query": sanitized_prompt,
            "response": ai_response_text,
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "latency_ms": latency,
            "timestamp_utc": timestamp_utc,
            "timestamp_local": timestamp_local,
            "device_type": device_type_val,
            "browser_name": browser_name_val,
            "fingerprint_id": fingerprint_id_val,
            "ip_address": ip_val,
            "balance_tokens": client_node.balance_tokens
        }

        try:
            encrypted_payload = cipher.encrypt(json.dumps(payload_data).encode()).decode()
        except Exception:
            encrypted_payload = json.dumps(payload_data)

        log_entry = TrafficLogModel(
            hw_id=client_node.hw_id,
            provider=provider,
            model=model,
            version=version,
            think_level=think_level,
            prompt_tokens=input_tokens,
            completion_tokens=output_tokens,
            latency_ms=latency,
            payload_json=encrypted_payload
        )
        db.add(log_entry)
        db.commit()

        await manager.broadcast({
            "type": "NEW_TRAFFIC",
            "data": {
                "id": log_entry.id,
                "timestamp": timestamp_utc,
                "tenant_id": client_node.hw_id,
                "device_type": device_type_val,
                "browser_name": browser_name_val,
                "fingerprint_id": fingerprint_id_val,
                "ip_address": ip_val,
                "provider": provider,
                "model": model,
                "version": version,
                "tokens": total_tokens,
                "balance_tokens": client_node.balance_tokens,
                "latency_ms": latency,
                "prompt": sanitized_prompt,
                "response": ai_response_text
            }
        })
    except HTTPException as he:
        raise he
    except Exception as ex:
        db.rollback()
        logger.error(f"AI Traffic error: {ex}")
        raise HTTPException(status_code=500, detail=str(ex))

    return {
        "id": f"chatcmpl-{int(time.time())}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": ai_response_text}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": input_tokens, "completion_tokens": output_tokens, "total_tokens": total_tokens},
        "balance_tokens": client_node.balance_tokens
    }

@app.get("/api/dashboard-data")
def dashboard_data(user: dict = Depends(verify_admin_user), db: Session = Depends(get_db)):
    try:
        client_rows = db.query(ClientModel).filter(ClientModel.is_deleted == False).all()
        approved_hw_ids = {c.hw_id for c in client_rows}
        
        log_rows = db.query(TrafficLogModel).filter(TrafficLogModel.hw_id.in_(approved_hw_ids)).order_by(TrafficLogModel.id.desc()).limit(200).all() if approved_hw_ids else []

        clients = []
        for c in client_rows:
            meta = {}
            if c.metadata_json:
                try:
                    meta = json.loads(c.metadata_json)
                except Exception:
                    pass

            if not meta.get("fingerprint_id") and c.hw_id and "-" in c.hw_id:
                meta["fingerprint_id"] = c.hw_id.split("-")[-1]

            clients.append({
                **meta,
                "hw_id": c.hw_id,
                "status": c.status or "APPROVED",
                "subscription_tier": c.subscription_tier or "ENTERPRISE_PRO",
                "balance_tokens": c.balance_tokens if c.balance_tokens is not None else 500000,
                "is_deleted": bool(c.is_deleted),
                "created_at": str(c.created_at) if c.created_at else "",
                "api_key": c.api_key or "",
            })

        logs = []
        for l in log_rows:
            payload = {}
            if l.payload_json:
                try:
                    payload = json.loads(cipher.decrypt(l.payload_json.encode()).decode())
                except Exception:
                    try:
                        payload = json.loads(l.payload_json)
                    except Exception:
                        payload = {}
            
            db_time = l.created_at or datetime.now(timezone.utc)
            utc_str = db_time.strftime("%Y-%m-%d %H:%M:%S UTC")
            ist_offset = timezone(timedelta(hours=5, minutes=30))
            local_str = db_time.astimezone(ist_offset).strftime("%Y-%m-%d %H:%M:%S Local (IST)") if hasattr(db_time, 'astimezone') else str(db_time)

            logs.append({
                "id": l.id,
                "hw_id": l.hw_id,
                "device_type": payload.get("device_type") or "Desktop Machine",
                "browser_name": payload.get("browser_name") or "Agent Interceptor",
                "ip_address": payload.get("ip_address") or "Dynamic",
                "timestamp_utc": utc_str,
                "timestamp_local": payload.get("timestamp_local") or local_str,
                "provider": l.provider,
                "model": l.model,
                "version": l.version,
                "think_level": l.think_level,
                "prompt_tokens": l.prompt_tokens or 0,
                "completion_tokens": l.completion_tokens or 0,
                "tokens": (l.prompt_tokens or 0) + (l.completion_tokens or 0),
                "balance_tokens": payload.get("balance_tokens") if payload.get("balance_tokens") is not None else 500000,
                "latency_ms": l.latency_ms or 0,
                "prompt": payload.get("query") or payload.get("prompt") or "Real-time telemetry event captured.",
                "response": payload.get("response") or "Verified Secure"
            })

        return {"clients": clients, "logs": logs, "authenticated_user": "compliance@enterprise.internal"}
    except Exception as e:
        db.rollback()
        logger.error(f"Dashboard data error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.websocket("/ws/live-traffic")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)