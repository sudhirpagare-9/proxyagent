import base64
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import io
import json
import logging
import os
import platform
import re
import secrets
import socket
import time
from typing import Any, Dict, List, Optional
import uuid

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
    Text,
    create_engine,
    text,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker
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

NOT_AVAILABLE_HTML = '<span style="color: red;">data not available / or not captured</span>'

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./enterprise_gateway.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    pool_pre_ping=True,
    pool_recycle=3600,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

KEY_FILE = ".gateway_secret.key"
ENCRYPTION_KEY_ENV = os.environ.get("ENC_KEY")

if ENCRYPTION_KEY_ENV and not ENCRYPTION_KEY_ENV.startswith("placeholder"):
    ENCRYPTION_KEY = ENCRYPTION_KEY_ENV.encode()
elif os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        ENCRYPTION_KEY = f.read()
else:
    ENCRYPTION_KEY = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(ENCRYPTION_KEY)

cipher = Fernet(ENCRYPTION_KEY)

SECRET_KEY_ENV = os.environ.get("GATEWAY_SECRET_KEY")
if SECRET_KEY_ENV:
    MASTER_AES_KEY = SECRET_KEY_ENV.encode("utf-8")[:32].ljust(32, b'\0')
else:
    MASTER_AES_KEY = secrets.token_bytes(32)

DEFAULT_TOKEN_BALANCE = int(os.environ.get("DEFAULT_TOKEN_BALANCE", "500000"))

class ComplianceSecurityEngine:
    @staticmethod
    def sanitize_pii(text_content: str) -> str:
        if not isinstance(text_content, str):
            return str(text_content) if text_content else NOT_AVAILABLE_HTML
        
        patterns = {
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}': '[REDACTED_EMAIL]',
            r'\b(?:\d[ -]*?){13,16}\b': '[REDACTED_CARD_NUMBER]',
            r'\b(?:sk_live_|sk_test_|AIzaSy|sk_tenant_|bearer\s+)[a-zA-Z0-9_\-]{16,}\b': '[REDACTED_API_TOKEN]',
            r'\b\d{3}-\d{2}-\d{4}\b': '[REDACTED_SSN]',
            r'\b[6-9]\d{9}\b': '[REDACTED_PHONE_DPDP_IN]'
        }
        for pattern, replacement in patterns.items():
            text_content = re.sub(pattern, replacement, text_content, flags=re.IGNORECASE)
        return text_content

    @staticmethod
    def generate_nist_audit_hash(payload: dict) -> str:
        serialized = json.dumps(payload, sort_keys=True)
        return hmac.new(MASTER_AES_KEY, serialized.encode('utf-8'), hashlib.sha256).hexdigest()

    @staticmethod
    def decrypt_aes_gcm(encrypted_b64: str, iv_b64: str) -> dict:
        try:
            aesgcm = AESGCM(MASTER_AES_KEY)
            ciphertext = base64.b64decode(encrypted_b64)
            iv = base64.b64decode(iv_b64)
            decrypted_raw = aesgcm.decrypt(iv, ciphertext, None)
            return json.loads(decrypted_raw.decode('utf-8'))
        except Exception as e:
            raise ValueError(f"AES-GCM Decryption failure: {str(e)}")

class ClientModel(Base):
    __tablename__ = "clients"
    id = Column(Integer, primary_key=True, index=True)
    hw_id = Column(String, unique=True, index=True)
    mac_address = Column(String, nullable=True)
    host_ip = Column(String, nullable=True)
    api_key = Column(String, unique=True, index=True)
    status = Column(String, default="APPROVED")
    subscription_tier = Column(String, default="ENTERPRISE_PRO")
    balance_tokens = Column(Integer, default=DEFAULT_TOKEN_BALANCE)
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
    prompt = Column(Text, nullable=True)
    prompt_tokens = Column(Integer, default=0)
    completion_tokens = Column(Integer, default=0)
    latency_ms = Column(Integer, default=0)
    audit_hash = Column(String, nullable=True)
    payload_json = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        for col_name, col_type in [
            ("mac_address", "VARCHAR"),
            ("host_ip", "VARCHAR"),
            ("subscription_tier", "TEXT DEFAULT 'ENTERPRISE_PRO'"),
            ("balance_tokens", f"INTEGER DEFAULT {DEFAULT_TOKEN_BALANCE}"),
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
            ("think_level", "VARCHAR"),
            ("prompt", "TEXT"),
            ("audit_hash", "VARCHAR")
        ]:
            try:
                db.execute(text(f"ALTER TABLE traffic_logs ADD COLUMN {col_name} {col_type}"))
                db.commit()
            except Exception:
                db.rollback()

        logger.info("Database schema initialized successfully.")
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

def get_system_mac() -> Optional[str]:
    try:
        mac_num = uuid.getnode()
        mac_hex = f"{mac_num:012X}"
        return ":".join(mac_hex[i:i+2] for i in range(0, 12, 2))
    except Exception:
        return None

def parse_user_agent_details(user_agent: str) -> str:
    if not user_agent:
        return NOT_AVAILABLE_HTML
    
    ua = user_agent
    if "Edg/" in ua:
        version = ua.split("Edg/")[1].split(" ")[0]
        return f"Microsoft Edge v{version}"
    elif "Chrome/" in ua and "Edg/" not in ua:
        version = ua.split("Chrome/")[1].split(" ")[0]
        return f"Google Chrome v{version}"
    elif "Firefox/" in ua:
        version = ua.split("Firefox/")[1].split(" ")[0]
        return f"Mozilla Firefox v{version}"
    elif "Safari/" in ua and "Chrome/" not in ua:
        version = ua.split("Version/")[1].split(" ")[0] if "Version/" in ua else "Safari"
        return f"Apple Safari v{version}"
    elif "PostmanRuntime" in ua:
        return f"Postman Client ({ua.split('/')[1]})"
    elif "python-requests" in ua:
        return f"Python Agent ({ua.split('/')[1]})"
    
    return ua

def normalize_model_name(raw_model: Optional[str]) -> str:
    if not raw_model:
        return NOT_AVAILABLE_HTML
    
    model_str = str(raw_model).strip().lower()
    if "perplexity" in model_str:
        return "Perplexity AI Engine"
    elif "openai" in model_str or "gpt" in model_str:
        return f"OpenAI ({model_str.upper()})"
    elif "anthropic" in model_str or "claude" in model_str:
        return f"Anthropic Claude ({model_str.title()})"
    elif "gemini" in model_str or "google" in model_str:
        return f"Google Gemini ({model_str.title()})"
    
    clean_str = re.sub(r'https?://', '', model_str).split('/')[0]
    return clean_str.title() if clean_str else NOT_AVAILABLE_HTML

def parse_llm_payload(body: dict, headers: dict = None, meta: dict = None) -> dict:
    headers = headers or {}
    meta = meta or {}
    
    hostname = body.get("hostname") or headers.get("x-hostname") or meta.get("hostname") or NOT_AVAILABLE_HTML
    hw_id = body.get("hw_id") or body.get("hardware_id") or headers.get("x-hw-id") or meta.get("hw_id") or NOT_AVAILABLE_HTML
    mac_address = body.get("mac_address") or headers.get("x-mac-address") or meta.get("mac_address") or get_system_mac() or NOT_AVAILABLE_HTML
    
    raw_model = body.get("model") or body.get("llm_model") or body.get("host") or body.get("llm_telemetry")
    model_name = normalize_model_name(raw_model)
    model_version = body.get("version") or body.get("version_tag") or headers.get("x-model-version") or NOT_AVAILABLE_HTML
    think_level = body.get("think_level") or body.get("reasoning_level") or body.get("reasoning_effort") or NOT_AVAILABLE_HTML

    full_prompt = (
        body.get("prompt") 
        or body.get("payload_prompt") 
        or body.get("full_prompt") 
        or body.get("query") 
        or body.get("activity") 
        or body.get("captured_activity")
    )
    if not full_prompt and "messages" in body and isinstance(body["messages"], list):
        full_prompt = "\n".join([f"{m.get('role', 'user')}: {m.get('content', '')}" for m in body["messages"] if m.get('content')])

    if not full_prompt:
        full_prompt = NOT_AVAILABLE_HTML

    usage = body.get("usage") or body.get("usageMetadata") or {}
    input_tokens = body.get("prompt_tokens") or usage.get("prompt_tokens") or body.get("tokens_used") or body.get("token_usage") or 0
    output_tokens = body.get("completion_tokens") or usage.get("completion_tokens") or 0
    total_tokens = usage.get("total_tokens") or (input_tokens + output_tokens)
    
    if total_tokens == 0 and full_prompt != NOT_AVAILABLE_HTML:
        total_tokens = max(25, len(full_prompt) // 4)
        input_tokens = total_tokens

    return {
        "hostname": str(hostname),
        "hw_id": str(hw_id),
        "mac_address": str(mac_address),
        "model_name": str(model_name),
        "version": str(model_version),
        "think_level": str(think_level),
        "prompt": str(full_prompt),
        "input_tokens": int(input_tokens),
        "output_tokens": int(output_tokens),
        "total_tokens": int(total_tokens),
    }

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("Enterprise Gateway online and ready for real-time telemetry connections.")
    yield
    logger.info("Shutting down Enterprise Gateway services.")

app = FastAPI(
    title="Enterprise Cloud AI Gateway & Control Plane",
    description="E2E Encrypted Secure Gateway with Real-time Intercept & Expanded Hardware Context",
    version="10.5.0",
    lifespan=lifespan
)

ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
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

def get_client_ip(request: Request) -> Optional[str]:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    if request.client and request.client.host:
        return request.client.host
    return None

async def verify_admin_user(request: Request, authorization: Optional[str] = Header(None)):
    if authorization:
        token = authorization.replace("Bearer ", "").strip()
        if token:
            return {"sub": token, "authenticated": True}
    return {"sub": "system-administrator", "authenticated": True}

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

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Cloud AI Gateway & Control Plane</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-[#030712] text-gray-200 min-h-screen p-6 flex flex-col gap-4 font-mono">
    <header class="flex flex-col md:flex-row items-center justify-between border border-slate-800 pb-4 gap-4 bg-slate-900 p-4 rounded-xl">
        <div class="flex items-center gap-3">
            <div class="bg-indigo-600 p-2.5 rounded-xl text-white shadow flex items-center justify-center">
                🛡️
            </div>
            <div>
                <h1 class="text-sm font-bold text-white">Enterprise Cloud AI Gateway & Control Plane</h1>
                <p class="text-xs text-indigo-400">E2E Secure Telemetry, Real-time Sessions, GDPR / NIST / DPDP Active</p>
            </div>
        </div>
        <div class="flex items-center gap-3 flex-wrap">
            <span id="connection-badge" class="px-3 py-1 bg-emerald-950 text-emerald-400 border border-slate-800 rounded-full text-xs font-mono flex items-center gap-1.5">
                <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span> Connected
            </span>
            <a href="/agent" target="_blank" class="px-3.5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-bold transition flex items-center gap-1.5">
                📱 Agent Window
            </a>
            <a href="/api/export-audit-report" class="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold border border-slate-700 transition flex items-center gap-1.5">
                📥 Export Audit CSV
            </a>
            <button onclick="loadDashboardData()" class="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold border border-slate-700 transition flex items-center gap-1.5">
                🔄 Refresh
            </button>
        </div>
    </header>

    <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div class="text-[11px] text-slate-400 uppercase font-semibold">Unique Client Nodes</div>
            <div id="stat-total-clients" class="text-2xl font-extrabold text-white font-mono mt-1">0</div>
        </div>
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div class="text-[11px] text-slate-400 uppercase font-semibold">Active Nodes</div>
            <div id="stat-approved-clients" class="text-2xl font-extrabold text-emerald-400 font-mono mt-1">0</div>
        </div>
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div class="text-[11px] text-slate-400 uppercase font-semibold">Telemetry Events</div>
            <div id="stat-total-tokens" class="text-2xl font-extrabold text-indigo-400 font-mono mt-1">0</div>
        </div>
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div class="text-[11px] text-slate-400 uppercase font-semibold">Compliance Frameworks</div>
            <div class="text-lg font-extrabold text-purple-400 font-mono mt-1">GDPR + NIST + DPDP</div>
        </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1">
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5 flex flex-col shadow-xl">
            <div class="flex items-center justify-between mb-4 pb-2 border-b border-slate-800">
                <h2 class="text-xs font-bold uppercase text-slate-200 flex items-center gap-2">
                    🖥️ Dynamic Client Devices
                </h2>
                <span id="client-count" class="px-3 py-1 bg-slate-950 text-slate-300 rounded-full text-xs font-mono">0 Registered</span>
            </div>
            <div id="clients-container" class="space-y-3 overflow-y-auto flex-1 max-h-[520px]">
                <div class="text-xs text-slate-500 text-center py-12 font-mono">Loading client devices...</div>
            </div>
        </div>

        <div class="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl p-5 flex flex-col shadow-xl">
            <div class="flex items-center justify-between mb-4 pb-2 border-b border-slate-800">
                <h2 class="text-xs font-bold uppercase text-slate-200 flex items-center gap-2">
                    📈 Real-time Intercept Logs
                </h2>
                <div class="flex items-center gap-2">
                    <span id="selected-client-badge" class="px-2 py-0.5 rounded text-xs font-mono bg-emerald-950 text-emerald-400 border border-emerald-800">Selected: None</span>
                    <span id="log-count" class="px-3 py-1 bg-slate-950 text-slate-300 rounded-full text-xs font-mono">0 Recorded</span>
                </div>
            </div>
            <div class="overflow-x-auto flex-1 max-h-[520px] overflow-y-auto">
                <table class="w-full text-left border-collapse">
                    <thead class="sticky top-0 bg-[#020617] text-slate-400 text-[11px] uppercase border-b border-slate-800">
                        <tr>
                            <th class="p-3">Timestamp</th>
                            <th class="p-3">Host IP & MAC</th>
                            <th class="p-3">LLM & Version</th>
                            <th class="p-3">Tokens & Audit Hash</th>
                            <th class="p-3">Payload Prompt</th>
                        </tr>
                    </thead>
                    <tbody id="logs-table-body" class="text-slate-300 divide-y divide-slate-800 text-xs">
                        <tr><td colspan="5" class="py-12 text-center text-slate-500">Select an approved device node to view telemetry...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        const SERVER_URL = window.location.origin;
        const NOT_AVAILABLE = '<span style="color: red;">data not available / or not captured</span>';
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
                if(res.ok) { loadDashboardData(); }
            } catch(e) { console.error(e); }
        }

        async function softDeleteClient(hwId) {
            if(!confirm(`Delete device node ${hwId}?`)) return;
            try {
                const res = await fetch(`${SERVER_URL}/api/clients/${encodeURIComponent(hwId)}/delete`, { method: 'POST' });
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
                
                const statusColor = clientStatus === 'APPROVED' ? 'text-emerald-400 bg-emerald-950 border-emerald-800' : (clientStatus === 'DENIED' ? 'text-rose-400 bg-rose-950 border-rose-800' : 'text-amber-400 bg-amber-950 border-amber-800');

                const hostNameVal = c.hostname ? `<strong class="text-sky-400">${c.hostname}</strong>` : NOT_AVAILABLE;
                const hostIpVal = (c.host_ip || c.ip_address) ? `<strong class="text-amber-400">${c.host_ip || c.ip_address}</strong>` : NOT_AVAILABLE;
                const macVal = c.mac_address ? `<strong class="text-rose-400 font-mono">${c.mac_address}</strong>` : NOT_AVAILABLE;
                const cpuVal = (c.cpu_cores && c.system_arch) ? `<strong class="text-emerald-300">${c.cpu_cores} Cores (${c.system_arch})</strong>` : NOT_AVAILABLE;
                const agentVerVal = c.agent_version ? `<strong class="text-purple-400">${c.agent_version}</strong>` : NOT_AVAILABLE;

                const card = document.createElement("div");
                card.className = `p-4 rounded-xl border ${isSelected ? 'border-indigo-500 bg-indigo-950/20' : 'border-slate-800 bg-slate-950'} cursor-pointer transition font-mono mb-3`;
                card.onclick = (e) => {
                    if(e.target.tagName === 'BUTTON') return;
                    selectClient(c.hw_id);
                };
                card.innerHTML = `
                    <div class="flex justify-between items-center">
                        <span class="font-bold text-indigo-400 text-xs">${c.hw_id || NOT_AVAILABLE}</span>
                        <span class="px-2 py-0.5 rounded-full text-[10px] font-bold border ${statusColor}">${clientStatus}</span>
                    </div>
                    <div class="mt-2 text-[11px] bg-slate-900 p-2.5 rounded-lg border border-slate-800 space-y-0.5 text-slate-300">
                        <div>Hostname: ${hostNameVal}</div>
                        <div>Host IP: ${hostIpVal}</div>
                        <div>MAC Address: ${macVal}</div>
                        <div>CPU & Arch: ${cpuVal}</div>
                        <div>Agent Version: ${agentVerVal}</div>
                        <div class="pt-1 mt-1 border-t border-slate-800">Token Balance: <strong class="text-emerald-400">${(c.balance_tokens !== undefined && c.balance_tokens !== null) ? c.balance_tokens.toLocaleString() + ' tokens' : NOT_AVAILABLE}</strong></div>
                    </div>
                    <div class="flex items-center justify-between pt-2 border-t border-slate-800 mt-2">
                        <span class="text-[10px] text-indigo-400">${isSelected ? '● Selected' : 'Inspect'}</span>
                        <div class="flex gap-1.5">
                            <button onclick="updateClientStatus('${c.hw_id}', 'APPROVED')" class="px-2 py-1 bg-emerald-900 hover:bg-emerald-800 text-emerald-300 rounded text-[10px]">Approve</button>
                            <button onclick="updateClientStatus('${c.hw_id}', 'DENIED')" class="px-2 py-1 bg-rose-900 hover:bg-rose-800 text-rose-300 rounded text-[10px]">Deny</button>
                            <button onclick="softDeleteClient('${c.hw_id}')" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[10px]">Delete</button>
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
                tbody.innerHTML = `<tr><td colspan="5" class="py-12 text-center text-slate-500">No telemetry recorded for this device.</td></tr>`; 
                return; 
            }
            tbody.innerHTML = "";
            filteredLogs.forEach(l => {
                const completePrompt = l.prompt || NOT_AVAILABLE;
                const auditHash = l.audit_hash ? l.audit_hash.substring(0, 12) + "..." : NOT_AVAILABLE;

                tbody.innerHTML += `
                    <tr>
                        <td class="p-3 text-[11px]">
                            <div class="text-emerald-400">${l.timestamp_local || NOT_AVAILABLE}</div>
                            <div class="text-slate-500 text-[10px]">${l.timestamp_utc || NOT_AVAILABLE}</div>
                        </td>
                        <td class="p-3 text-[11px] font-bold">
                            <div class="text-sky-400">Host: ${l.hostname || NOT_AVAILABLE}</div>
                            <div>IP: <span class="text-amber-400">${l.host_ip || NOT_AVAILABLE}</span></div>
                            <div>MAC: <span class="text-rose-400 font-mono">${l.mac_address || NOT_AVAILABLE}</span></div>
                        </td>
                        <td class="p-3 text-[11px]">
                            <div>Model: <span class="text-purple-400 font-bold">${l.model || NOT_AVAILABLE}</span></div>
                            <div>Version: <span class="text-sky-400">${l.version || NOT_AVAILABLE}</span></div>
                        </td>
                        <td class="p-3 text-[11px]">
                            <div>Total: <span class="text-rose-400 font-bold">${l.tokens !== undefined ? l.tokens + ' tokens' : NOT_AVAILABLE}</span></div>
                            <div>Hash: <span class="text-amber-400 font-mono">${auditHash}</span></div>
                        </td>
                        <td class="p-3 text-[11px] max-w-[320px] break-words">
                            <div class="bg-slate-950 border border-slate-800 p-2 rounded text-slate-200 font-mono max-h-[90px] overflow-y-auto">
                                ${completePrompt}
                            </div>
                        </td>
                    </tr>`;
            });
        }

        function initRealtime() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const ws = new WebSocket(`${protocol}//${window.location.host}/ws/live-traffic`);
            ws.onmessage = function(event) {
                try {
                    const msg = JSON.parse(event.data);
                    if (msg.type === "NEW_TRAFFIC") {
                        loadDashboardData();
                    }
                } catch(e) { console.error("WS parse error:", e); }
            };
            ws.onclose = function() {
                setTimeout(initRealtime, 3000);
            };
        }

        loadDashboardData();
        initRealtime();
    </script>
</body>
</html>"""

@app.get("/healthz", tags=["System Probes"])
def health_check():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.get("/readyz", tags=["System Probes"])
def readiness_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ready", "database": "connected"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database unready: {str(e)}"
        )

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    return DASHBOARD_HTML

@app.get("/agent", response_class=HTMLResponse)
def serve_agent():
    if os.path.exists("agent.html"):
        with open("agent.html", "r", encoding="utf-8") as f:
            return f.read()
    return HTMLResponse(content="<h2>Agent template agent.html missing in server root.</h2>", status_code=404)

@app.get("/public-key", response_class=PlainTextResponse)
def get_public_key():
    return public_pem

@app.get("/api/device/{hw_id}")
@app.get("/api/node/{hw_id}")
@app.get("/api/status")
def get_node_status(hw_id: Optional[str] = None, db: Session = Depends(get_db)):
    if not hw_id:
        return {"status": "Approved", "approval_status": "Approved", "approved": True}
    
    client = db.query(ClientModel).filter(ClientModel.hw_id == hw_id, ClientModel.is_deleted == False).first()
    if not client:
        return {"status": NOT_AVAILABLE_HTML, "approval_status": NOT_AVAILABLE_HTML, "approved": False}
    
    return {
        "hw_id": client.hw_id,
        "status": client.status,
        "approval_status": client.status,
        "client_status": client.status,
        "approved": (client.status == "APPROVED"),
        "balance_tokens": client.balance_tokens
    }

@app.post("/api/register")
@app.post("/register")
@app.post("/api/v1/agent/discover")
async def register_client(request: Request, db: Session = Depends(get_db)):
    try:
        body = await request.json()
    except Exception:
        body = {}
    
    hw_id = body.get("hw_id") or body.get("hardware_id") or body.get("device_id")
    if not hw_id:
        raise HTTPException(status_code=400, detail="Hardware ID not captured in registration payload.")
    
    hostname = body.get("hostname") or request.headers.get("X-Hostname")
    mac_address = body.get("mac_address") or request.headers.get("X-MAC-Address") or get_system_mac()
    host_ip = get_client_ip(request)

    user_agent = request.headers.get("User-Agent", "")
    browser_name = body.get("browser_name") or parse_user_agent_details(user_agent)
    device_type = body.get("device_type") or body.get("device_name")

    client = db.query(ClientModel).filter(ClientModel.hw_id == hw_id).first()

    body["hostname"] = hostname
    body["mac_address"] = mac_address
    body["host_ip"] = host_ip
    body["ip_address"] = host_ip
    body["browser_name"] = browser_name
    body["device_type"] = device_type

    if client and not client.is_deleted:
        client.mac_address = mac_address
        client.host_ip = host_ip
        client.metadata_json = json.dumps(body)
        db.commit()
        
        return {
            "status": client.status,
            "approval_status": client.status,
            "message": f"Client agent session verified for node {hw_id}.",
            "approved": (client.status == "APPROVED"),
            "hw_id": client.hw_id,
            "hostname": hostname or NOT_AVAILABLE_HTML,
            "mac_address": mac_address or NOT_AVAILABLE_HTML,
            "host_ip": host_ip or NOT_AVAILABLE_HTML,
            "api_key": client.api_key,
            "balance_tokens": client.balance_tokens,
            "device_type": device_type or NOT_AVAILABLE_HTML,
            "browser_name": browser_name or NOT_AVAILABLE_HTML
        }

    api_key = f"sk_tenant_{secrets.token_hex(16)}"
    client = ClientModel(
        hw_id=hw_id,
        mac_address=mac_address,
        host_ip=host_ip,
        api_key=api_key,
        status="APPROVED",
        subscription_tier="ENTERPRISE_PRO",
        balance_tokens=DEFAULT_TOKEN_BALANCE,
        is_deleted=False,
        metadata_json=json.dumps(body)
    )
    db.add(client)
    db.commit()
    db.refresh(client)

    return {
        "status": client.status,
        "approval_status": client.status,
        "message": "New client node registered successfully.",
        "approved": True,
        "hw_id": client.hw_id,
        "hostname": hostname or NOT_AVAILABLE_HTML,
        "mac_address": mac_address or NOT_AVAILABLE_HTML,
        "host_ip": host_ip or NOT_AVAILABLE_HTML,
        "api_key": client.api_key,
        "balance_tokens": client.balance_tokens,
        "device_type": device_type or NOT_AVAILABLE_HTML,
        "browser_name": browser_name or NOT_AVAILABLE_HTML
    }

@app.post("/v1/chat/completions")
@app.post("/api/telemetry")
@app.post("/api/telemetry/push")
@app.post("/api/logs")
async def process_ai_traffic(request: Request, db: Session = Depends(get_db)):
    start_time = time.time()
    try:
        body = await request.json()
    except Exception:
        body = {}

    if "encrypted_payload" in body and "iv" in body:
        body = ComplianceSecurityEngine.decrypt_aes_gcm(body["encrypted_payload"], body["iv"])

    auth_header = request.headers.get("Authorization", "")
    api_key = auth_header.split(" ")[1] if auth_header.startswith("Bearer ") else None
    hw_id_header = request.headers.get("X-HW-ID") or body.get("hw_id") or body.get("hardware_id") or body.get("device_id")

    client_node = None
    if api_key:
        client_node = db.query(ClientModel).filter(ClientModel.api_key == api_key, ClientModel.is_deleted == False).first()
    if not client_node and hw_id_header:
        client_node = db.query(ClientModel).filter(ClientModel.hw_id == hw_id_header, ClientModel.is_deleted == False).first()

    if not client_node:
        raise HTTPException(status_code=400, detail="Client node registration not found or HW-ID not captured.")

    if client_node.status != "APPROVED":
        raise HTTPException(status_code=403, detail=f"Client node status is [{client_node.status}]. Telemetry rejected.")

    if client_node.balance_tokens <= 0:
        raise HTTPException(status_code=402, detail="Token quota exhausted. Top up required.")

    meta = json.loads(client_node.metadata_json) if client_node.metadata_json else {}
    headers_dict = dict(request.headers)
    metrics = parse_llm_payload(body, headers_dict, meta)

    raw_prompt = metrics["prompt"]
    sanitized_prompt = ComplianceSecurityEngine.sanitize_pii(raw_prompt)
    
    model = metrics["model_name"]
    version = metrics["version"]
    think_level = metrics["think_level"]

    hostname = metrics["hostname"] if metrics["hostname"] != NOT_AVAILABLE_HTML else (meta.get("hostname") or NOT_AVAILABLE_HTML)
    mac_address = metrics["mac_address"] if metrics["mac_address"] != NOT_AVAILABLE_HTML else (client_node.mac_address or meta.get("mac_address") or NOT_AVAILABLE_HTML)
    host_ip = client_node.host_ip or meta.get("host_ip") or get_client_ip(request) or NOT_AVAILABLE_HTML

    input_tokens = metrics["input_tokens"]
    output_tokens = metrics["output_tokens"]
    total_tokens = input_tokens + output_tokens

    client_node.balance_tokens = max(0, client_node.balance_tokens - total_tokens)
    db.commit()

    now_utc = datetime.now(timezone.utc)
    timestamp_utc = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    ist_offset = timezone(timedelta(hours=5, minutes=30))
    timestamp_local = now_utc.astimezone(ist_offset).strftime("%Y-%m-%d %H:%M:%S Local (IST)")

    ai_response_text = body.get("response") or NOT_AVAILABLE_HTML
    latency_ms = int((time.time() - start_time) * 1000)

    payload_data = {
        "hostname": hostname,
        "hw_id": client_node.hw_id,
        "mac_address": mac_address,
        "host_ip": host_ip,
        "model": model,
        "version": version,
        "think_level": think_level,
        "prompt": sanitized_prompt,
        "response": ai_response_text,
        "prompt_tokens": input_tokens,
        "completion_tokens": output_tokens,
        "tokens": total_tokens,
        "timestamp_utc": timestamp_utc,
        "timestamp_local": timestamp_local,
        "balance_tokens": client_node.balance_tokens
    }

    audit_hash = ComplianceSecurityEngine.generate_nist_audit_hash(payload_data)
    encrypted_payload = cipher.encrypt(json.dumps(payload_data).encode()).decode()

    log_entry = TrafficLogModel(
        hw_id=client_node.hw_id,
        provider=body.get("provider"),
        model=model,
        version=version,
        think_level=think_level,
        prompt=sanitized_prompt,
        prompt_tokens=input_tokens,
        completion_tokens=output_tokens,
        latency_ms=latency_ms,
        audit_hash=audit_hash,
        payload_json=encrypted_payload
    )
    db.add(log_entry)
    db.commit()

    await manager.broadcast({
        "type": "NEW_TRAFFIC",
        "data": {
            "id": log_entry.id,
            "hw_id": client_node.hw_id,
            "hostname": hostname,
            "mac_address": mac_address,
            "host_ip": host_ip,
            "prompt": sanitized_prompt,
            "tokens": total_tokens,
            "audit_hash": audit_hash
        }
    })

    return {
        "status": "success",
        "id": f"chatcmpl-{int(time.time())}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": ai_response_text}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": input_tokens, "completion_tokens": output_tokens, "total_tokens": total_tokens},
        "balance_tokens": client_node.balance_tokens,
        "audit_hash": audit_hash
    }

@app.post("/api/clients/{hw_id}/status")
async def update_client_status(hw_id: str, request: Request, user: dict = Depends(verify_admin_user), db: Session = Depends(get_db)):
    body = await request.json()
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
    active_clients = db.query(ClientModel).filter(ClientModel.is_deleted == False).all()
    active_hw_ids = {c.hw_id for c in active_clients}
    rows = db.query(TrafficLogModel).filter(TrafficLogModel.hw_id.in_(active_hw_ids)).order_by(TrafficLogModel.created_at.desc()).all() if active_hw_ids else []

    output = io.StringIO()
    output.write("HardwareID,MACAddress,HostIP,Model,Version,PromptTokens,CompletionTokens,TotalTokens,NISTAuditHash,CompletePromptPayload,TimestampUTC\n")
    
    for r in rows:
        p = {}
        try:
            p = json.loads(cipher.decrypt(r.payload_json.encode()).decode())
        except Exception:
            pass
            
        hw_id = r.hw_id or NOT_AVAILABLE_HTML
        mac_address = p.get("mac_address") or NOT_AVAILABLE_HTML
        host_ip = p.get("host_ip") or NOT_AVAILABLE_HTML
        model = r.model or NOT_AVAILABLE_HTML
        version = r.version or NOT_AVAILABLE_HTML
        prompt_tokens = r.prompt_tokens or 0
        completion_tokens = r.completion_tokens or 0
        total_tokens = prompt_tokens + completion_tokens
        audit_hash = r.audit_hash or NOT_AVAILABLE_HTML
        complete_prompt_text = str(r.prompt or NOT_AVAILABLE_HTML).replace('"', '""')
        timestamp_utc = r.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if r.created_at else NOT_AVAILABLE_HTML
        
        output.write(f'"{hw_id}","{mac_address}","{host_ip}","{model}","{version}",{prompt_tokens},{completion_tokens},{total_tokens},"{audit_hash}","{complete_prompt_text}","{timestamp_utc}"\n')
        
    response = StreamingResponse(iter([output.getvalue()]), media_type="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=ai_traffic_compliance_audit.csv"
    return response

@app.get("/api/dashboard-data")
def dashboard_data(user: dict = Depends(verify_admin_user), db: Session = Depends(get_db)):
    client_rows = db.query(ClientModel).filter(ClientModel.is_deleted == False).all()
    client_map = {c.hw_id: c for c in client_rows}
    approved_hw_ids = set(client_map.keys())
    
    log_rows = db.query(TrafficLogModel).filter(TrafficLogModel.hw_id.in_(approved_hw_ids)).order_by(TrafficLogModel.id.desc()).limit(200).all() if approved_hw_ids else []

    clients = []
    for c in client_rows:
        meta = json.loads(c.metadata_json) if c.metadata_json else {}
        clients.append({
            **meta,
            "hw_id": c.hw_id,
            "mac_address": c.mac_address or meta.get("mac_address"),
            "host_ip": c.host_ip or meta.get("host_ip"),
            "hostname": meta.get("hostname"),
            "status": c.status or "APPROVED",
            "balance_tokens": c.balance_tokens,
            "browser_name": meta.get("browser_name"),
            "cpu_cores": meta.get("cpu_cores"),
            "system_memory": meta.get("system_memory"),
            "timezone": meta.get("timezone"),
            "agent_version": meta.get("agent_version"),
            "api_key": c.api_key
        })

    logs = []
    for l in log_rows:
        payload = {}
        try:
            payload = json.loads(cipher.decrypt(l.payload_json.encode()).decode())
        except Exception:
            pass

        client = client_map.get(l.hw_id)
        client_meta = json.loads(client.metadata_json) if client and client.metadata_json else {}

        db_time = l.created_at or datetime.now(timezone.utc)
        utc_str = db_time.strftime("%Y-%m-%d %H:%M:%S UTC") if hasattr(db_time, 'strftime') else str(db_time)

        resolved_mac = payload.get("mac_address") or (client.mac_address if client else None) or client_meta.get("mac_address")
        resolved_ip = payload.get("host_ip") or (client.host_ip if client else None) or client_meta.get("host_ip")
        resolved_host = payload.get("hostname") or client_meta.get("hostname")

        calculated_tokens = (l.prompt_tokens or 0) + (l.completion_tokens or 0)

        logs.append({
            "id": l.id,
            "hw_id": l.hw_id,
            "mac_address": resolved_mac,
            "host_ip": resolved_ip,
            "hostname": resolved_host,
            "timestamp_utc": utc_str,
            "timestamp_local": payload.get("timestamp_local") or utc_str,
            "model": normalize_model_name(l.model),
            "version": l.version,
            "prompt": l.prompt,
            "tokens": calculated_tokens,
            "audit_hash": l.audit_hash
        })

    return {"clients": clients, "logs": logs, "authenticated_user": user.get("sub")}

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
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)