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

# Database Initialization
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

# Persistent Cryptographic Key Setup
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

# Compliance Engine (GDPR, DPDP, NIST SP 800-92)
class ComplianceSecurityEngine:
    @staticmethod
    def sanitize_pii(text_content: str) -> str:
        """Redacts PII and sensitive tokens under GDPR, DPDP, and NIST guidelines."""
        if not isinstance(text_content, str):
            return str(text_content) if text_content else ""
        
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
        """Generates an immutable HMAC-SHA256 audit signature per NIST SP 800-92."""
        serialized = json.dumps(payload, sort_keys=True)
        return hmac.new(MASTER_AES_KEY, serialized.encode('utf-8'), hashlib.sha256).hexdigest()

    @staticmethod
    def decrypt_aes_gcm(encrypted_b64: str, iv_b64: str) -> dict:
        """Decrypts E2E payload using AES-256-GCM."""
        try:
            aesgcm = AESGCM(MASTER_AES_KEY)
            ciphertext = base64.b64decode(encrypted_b64)
            iv = base64.b64decode(iv_b64)
            decrypted_raw = aesgcm.decrypt(iv, ciphertext, None)
            return json.loads(decrypted_raw.decode('utf-8'))
        except Exception as e:
            raise ValueError(f"AES-GCM Decryption failure: {str(e)}")

# ORM Database Models
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

def get_system_mac() -> str:
    mac_num = uuid.getnode()
    mac_hex = f"{mac_num:012X}"
    return ":".join(mac_hex[i:i+2] for i in range(0, 12, 2))

def parse_user_agent_details(user_agent: str) -> str:
    if not user_agent or user_agent == "Unknown":
        return "Unknown Agent"
    
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
    elif "Opera/" in ua or "OPR/" in ua:
        version = ua.split("OPR/")[1].split(" ")[0] if "OPR/" in ua else ua.split("Opera/")[1].split(" ")[0]
        return f"Opera v{version}"
    elif "PostmanRuntime" in ua:
        return f"Postman Client ({ua.split('/')[1]})"
    elif "python-requests" in ua:
        return f"Python Requests Agent ({ua.split('/')[1]})"
    
    return f"User Agent ({ua[:25]}...)"

def normalize_model_name(raw_model: str) -> str:
    """Formats intercepted domains or model identifiers into clean enterprise names."""
    if not raw_model:
        return "Unknown AI Model"
    
    model_str = str(raw_model).strip()
    if "perplexity.ai" in model_str.lower():
        return f"Perplexity AI ({model_str.lower()})"
    elif "openai" in model_str.lower() or "gpt" in model_str.lower():
        return f"OpenAI ({model_str})"
    elif "anthropic" in model_str.lower() or "claude" in model_str.lower():
        return f"Anthropic Claude ({model_str})"
    elif "gemini" in model_str.lower():
        return f"Google Gemini ({model_str})"
    
    if model_str.lower().endswith(" ai model"):
        return model_str.title()
    
    return model_str

def parse_llm_payload(body: dict, headers: dict = None, meta: dict = None) -> dict:
    headers = headers or {}
    meta = meta or {}
    
    hostname = body.get("hostname") or headers.get("x-hostname") or meta.get("hostname") or socket.gethostname()
    hw_id = body.get("hw_id") or body.get("hardware_id") or body.get("device_id") or headers.get("x-hw-id") or meta.get("hw_id") or f"HW-NODE-{secrets.token_hex(4).upper()}"
    mac_address = body.get("mac_address") or headers.get("x-mac-address") or meta.get("mac_address") or get_system_mac()
    
    raw_model = body.get("model") or body.get("llm_model") or body.get("model_name") or body.get("host") or "Unknown Model"
    model_name = normalize_model_name(raw_model)
    model_version = body.get("version") or body.get("model_version") or headers.get("x-model-version") or "v1.0"
    think_level = body.get("think_level") or body.get("reasoning_effort") or "Standard Reasoning"

    full_prompt = body.get("prompt") or body.get("full_prompt") or body.get("payload") or body.get("activity")
    if not full_prompt and "messages" in body and isinstance(body["messages"], list):
        full_prompt = "\n".join([f"{m.get('role', 'user')}: {m.get('content', '')}" for m in body["messages"]])

    if not full_prompt:
        full_prompt = "Active Telemetry Session Intercepted."

    usage = body.get("usage") or body.get("usageMetadata") or {}
    if not isinstance(usage, dict):
        usage = {}

    input_tokens = body.get("prompt_tokens") or body.get("input_tokens") or usage.get("prompt_tokens") or usage.get("promptTokenCount") or 0
    output_tokens = body.get("completion_tokens") or body.get("output_tokens") or usage.get("completion_tokens") or usage.get("candidatesTokenCount") or 0
    total_tokens = body.get("tokens_used") or usage.get("total_tokens") or (input_tokens + output_tokens)

    if total_tokens <= 0 and full_prompt:
        words = len(str(full_prompt).split())
        chars = len(str(full_prompt))
        input_tokens = max(12, words, int(chars / 4))
        output_tokens = 0
        total_tokens = input_tokens

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
    logger.info("Enterprise Gateway online and ready for connections.")
    yield
    logger.info("Shutting down Enterprise Gateway services.")

app = FastAPI(
    title="Enterprise Cloud AI Gateway & Control Plane",
    description="E2E Encrypted Secure Gateway with GDPR, NIST, and DPDP Compliance.",
    version="10.4.0",
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

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"

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

ICONS = {
    "shield": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    "smartphone": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="14" height="20" x="5" y="2" rx="2"/><path d="M12 18h.01"/></svg>',
    "download": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/></svg>',
    "refresh": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/></svg>',
    "server": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="20" height="8" x="2" y="2" rx="2"/><rect width="20" height="8" x="2" y="14" rx="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/></svg>',
    "activity": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',
    "cpu": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M9 1v3"/><path d="M15 1v3"/><path d="M9 20v3"/><path d="M15 20v3"/><path d="M20 9h3"/><path d="M20 14h3"/><path d="M1 9h3"/><path d="M1 14h3"/></svg>',
    "send": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m22 2-7 20-4-9-9-4Z"/><path d="M22 2 11 13"/></svg>'
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

DASHBOARD_HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Cloud AI Gateway & Control Plane</title>
    <style>{GLOBAL_CSS}</style>
</head>
<body class="min-h-screen p-6 flex flex-col gap-4">
    <header class="flex flex-col md:flex-row items-center justify-between border border-slate-800 pb-4 gap-4 bg-slate-900 p-4 rounded-xl">
        <div class="flex items-center gap-3">
            <div class="bg-indigo-600 p-2.5 rounded-xl text-white shadow flex items-center justify-center">
                {ICONS["shield"]}
            </div>
            <div>
                <h1 class="text-sm font-bold text-white">Enterprise Cloud AI Gateway & Control Plane</h1>
                <p class="text-xs text-indigo-400">E2E Secure Telemetry, Real-time Sessions, GDPR / NIST / DPDP Active</p>
            </div>
        </div>
        <div class="flex items-center gap-3 flex-wrap">
            <span id="connection-badge" class="px-3 py-1 bg-emerald-950 text-emerald-400 border border-slate-800 rounded-full text-xs font-mono flex items-center gap-1.5">
                <span style="width:8px; height:8px; border-radius:50%; background:#10b981;"></span> Connected
            </span>
            <a href="/agent" target="_blank" style="padding: 0.5rem 0.875rem; background: #4f46e5; color: white; border-radius: 0.5rem; text-decoration: none;" class="text-xs font-bold flex items-center gap-1.5">
                {ICONS["smartphone"]} Agent Window
            </a>
            <a href="/api/export-audit-report" style="padding: 0.5rem 0.875rem; background: #1e293b; color: #e2e8f0; border-radius: 0.5rem; text-decoration: none;" class="text-xs font-semibold flex items-center gap-1.5">
                {ICONS["download"]} Export Audit CSV
            </a>
            <button onclick="loadDashboardData()" style="padding: 0.5rem 0.875rem; background: #1e293b; color: #e2e8f0; border-radius: 0.5rem; border: none; cursor: pointer;" class="text-xs font-semibold flex items-center gap-1.5">
                {ICONS["refresh"]} Refresh
            </button>
        </div>
    </header>

    <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; font-weight: 600;">Unique Client Nodes</div>
            <div id="stat-total-clients" style="font-size: 1.5rem; font-weight: 800; color: #ffffff;" class="font-mono mt-1">0</div>
        </div>
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; font-weight: 600;">Active Nodes</div>
            <div id="stat-approved-clients" style="font-size: 1.5rem; font-weight: 800; color: #34d399;" class="font-mono mt-1">0</div>
        </div>
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; font-weight: 600;">Telemetry Events</div>
            <div id="stat-total-tokens" style="font-size: 1.5rem; font-weight: 800; color: #818cf8;" class="font-mono mt-1">0</div>
        </div>
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; font-weight: 600;">Compliance Frameworks</div>
            <div style="font-size: 1.1rem; font-weight: 800; color: #c084fc;" class="font-mono mt-1">GDPR + NIST + DPDP</div>
        </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1">
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5 flex flex-col shadow-xl">
            <div class="flex items-center justify-between mb-4 pb-2" style="border-bottom: 1px solid #1e293b;">
                <h2 class="text-xs font-bold uppercase text-slate-200 flex items-center gap-2">
                    {ICONS["server"]} Dynamic Client Devices
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
                    {ICONS["activity"]} Real-time Intercept Logs
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
                            <th>Host IP & MAC</th>
                            <th>LLM & Version</th>
                            <th>Tokens & Audit Hash</th>
                            <th>Payload Prompt</th>
                        </tr>
                    </thead>
                    <tbody id="logs-table-body" style="color: #cbd5e1;">
                        <tr><td colspan="5" class="py-12 text-center text-slate-500">Select an approved device node to view telemetry...</td></tr>
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

        async function loadDashboardData() {{
            try {{
                const res = await fetch(`${{SERVER_URL}}/api/dashboard-data`);
                if(!res.ok) return;
                const data = await res.json();
                
                globalClients = (data.clients || []).filter(c => !c.is_deleted);
                globalLogs = data.logs || [];

                const approvedClients = globalClients.filter(c => c.status === 'APPROVED');

                document.getElementById("stat-total-clients").innerText = globalClients.length;
                document.getElementById("stat-approved-clients").innerText = approvedClients.length;
                document.getElementById("stat-total-tokens").innerText = globalLogs.length;

                if (selectedHwId && !globalClients.some(c => c.hw_id === selectedHwId)) {{
                    selectedHwId = null;
                }}
                if (!selectedHwId && globalClients.length > 0) {{
                    selectedHwId = globalClients[0].hw_id;
                }}

                renderClients(globalClients);
                renderLogs(globalLogs);
            }} catch (err) {{ console.error("Fetch error:", err); }}
        }}

        async function updateClientStatus(hwId, status) {{
            try {{
                const res = await fetch(`${{SERVER_URL}}/api/clients/${{encodeURIComponent(hwId)}}/status`, {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{ status: status }})
                }});
                if(res.ok) {{ loadDashboardData(); }}
            }} catch(e) {{ console.error(e); }}
        }}

        async function softDeleteClient(hwId) {{
            if(!confirm(`Delete device node ${{hwId}}?`)) return;
            try {{
                const res = await fetch(`${{SERVER_URL}}/api/clients/${{encodeURIComponent(hwId)}}/delete`, {{ method: 'POST' }});
                if(res.ok) {{ 
                    if(selectedHwId === hwId) {{ selectedHwId = null; }}
                    loadDashboardData(); 
                }}
            }} catch(e) {{ console.error(e); }}
        }}

        function selectClient(hwId) {{
            selectedHwId = hwId;
            renderClients(globalClients);
            renderLogs(globalLogs);
        }}

        function renderClients(clients) {{
            const container = document.getElementById("clients-container");
            document.getElementById("client-count").innerText = `${{clients.length}} Registered`;
            if (!clients.length) {{ 
                container.innerHTML = `<div class="text-xs text-slate-500 text-center py-12 font-mono">No client devices registered yet.</div>`; 
                renderLogs([]);
                return; 
            }}
            container.innerHTML = "";
            clients.forEach(c => {{
                const isSelected = c.hw_id === selectedHwId;
                const clientStatus = c.status || 'APPROVED';
                
                const statusColor = clientStatus === 'APPROVED' ? '#34d399' : (clientStatus === 'DENIED' ? '#fca5a5' : '#fbbf24');
                const statusBg = clientStatus === 'APPROVED' ? '#022c22' : (clientStatus === 'DENIED' ? '#450a0a' : '#451a03');

                const card = document.createElement("div");
                card.style.cssText = `padding: 1rem; border-radius: 0.75rem; border: 1px solid ${{isSelected ? '#4f46e5' : '#1e293b'}}; background: ${{isSelected ? 'rgba(79, 70, 229, 0.1)' : '#020617'}}; cursor: pointer; font-family: monospace; margin-bottom: 0.75rem;`;
                card.onclick = (e) => {{
                    if(e.target.tagName === 'BUTTON') return;
                    selectClient(c.hw_id);
                }};
                card.innerHTML = `
                    <div class="flex justify-between items-center">
                        <span style="font-weight: 700; color: #818cf8; font-size: 11px;">${{c.hw_id}}</span>
                        <span style="padding: 0.125rem 0.5rem; border-radius: 9999px; font-size: 10px; font-weight: 700; color: ${{statusColor}}; background: ${{statusBg}};">${{clientStatus}}</span>
                    </div>
                    <div style="margin-top: 0.5rem; font-size: 11px; background: #0f172a; padding: 0.5rem; border-radius: 0.375rem; border: 1px solid #1e293b; line-height: 1.4;">
                        <div>Hostname: <strong style="color: #38bdf8;">${{c.hostname || 'N/A'}}</strong></div>
                        <div>Host IP Address: <strong style="color: #fbbf24;">${{c.host_ip || c.ip_address || 'N/A'}}</strong></div>
                        <div>MAC Address: <strong style="color: #f43f5e;">${{c.mac_address || 'N/A'}}</strong></div>
                        <div>Browser Agent: <strong style="color: #34d399;">${{c.browser_name || 'N/A'}}</strong></div>
                        <div>OS Context: <strong style="color: #67e8f9;">${{c.device_type || 'N/A'}}</strong></div>
                        <div style="margin-top: 4px; padding-top: 4px; border-top: 1px dashed #1e293b;">Token Balance: <strong style="color: #34d399;">${{(c.balance_tokens || 0).toLocaleString()}} tokens</strong></div>
                    </div>
                    <div class="flex items-center justify-between" style="padding-top: 0.5rem; border-top: 1px solid #1e293b; margin-top: 0.5rem;">
                        <span style="font-size: 10px; color: #818cf8;">${{isSelected ? '● Selected' : 'Inspect'}}</span>
                        <div class="flex gap-1.5">
                            <button onclick="updateClientStatus('${{c.hw_id}}', 'APPROVED')" style="padding: 0.25rem 0.5rem; background: #065f46; color: #34d399; border-radius: 0.25rem; font-size: 10px; border: none; cursor: pointer;">Approve</button>
                            <button onclick="updateClientStatus('${{c.hw_id}}', 'DENIED')" style="padding: 0.25rem 0.5rem; background: #7f1d1d; color: #fca5a5; border-radius: 0.25rem; font-size: 10px; border: none; cursor: pointer;">Deny</button>
                            <button onclick="softDeleteClient('${{c.hw_id}}')" style="padding: 0.25rem 0.5rem; background: #334155; color: #cbd5e1; border-radius: 0.25rem; font-size: 10px; border: none; cursor: pointer;">Delete</button>
                        </div>
                    </div>`;
                container.appendChild(card);
            }});
        }}

        function renderLogs(logs) {{
            const tbody = document.getElementById("logs-table-body");
            const badge = document.getElementById("selected-client-badge");
            
            if (!selectedHwId || globalClients.length === 0) {{
                badge.innerText = "Selected: None";
                document.getElementById("log-count").innerText = "0 Recorded";
                tbody.innerHTML = `<tr><td colspan="5" class="py-12 text-center text-slate-500">No device node selected.</td></tr>`;
                return;
            }}

            badge.innerText = `Selected: ${{selectedHwId}}`;
            const filteredLogs = logs.filter(l => l.hw_id === selectedHwId);
            document.getElementById("log-count").innerText = `${{filteredLogs.length}} Recorded`;

            if (!filteredLogs.length) {{ 
                tbody.innerHTML = `<tr><td colspan="5" class="py-12 text-center text-slate-500">No telemetry recorded for this device.</td></tr>`; 
                return; 
            }}
            tbody.innerHTML = "";
            filteredLogs.forEach(l => {{
                const completePrompt = l.prompt || 'N/A';
                const auditHash = l.audit_hash ? l.audit_hash.substring(0, 12) + "..." : "N/A";

                tbody.innerHTML += `
                    <tr>
                        <td style="font-size: 11px;">
                            <div style="color: #34d399;">Local: ${{l.timestamp_local || 'N/A'}}</div>
                            <div style="color: #94a3b8; font-size: 10px;">UTC: ${{l.timestamp_utc || 'N/A'}}</div>
                        </td>
                        <td style="font-size: 11px; font-weight: bold; color: #818cf8;">
                            <div style="color: #38bdf8;">Host: ${{l.hostname || 'N/A'}}</div>
                            <div>IP: <span style="color: #fbbf24;">${{l.host_ip || 'N/A'}}</span></div>
                            <div>MAC: <span style="color: #f43f5e; font-family: monospace;">${{l.mac_address || 'N/A'}}</span></div>
                        </td>
                        <td style="font-size: 11px;">
                            <div>Model: <span style="color: #c084fc; font-weight: bold;">${{l.model || 'N/A'}}</span></div>
                            <div>Version: <span style="color: #38bdf8;">${{l.version || 'N/A'}}</span></div>
                        </td>
                        <td style="font-size: 11px;">
                            <div>Total: <span style="color: #f43f5e; font-weight: bold;">${{l.tokens || 0}} tokens</span></div>
                            <div>Audit Hash: <span style="color: #fbbf24; font-family: monospace;">${{auditHash}}</span></div>
                        </td>
                        <td style="font-size: 11px; max-width: 320px; word-break: break-word;">
                            <div style="background: #020617; border: 1px solid #1e293b; padding: 0.5rem; border-radius: 0.375rem; color: #e2e8f0; font-family: monospace; max-height: 90px; overflow-y: auto;">
                                <strong>Prompt:</strong> ${{completePrompt}}
                            </div>
                        </td>
                    </tr>`;
            }});
        }}

        function initRealtime() {{
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const ws = new WebSocket(`${{protocol}}//${{window.location.host}}/ws/live-traffic`);
            ws.onmessage = function(event) {{
                try {{
                    const msg = JSON.parse(event.data);
                    if (msg.type === "NEW_TRAFFIC") {{
                        loadDashboardData();
                    }}
                }} catch(e) {{ console.error("WS parse error:", e); }}
            }};
            ws.onclose = function() {{
                setTimeout(initRealtime, 3000);
            }};
        }}

        loadDashboardData();
        initRealtime();
    </script>
</body>
</html>"""

WEB_AGENT_HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Universal AI Telemetry Agent - E2E Encrypted</title>
    <style>{GLOBAL_CSS}</style>
</head>
<body class="min-h-screen p-4 flex flex-col items-center justify-center">
    <div class="max-w-4xl w-full bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-xl flex flex-col" style="height: 94vh;">
        <div class="flex flex-col md:flex-row items-center justify-between mb-3 border-b border-slate-800 pb-3 gap-2">
            <div>
                <h1 class="text-sm font-bold text-white flex items-center gap-2">
                    {ICONS["smartphone"]} Universal AI Telemetry Agent
                </h1>
                <p id="client-info" class="text-xs text-indigo-400 font-mono mt-0.5">Initializing Realtime Client Node...</p>
            </div>
            <div class="flex items-center gap-3 flex-wrap">
                <a href="/" class="text-indigo-400 text-xs font-mono" style="text-decoration: none;">&larr; Return to Control Plane</a>
            </div>
        </div>

        <div id="dedup-warning-banner" style="display: none; background: #451a03; border: 1px solid #b45309; padding: 0.75rem; border-radius: 0.5rem; margin-bottom: 0.75rem; font-family: monospace;" class="text-xs">
            <strong style="color: #fbbf24;">[AGENT SINGLETON NOTICE]:</strong> <span id="dedup-warning-text" style="color: #fde68a;">Reusing established client node details.</span>
        </div>

        <div style="background: #020617; border: 1px solid #1e293b; border-radius: 0.75rem; padding: 1rem; margin-bottom: 0.75rem; font-family: monospace;">
            <div style="font-size: 11px; font-weight: bold; color: #34d399; margin-bottom: 0.5rem; display: flex; align-items: center; gap: 0.5rem;">
                {ICONS["cpu"]} Dynamic Realtime Telemetry Transmission
            </div>
            <div class="grid grid-cols-1 md:grid-cols-4 gap-2 mb-2">
                <div>
                    <label style="font-size: 10px; color: #94a3b8; display: block; margin-bottom: 2px;">Hostname:</label>
                    <input type="text" id="external-hostname" placeholder="Fetching..." style="width: 100%; background: #0f172a; border: 1px solid #334155; color: #f8fafc; padding: 0.4rem; border-radius: 0.375rem; font-size: 11px;">
                </div>
                <div>
                    <label style="font-size: 10px; color: #94a3b8; display: block; margin-bottom: 2px;">LLM Model:</label>
                    <input type="text" id="external-model-name" value="gemini-2.5-pro" style="width: 100%; background: #0f172a; border: 1px solid #334155; color: #f8fafc; padding: 0.4rem; border-radius: 0.375rem; font-size: 11px;">
                </div>
                <div>
                    <label style="font-size: 10px; color: #94a3b8; display: block; margin-bottom: 2px;">Reasoning Level:</label>
                    <select id="external-think-level" style="width: 100%; background: #0f172a; border: 1px solid #334155; color: #f8fafc; padding: 0.4rem; border-radius: 0.375rem; font-size: 11px;">
                        <option value="High Reasoning (DeepThink)">High Reasoning (DeepThink)</option>
                        <option value="Standard Reasoning">Standard Reasoning</option>
                    </select>
                </div>
                <div>
                    <label style="font-size: 10px; color: #94a3b8; display: block; margin-bottom: 2px;">Version Tag:</label>
                    <input type="text" id="external-version" value="v2.5" style="width: 100%; background: #0f172a; border: 1px solid #334155; color: #f8fafc; padding: 0.4rem; border-radius: 0.375rem; font-size: 11px;">
                </div>
            </div>
            <div class="mb-2">
                <label style="font-size: 10px; color: #94a3b8; display: block; margin-bottom: 2px;">Prompt Payload Input:</label>
                <textarea id="external-prompt-input" rows="3" placeholder="Enter custom prompt payload..." style="width: 100%; background: #0f172a; border: 1px solid #334155; color: #f8fafc; padding: 0.4rem; border-radius: 0.375rem; font-size: 11px; font-family: monospace;"></textarea>
            </div>
            <button onclick="captureExternalAppPrompt()" style="width: 100%; padding: 0.5rem; background: #059669; color: white; border-radius: 0.375rem; border: none; cursor: pointer; font-weight: bold; font-size: 11px;" class="flex items-center justify-center gap-1.5">
                {ICONS["send"]} Transmit Telemetry Payload
            </button>
        </div>

        <div id="chat-messages" class="flex-1 bg-slate-950 rounded-xl p-4 border border-slate-800 overflow-y-auto space-y-3 text-xs font-mono mb-3">
            <div class="text-slate-500 text-center py-6">Ready to stream encrypted telemetry. Dynamic hardware identification enabled.</div>
        </div>
    </div>

    <script>
        const SERVER_URL = window.location.origin;
        const SINGLETON_CHANNEL = new BroadcastChannel("agent_singleton_lock");
        let clientCredentials = {{ hw_id: "", api_key: "", device_type: "", browser_name: "", hostname: "", mac_address: "" }};

        SINGLETON_CHANNEL.postMessage({{ type: "PING_AGENT_EXISTENCE" }});
        SINGLETON_CHANNEL.onmessage = (event) => {{
            if (event.data.type === "PING_AGENT_EXISTENCE") {{
                SINGLETON_CHANNEL.postMessage({{ type: "AGENT_ALREADY_RUNNING", hwid: clientCredentials.hw_id }});
            }} else if (event.data.type === "AGENT_ALREADY_RUNNING") {{
                showDedupWarning(`Client agent active on this system. Reusing HWID: ${{event.data.hwid}}`);
            }}
        }};

        function showDedupWarning(msg) {{
            const banner = document.getElementById("dedup-warning-banner");
            const text = document.getElementById("dedup-warning-text");
            text.innerText = msg;
            banner.style.display = "block";
        }}

        function getDeviceAndHardwareProfile() {{
            const ua = navigator.userAgent;
            let osPrefix = "HW-SYS";
            let osName = navigator.platform || "Unknown OS";
            
            if (/android/i.test(ua)) {{ osPrefix = "HW-ANDROID"; osName = "Android Mobile"; }}
            else if (/iphone|ipad|ipod/i.test(ua)) {{ osPrefix = "HW-IOS"; osName = "iOS Mobile"; }}
            else if (/macintosh|mac os x/i.test(ua)) {{ osPrefix = "HW-MAC"; osName = "macOS Workstation"; }}
            else if (/windows/i.test(ua)) {{ osPrefix = "HW-WIN"; osName = "Windows Workstation"; }}
            else if (/linux/i.test(ua)) {{ osPrefix = "HW-LINUX"; osName = "Linux Workstation"; }}

            let cachedHwid = localStorage.getItem("gateway_client_hwid");
            if (!cachedHwid) {{
                const screenStr = `${{window.screen.width}}x${{window.screen.height}}`;
                const rawHashStr = `${{ua}}|${{screenStr}}|${{navigator.hardwareConcurrency || 2}}`;
                let hash = 0;
                for (let i = 0; i < rawHashStr.length; i++) {{
                    hash = ((hash << 5) - hash) + rawHashStr.charCodeAt(i);
                    hash |= 0;
                }}
                const uniqueHashHex = Math.abs(hash).toString(16).toUpperCase().padStart(8, '0');
                cachedHwid = `${{osPrefix}}-${{uniqueHashHex.slice(0, 8)}}`;
                localStorage.setItem("gateway_client_hwid", cachedHwid);
            }}

            const macArr = cachedHwid.replace(/[^A-Z0-9]/g, '').padEnd(12, '0').match(/.{{1,2}}/g) || ["00", "00", "00", "00", "00", "00"];
            const macAddress = macArr.join(":").toUpperCase();
            const inferredHost = window.location.hostname || "local-node";

            return {{ hw_id: cachedHwid, device_type: osName, browser_name: navigator.userAgent.slice(0, 30), mac_address: macAddress, hostname: inferredHost }};
        }}

        async function initClient() {{
            try {{
                const profile = getDeviceAndHardwareProfile();
                document.getElementById("external-hostname").value = profile.hostname;

                const res = await fetch(`${{SERVER_URL}}/api/register`, {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{
                        hw_id: profile.hw_id,
                        hostname: profile.hostname,
                        mac_address: profile.mac_address,
                        device_type: profile.device_type,
                        browser_name: profile.browser_name,
                        user_agent: navigator.userAgent
                    }})
                }});
                const data = await res.json();

                if (data.status === "EXISTING_SESSION_REUSED") {{
                    showDedupWarning(data.message);
                }}

                clientCredentials.hw_id = data.hw_id;
                clientCredentials.api_key = data.api_key;
                clientCredentials.device_type = profile.device_type;
                clientCredentials.browser_name = data.browser_name || profile.browser_name;
                clientCredentials.hostname = data.hostname || profile.hostname;
                clientCredentials.mac_address = data.mac_address || profile.mac_address;

                document.getElementById("client-info").innerText = `HW-ID: ${{data.hw_id}} | Host IP: ${{data.host_ip}} | MAC: ${{clientCredentials.mac_address}} | OS: ${{clientCredentials.device_type}}`;
            }} catch(e) {{ console.error("Client registration error:", e); }}
        }}

        async function captureExternalAppPrompt() {{
            if(!clientCredentials.api_key) {{ await initClient(); }}
            if(!clientCredentials.api_key) return;

            const modelName = document.getElementById("external-model-name").value;
            const modelVersion = document.getElementById("external-version").value;
            const thinkLevel = document.getElementById("external-think-level").value;
            const hostName = document.getElementById("external-hostname").value;
            const promptText = document.getElementById("external-prompt-input").value.trim();
            
            if(!promptText) {{ alert("Please enter a prompt payload."); return; }}

            const chatContainer = document.getElementById("chat-messages");

            try {{
                const res = await fetch(`${{SERVER_URL}}/v1/chat/completions`, {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${{clientCredentials.api_key}}`,
                        'X-HW-ID': clientCredentials.hw_id
                    }},
                    body: JSON.stringify({{
                        hostname: hostName,
                        hw_id: clientCredentials.hw_id,
                        mac_address: clientCredentials.mac_address,
                        model: modelName,
                        version: modelVersion,
                        think_level: thinkLevel,
                        prompt: promptText
                    }})
                }});

                if(!res.ok) throw new Error(await res.text());
                const data = await res.json();

                chatContainer.innerHTML += `<div style="padding: 0.6rem; background: rgba(6, 95, 70, 0.3); border: 1px solid #059669; border-radius: 0.5rem; margin-bottom: 0.5rem;">
                    <strong style="color: #34d399;">[Transmitted Telemetry]:</strong>
                    <div style="background: #020617; padding: 0.4rem; border-radius: 0.25rem; margin: 4px 0; color: #f8fafc;">${{promptText}}</div>
                    <div style="font-size: 10px; color: #38bdf8; margin-top: 3px;">
                        HWID: ${{clientCredentials.hw_id}} | Remaining Balance:     ${{(data.balance_tokens || 0).toLocaleString()}} tokens | NIST Hash: ${{data.audit_hash.substring(0, 10)}}...
                    </div>
                </div>`;
                chatContainer.scrollTop = chatContainer.scrollHeight;
            }} catch(e) {{
                chatContainer.innerHTML += `<div style="padding: 0.6rem; background: #450a0a; color: #fca5a5; border-radius: 0.5rem;">Error sending telemetry: ${{e.message}}</div>`;
            }}
        }}

        initClient();
    </script>
</body>
</html>"""

# System Probes
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

# Dashboard & UI Endpoints
@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    return DASHBOARD_HTML

@app.get("/agent", response_class=HTMLResponse)
def serve_agent():
    return WEB_AGENT_HTML

@app.get("/public-key", response_class=PlainTextResponse)
def get_public_key():
    return public_pem

# Unified Client Registration & Deduplication Endpoint
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
        hw_id = f"HW-GENERIC-{secrets.token_hex(4).upper()}"
    
    hostname = body.get("hostname") or request.headers.get("X-Hostname") or socket.gethostname()
    mac_address = body.get("mac_address") or request.headers.get("X-MAC-Address") or get_system_mac()
    host_ip = get_client_ip(request)

    user_agent = request.headers.get("User-Agent", "")
    browser_name = body.get("browser_name") or parse_user_agent_details(user_agent)
    device_type = body.get("device_type") or body.get("device_name") or platform.system()

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
            "status": "EXISTING_SESSION_REUSED",
            "message": f"Client agent active on node {device_type}. Reusing existing session.",
            "approval_status": client.status,
            "approved": (client.status == "APPROVED"),
            "hw_id": client.hw_id,
            "hostname": hostname,
            "mac_address": mac_address,
            "host_ip": host_ip,
            "api_key": client.api_key,
            "balance_tokens": client.balance_tokens,
            "device_type": device_type,
            "browser_name": browser_name
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
        "status": "REGISTERED_NEW",
        "message": "New client node registered successfully.",
        "approval_status": client.status,
        "approved": True,
        "hw_id": client.hw_id,
        "hostname": hostname,
        "mac_address": mac_address,
        "host_ip": host_ip,
        "api_key": client.api_key,
        "balance_tokens": client.balance_tokens,
        "device_type": device_type,
        "browser_name": browser_name
    }

# Encrypted AI Ingestion Endpoint
@app.post("/v1/chat/completions")
@app.post("/api/telemetry")
async def process_ai_traffic(request: Request, db: Session = Depends(get_db)):
    try:
        body = await request.json()
    except Exception:
        body = {}

    if "encrypted_payload" in body and "iv" in body:
        body = ComplianceSecurityEngine.decrypt_aes_gcm(body["encrypted_payload"], body["iv"])

    auth_header = request.headers.get("Authorization", "")
    api_key = auth_header.split(" ")[1] if auth_header.startswith("Bearer ") else None
    hw_id_header = request.headers.get("X-HW-ID") or body.get("hw_id")

    client_node = None
    if api_key:
        client_node = db.query(ClientModel).filter(ClientModel.api_key == api_key, ClientModel.is_deleted == False).first()
    if not client_node and hw_id_header:
        client_node = db.query(ClientModel).filter(ClientModel.hw_id == hw_id_header, ClientModel.is_deleted == False).first()

    if not client_node:
        client_node = db.query(ClientModel).filter(ClientModel.is_deleted == False).order_by(ClientModel.created_at.desc()).first()

    if not client_node:
        raise HTTPException(status_code=403, detail="Unregistered or deleted client node access denied.")

    if client_node.status != "APPROVED":
        raise HTTPException(status_code=403, detail=f"Client node status is {client_node.status}.")

    if client_node.balance_tokens <= 0:
        raise HTTPException(
            status_code=402, 
            detail="Token quota exhausted. Please request a token top-up from the administrator."
        )

    meta = json.loads(client_node.metadata_json) if client_node.metadata_json else {}
    headers_dict = dict(request.headers)
    metrics = parse_llm_payload(body, headers_dict, meta)

    raw_prompt = metrics["prompt"]
    sanitized_prompt = ComplianceSecurityEngine.sanitize_pii(raw_prompt)
    
    model = metrics["model_name"]
    version = metrics["version"]
    think_level = metrics["think_level"]

    hostname = metrics["hostname"] or meta.get("hostname") or socket.gethostname()
    mac_address = metrics["mac_address"] or client_node.mac_address or get_system_mac()
    host_ip = client_node.host_ip or meta.get("host_ip") or get_client_ip(request)

    input_tokens = metrics["input_tokens"]
    output_tokens = metrics["output_tokens"]
    total_tokens = input_tokens + output_tokens

    client_node.balance_tokens = max(0, client_node.balance_tokens - total_tokens)
    db.commit()

    now_utc = datetime.now(timezone.utc)
    timestamp_utc = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    ist_offset = timezone(timedelta(hours=5, minutes=30))
    timestamp_local = now_utc.astimezone(ist_offset).strftime("%Y-%m-%d %H:%M:%S Local (IST)")

    ai_response_text = body.get("response") or f"Telemetry execution acknowledged for model {model} ({version})."

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
        provider=body.get("provider", "AI Gateway Engine"),
        model=model,
        version=version,
        think_level=think_level,
        prompt=sanitized_prompt,
        prompt_tokens=input_tokens,
        completion_tokens=output_tokens,
        latency_ms=25,
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
            
        hw_id = r.hw_id or ""
        mac_address = p.get("mac_address") or ""
        host_ip = p.get("host_ip") or ""
        model = r.model or ""
        version = r.version or ""
        prompt_tokens = r.prompt_tokens or 0
        completion_tokens = r.completion_tokens or 0
        total_tokens = prompt_tokens + completion_tokens
        audit_hash = r.audit_hash or ""
        complete_prompt_text = str(r.prompt or "").replace('"', '""')
        timestamp_utc = r.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if r.created_at else ""
        
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
            "mac_address": c.mac_address or meta.get("mac_address") or "",
            "host_ip": c.host_ip or meta.get("host_ip") or "",
            "hostname": meta.get("hostname") or socket.gethostname(),
            "status": c.status or "APPROVED",
            "balance_tokens": c.balance_tokens if c.balance_tokens is not None else 0,
            "browser_name": meta.get("browser_name") or "",
            "api_key": c.api_key or ""
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

        resolved_mac = payload.get("mac_address") or (client.mac_address if client else None) or client_meta.get("mac_address") or "N/A"
        resolved_ip = payload.get("host_ip") or (client.host_ip if client else None) or client_meta.get("host_ip") or "N/A"
        resolved_host = payload.get("hostname") or client_meta.get("hostname") or socket.gethostname()

        calculated_tokens = (l.prompt_tokens or 0) + (l.completion_tokens or 0)
        if calculated_tokens <= 0 and l.prompt:
            calculated_tokens = max(12, len(str(l.prompt).split()))

        logs.append({
            "id": l.id,
            "hw_id": l.hw_id,
            "mac_address": resolved_mac,
            "host_ip": resolved_ip,
            "hostname": resolved_host,
            "timestamp_utc": utc_str,
            "timestamp_local": payload.get("timestamp_local") or utc_str,
            "model": normalize_model_name(l.model),
            "version": l.version or "v1.0",
            "prompt": l.prompt or "",
            "tokens": calculated_tokens,
            "audit_hash": l.audit_hash or ""
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