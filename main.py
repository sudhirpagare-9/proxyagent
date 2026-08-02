import os
import json
import base64
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = FastAPI(title="AI Traffic Dashboard & Security Monitor", version="4.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = (
    os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or 
    os.environ.get("SUPABASE_KEY") or 
    os.environ.get("SUPABASE_ANON_KEY")
)

RAW_PRIVATE_KEY = os.environ.get("RSA_PRIVATE_KEY", "")
RAW_PUBLIC_KEY = os.environ.get("RSA_PUBLIC_KEY", "")

AES_SECRET_ENV = os.environ.get("AES_PII_SECRET", "soc-gdpr-nist-default-32byte-secret-key!!")
AES_PII_SECRET = AES_SECRET_ENV.encode('utf-8')[:32].ljust(32, b'0')

def safe_str(val, max_len=100) -> str:
    if val is None:
        return ""
    return str(val).strip()[:max_len]

def sanitize_key_str(raw_str: str) -> str:
    if not raw_str:
        return ""
    clean_str = raw_str.strip()
    if not clean_str.startswith("-----BEGIN"):
        try:
            decoded = base64.b64decode(clean_str).decode('utf-8')
            if "-----BEGIN" in decoded:
                return decoded
        except Exception:
            pass
    return clean_str.replace("\\n", "\n")

PUBLIC_KEY_PEM = sanitize_key_str(RAW_PUBLIC_KEY)
PRIVATE_KEY_PEM = sanitize_key_str(RAW_PRIVATE_KEY)

private_key = None
public_key_pem_str = ""

if PRIVATE_KEY_PEM:
    try:
        private_key = serialization.load_pem_private_key(PRIVATE_KEY_PEM.encode('utf-8'), password=None)
        public_key_pem_str = PUBLIC_KEY_PEM
    except Exception as e:
        print(f"[!] Error loading RSA private key: {e}")

if not private_key:
    _generated_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = _generated_priv
    _generated_pub = _generated_priv.public_key()
    public_key_pem_str = _generated_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

supabase = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        print("[*] Connected to Supabase successfully.")
    except Exception as e:
        print(f"[!] Supabase initialization failed: {e}")

def encrypt_pii(plaintext: str) -> str:
    if not plaintext:
        return ""
    try:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(AES_PII_SECRET), modes.CTR(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        return base64.b64encode(iv + ct).decode('utf-8')
    except Exception:
        return plaintext

def decrypt_pii(encrypted_b64: str) -> str:
    if not encrypted_b64:
        return ""
    try:
        raw = base64.b64decode(encrypted_b64)
        if len(raw) <= 16:
            return encrypted_b64
        iv, ct = raw[:16], raw[16:]
        cipher = Cipher(algorithms.AES(AES_PII_SECRET), modes.CTR(iv))
        decryptor = cipher.decryptor()
        return (decryptor.update(ct) + decryptor.finalize()).decode('utf-8')
    except Exception:
        return encrypted_b64

def mask_ip(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.***.***"
    return ip

def mask_mac(mac: str) -> str:
    parts = mac.split(":")
    if len(parts) == 6:
        return f"{parts[0]}:{parts[1]}:{parts[2]}:**:**:**"
    return mac

@app.get("/", response_class=HTMLResponse)
async def read_index():
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Dashboard UI (index.html) is missing from the server root directory.</h1>"

@app.get("/web-agent", response_class=HTMLResponse)
@app.get("/web_agent.html", response_class=HTMLResponse)
async def read_web_agent():
    if os.path.exists("web_agent.html"):
        with open("web_agent.html", "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Mobile Web Agent (web_agent.html) missing.</h1>"

@app.get("/public-key", response_class=PlainTextResponse)
async def get_public_key():
    return public_key_pem_str

@app.get("/client-status")
async def get_client_status(hw_id: str = Query(...)):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database connection required.")
    try:
        res = supabase.table("clients_registry").select("status").eq("hw_id", hw_id).execute()
        if res.data and len(res.data) > 0:
            return {"hw_id": hw_id, "status": res.data[0].get("status", "PENDING")}
        return {"hw_id": hw_id, "status": "PENDING"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/register")
async def register_client(request: Request):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database connection required.")
    try:
        data = await request.json()
        hw_id = safe_str(data.get("hw_id"), 50)
        if not hw_id:
            raise HTTPException(status_code=400, detail="Missing hw_id parameter.")

        client_ip = request.client.host if request.client else data.get("ip_address", "127.0.0.1")

        current_status = "PENDING"
        try:
            existing = supabase.table("clients_registry").select("status").eq("hw_id", hw_id).execute()
            if existing.data and len(existing.data) > 0:
                current_status = safe_str(existing.data[0].get("status", "PENDING"), 50)
        except Exception:
            pass

        client_record = {
            "hw_id": hw_id,
            "hostname": encrypt_pii(safe_str(data.get("hostname"), 60)),
            "mac_address": encrypt_pii(safe_str(data.get("mac_address"), 40)),
            "ip_address": encrypt_pii(safe_str(client_ip, 40)),
            "last_ip": encrypt_pii(safe_str(client_ip, 40)),
            "status": current_status,
            "client_name": safe_str(data.get("client_name"), 60),
            "model_name": safe_str(data.get("model_name"), 60),
            "model_version": safe_str(data.get("model_version"), 30),
            "thinklevl": safe_str(data.get("think_level"), 30),
            "interface_browser": safe_str(data.get("interface_browser"), 100),
            "input_tokens": int(data.get("input_tokens", 0)),
            "output_tokens": int(data.get("output_tokens", 0)),
            "balance_tokens": int(data.get("balance_tokens", 12500)),
            "subscription_status": safe_str(data.get("subscription_status", "PRO"), 20),
            "country": safe_str(data.get("country"), 30),
            "geo_location": encrypt_pii(safe_str(data.get("geo_location"), 60))
        }

        supabase.table("clients_registry").upsert(client_record, on_conflict="hw_id").execute()
        return {"status": "success", "client_status": current_status}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/proxy/v1/messages")
@app.post("/api/proxy/v1/chat/completions")
async def proxy_ai_message(request: Request):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database connection required.")
    
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body.")

    hw_id = request.headers.get("X-HW-ID") or body.get("hw_id")
    if not hw_id:
        raise HTTPException(status_code=400, detail="Missing X-HW-ID header.")

    client_res = supabase.table("clients_registry").select("status").eq("hw_id", hw_id).execute()
    if not client_res.data:
        raise HTTPException(status_code=404, detail="Unregistered client.")
    if client_res.data[0].get("status") != "APPROVED":
        raise HTTPException(status_code=402, detail="Client pending or denied approval.")

    prompt_str = json.dumps(body)
    input_tokens = max(10, len(prompt_str) // 4)
    output_tokens = max(25, input_tokens * 2)
    model_used = body.get("model", "Live-Detected-Model")

    try:
        supabase.table("ai_usage_logs").insert({
            "hw_id": hw_id,
            "model_name": model_used,
            "version": "live-v1",
            "model_type": "Live Proxy API",
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "balance_tokens": 12500,
            "subscription_status": "PRO",
            "think_level": "Extended"
        }).execute()
    except Exception as e:
        print(f"[!] Failed to log proxy traffic: {e}")

    return {
        "id": "msg_proxy_live_01",
        "type": "message",
        "role": "assistant",
        "model": model_used,
        "content": [{"type": "text", "text": f"Live proxy telemetry recorded for model: {model_used}."}],
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens}
    }

@app.post("/log-traffic")
async def log_traffic(request: Request):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database connection required.")
    try:
        data = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")

    encrypted_payload_b64 = data.get("encrypted_payload")
    hw_id = safe_str(data.get("hw_id"), 50)

    if not encrypted_payload_b64 or not hw_id:
        raise HTTPException(status_code=400, detail="Missing parameters.")

    try:
        client_res = supabase.table("clients_registry").select("status").eq("hw_id", hw_id).execute()
        if not client_res.data:
            raise HTTPException(status_code=404, detail="Client record unregistered.")
        status = client_res.data[0].get("status")
        if status == "PENDING":
            raise HTTPException(status_code=402, detail="Client pending approval. Traffic blocked.")
        elif status == "DENIED" or status == "DELETED":
            raise HTTPException(status_code=403, detail="Client access DENIED.")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    try:
        encrypted_data = base64.b64decode(encrypted_payload_b64)
        decrypted_bytes = private_key.decrypt(
            encrypted_data,
            padding.PKCS1v15()
        )
        payload = json.loads(decrypted_bytes.decode('utf-8'))
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Decryption Failure: {str(e)}")

    model_name = safe_str(payload.get("m", "Dynamic Model"), 50)
    version = safe_str(payload.get("v", "v1.0"), 50)
    model_type = safe_str(payload.get("t", "Live Agent"), 50)
    think_level = safe_str(payload.get("l", "Standard"), 50)
    in_tokens = int(payload.get("i", 0))
    out_tokens = int(payload.get("o", 0))
    bal_tokens = int(payload.get("b", 12500))
    sub_status = safe_str(payload.get("s", "PRO"), 20)

    try:
        supabase.table("ai_usage_logs").insert({
            "hw_id": hw_id,
            "model_name": model_name,
            "version": version,
            "model_type": model_type,
            "input_tokens": in_tokens,
            "output_tokens": out_tokens,
            "balance_tokens": bal_tokens,
            "subscription_status": sub_status,
            "think_level": think_level
        }).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
            
    return {"status": "success", "model_recorded": model_name}

@app.get("/api/dashboard-data")
async def get_dashboard_data(
    hw_id: Optional[str] = Query(None),
    filter_mode: Optional[str] = Query("top100")
):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database connection required.")
        
    try:
        raw_clients = supabase.table("clients_registry").select("*").neq("status", "DELETED").execute().data or []
        
        raw_logs = []
        if hw_id:
            client_check = supabase.table("clients_registry").select("status").eq("hw_id", hw_id).execute()
            if client_check.data and client_check.data[0].get("status") == "APPROVED":
                logs_query = supabase.table("ai_usage_logs").select("*").eq("hw_id", hw_id).order("created_at", desc=True).limit(100)
                raw_logs = logs_query.execute().data or []

        processed_clients = []
        for c in raw_clients:
            dec_ip = decrypt_pii(c.get("ip_address", ""))
            dec_mac = decrypt_pii(c.get("mac_address", ""))
            dec_geo = decrypt_pii(c.get("geo_location", ""))
            dec_host = decrypt_pii(c.get("hostname", ""))
            
            processed_clients.append({
                "hw_id": c.get("hw_id"),
                "hostname": dec_host or "Web Client",
                "mac_address": mask_mac(dec_mac) if dec_mac else "Dynamic",
                "ip_address": mask_ip(dec_ip) if dec_ip else "Live IP",
                "status": c.get("status", "PENDING"),
                "subscription_status": c.get("subscription_status", "PRO"),
                "model_name": c.get("model_name") or "Dynamic Model",
                "think_level": c.get("thinklevl") or "Standard",
                "country": c.get("country") or "IND",
                "geo_location": dec_geo or "Live Region",
                "encrypted_pii": True
            })

        return {
            "clients": processed_clients, 
            "logs": raw_logs, 
            "db_status": "connected",
            "crypto_status": "Active (RSA-2048 PKCS1v15 / AES-CTR 256)"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/client-action")
async def client_action(request: Request):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database connection required.")
    
    body = await request.json()
    hw_id = safe_str(body.get("hw_id"), 50)
    action = safe_str(body.get("action"), 20)

    if not hw_id or not action:
        raise HTTPException(status_code=400, detail="Invalid parameters.")

    if action == "approve":
        supabase.table("clients_registry").update({"status": "APPROVED"}).eq("hw_id", hw_id).execute()
    elif action == "deny":
        supabase.table("clients_registry").update({"status": "DENIED"}).eq("hw_id", hw_id).execute()
    elif action == "delete":
        supabase.table("clients_registry").update({"status": "DELETED"}).eq("hw_id", hw_id).execute()
        
    return {"status": "success", "action": action, "hw_id": hw_id}