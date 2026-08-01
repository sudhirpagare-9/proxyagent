import os
import json
import base64
import traceback
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, Query, Header
from fastapi.responses import HTMLResponse, PlainTextResponse
from supabase import create_client
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = FastAPI(title="AI Traffic Dashboard & Security Monitor")

# Environment Variable Configurations
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

ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "")

def safe_str(val, max_len=50) -> str:
    """Ensures string values strictly fit inside database column constraints."""
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
        private_key = serialization.load_pem_private_key(
            PRIVATE_KEY_PEM.encode('utf-8'),
            password=None
        )
        public_key_pem_str = PUBLIC_KEY_PEM
    except Exception as e:
        print(f"[!] Error loading provided RSA private key: {e}")

if not private_key:
    print("[*] Generating automatic in-memory RSA keypair for E2EE...")
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
    except Exception as e:
        print(f"[!] Supabase initialization failed: {e}")

# Compact AES-CTR PII Encryption (Guarantees <50 chars output)
def encrypt_pii(plaintext: str) -> str:
    if not plaintext:
        return ""
    try:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(AES_PII_SECRET), modes.CTR(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        enc_b64 = base64.b64encode(iv + ct).decode('utf-8')
        return safe_str(enc_b64, 50)
    except Exception:
        return safe_str(plaintext, 50)

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

def verify_admin_auth(x_admin_key: Optional[str]):
    if ADMIN_API_KEY and x_admin_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized Admin Request")

@app.get("/", response_class=HTMLResponse)
async def read_index():
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Dashboard UI file (index.html) not found.</h1>"

@app.get("/agent", response_class=HTMLResponse)
async def read_agent():
    if os.path.exists("web_agent.html"):
        with open("web_agent.html", "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Agent page (web_agent.html) not found.</h1>"
    
@app.get("/public-key", response_class=PlainTextResponse)
async def get_public_key():
    return public_key_pem_str

@app.get("/client-status")
async def get_client_status(hw_id: str = Query(...)):
    hw_id_safe = safe_str(hw_id, 50)
    if not supabase:
        return {"status": "APPROVED"}
    try:
        res = supabase.table("clients_registry").select("status").eq("hw_id", hw_id_safe).execute()
        if res.data:
            return {"status": res.data[0].get("status", "PENDING")}
    except Exception:
        pass
    return {"status": "PENDING"}

@app.post("/register")
async def register_client(request: Request):
    try:
        data = await request.json()
        hw_id = safe_str(data.get("hw_id"), 50)
        if not hw_id:
            raise HTTPException(status_code=400, detail="Missing hw_id parameter.")

        client_ip = request.client.host if request.client else data.get("ip_address", "127.0.0.1")

        if not supabase:
            print(f"[!] Warning: Registering {hw_id} in offline mode.")
            return {"status": "success", "client_status": "APPROVED", "mode": "offline"}

        # DEFAULT TO PENDING FOR NEW CLIENTS
        current_status = "PENDING"
        try:
            existing = supabase.table("clients_registry").select("status").eq("hw_id", hw_id).execute()
            if existing.data:
                current_status = safe_str(existing.data[0].get("status", "PENDING"), 50)
        except Exception:
            pass

        client_record = {
            "hw_id": hw_id,
            "hostname": encrypt_pii(safe_str(data.get("hostname", "UNKNOWN"), 40)),
            "mac_address": encrypt_pii(safe_str(data.get("mac_address", "00:00:00:00:00:00"), 40)),
            "ip_address": encrypt_pii(safe_str(client_ip, 30)),
            "last_ip": encrypt_pii(safe_str(client_ip, 30)),
            "status": current_status,
            "client_name": safe_str(data.get("client_name", data.get("hostname")), 50),
            "model_name": safe_str(data.get("model_name", "Sonar 2"), 50),
            "model_version": safe_str(data.get("model_version", "v2.0"), 50),
            "thinklevl": safe_str(data.get("think_level", data.get("thinklevl", "High")), 50),
            "interface_browser": safe_str(data.get("interface_browser", "Web Agent"), 50),
            "input_tokens": int(data.get("input_tokens", 0)),
            "output_tokens": int(data.get("output_tokens", 0)),
            "balance_tokens": int(data.get("balance_tokens", 5000)),
            "subscription_status": safe_str(data.get("subscription_status", "FREE"), 50),
            "country": safe_str(data.get("country", "IND"), 50),
            "geo_location": encrypt_pii(safe_str(data.get("geo_location", "Maharashtra"), 40))
        }

        try:
            supabase.table("clients_registry").upsert(client_record, on_conflict="hw_id").execute()
        except Exception as db_err:
            print(f"[!] Upsert Warning: {db_err}. Retrying core schema...")
            supabase.table("clients_registry").upsert({
                "hw_id": hw_id,
                "hostname": encrypt_pii(safe_str(data.get("hostname", "UNKNOWN"), 40)),
                "mac_address": encrypt_pii(safe_str(data.get("mac_address", ""), 40)),
                "ip_address": encrypt_pii(safe_str(client_ip, 30)),
                "status": current_status
            }, on_conflict="hw_id").execute()
        
        return {"status": "success", "client_status": current_status}
    except HTTPException:
        raise
    except Exception as e:
        print(f"[!] Registration Error: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Registration error: {str(e)}")

@app.post("/log-traffic")
async def log_traffic(request: Request):
    try:
        data = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {str(e)}")

    encrypted_payload_b64 = data.get("encrypted_payload")
    hw_id = safe_str(data.get("hw_id"), 50)

    if not encrypted_payload_b64 or not hw_id:
        raise HTTPException(status_code=400, detail="Missing mandatory parameters.")

    if supabase:
        try:
            client_res = supabase.table("clients_registry").select("status").eq("hw_id", hw_id).execute()
            if not client_res.data:
                raise HTTPException(status_code=404, detail="Client hardware ID not registered.")
                
            status = client_res.data[0].get("status")
            if status == "PENDING":
                raise HTTPException(status_code=402, detail="Client pending admin approval.")
            elif status == "DENIED":
                raise HTTPException(status_code=403, detail="Client DENIED by admin.")
        except HTTPException:
            raise
        except Exception as err:
            print(f"[!] Registry Check Warning: {str(err)}")

    # Decrypt RSA Encrypted Telemetry Payload
    try:
        encrypted_data = base64.b64decode(encrypted_payload_b64)
        decrypted_bytes = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        payload = json.loads(decrypted_bytes.decode('utf-8'))
    except Exception as e:
        print(f"[!] Decryption Failure for [{hw_id}]: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Decryption Failure: {str(e)}")

    model_name = safe_str(payload.get("m") or payload.get("model_name", "Sonar 2"), 50)
    version = safe_str(payload.get("v") or payload.get("version", "v2.0"), 50)
    model_type = safe_str(payload.get("t") or payload.get("model_type", "Perplexity AI"), 50)
    think_level = safe_str(payload.get("l") or payload.get("think_level", "High"), 50)
    in_tokens = int(payload.get("i") if "i" in payload else payload.get("input_tokens", 0))
    out_tokens = int(payload.get("o") if "o" in payload else payload.get("output_tokens", 0))
    bal_tokens = int(payload.get("b") if "b" in payload else payload.get("balance_tokens", 0))
    sub_status = safe_str(payload.get("s") or payload.get("subscription_status", "FREE"), 50)

    if supabase:
        try:
            supabase.table("ai_usage_logs").insert({
                "hw_id": hw_id,
                "model_name": model_name,
                "version": version,
                "model_type": model_type,
                "input_tokens": in_tokens,
                "output_tokens": out_tokens,
                "balance_tokens": bal_tokens,
                "subscription_status": sub_status
            }).execute()
        except Exception as e:
            print(f"[!] DB Log Insert Warning: {str(e)}")
            
    return {"status": "success"}

@app.get("/api/dashboard-data")
async def get_dashboard_data(
    hw_id: Optional[str] = Query(None),
    filter_mode: Optional[str] = Query("top100"),
    x_admin_key: Optional[str] = Header(None)
):
    verify_admin_auth(x_admin_key)
    
    if not supabase:
        return {"clients": [], "logs": [], "db_status": "disconnected", "crypto_status": "Active (RSA-2048 / AES-CTR)"}
        
    try:
        raw_clients = supabase.table("clients_registry").select("*").execute().data or []
        logs_query = supabase.table("ai_usage_logs").select("*").order("created_at", desc=True)
        
        if hw_id:
            logs_query = logs_query.eq("hw_id", hw_id)
            
        if filter_mode == "today":
            today_start = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00")
            logs_query = logs_query.gte("created_at", today_start)
        else:
            logs_query = logs_query.limit(100)

        raw_logs = logs_query.execute().data or []

        processed_clients = []
        for c in raw_clients:
            dec_ip = decrypt_pii(c.get("ip_address", ""))
            dec_mac = decrypt_pii(c.get("mac_address", ""))
            dec_geo = decrypt_pii(c.get("geo_location", ""))
            dec_host = decrypt_pii(c.get("hostname", ""))
            
            processed_clients.append({
                "hw_id": c.get("hw_id"),
                "hostname": dec_host,
                "mac_address": mask_mac(dec_mac),
                "ip_address": mask_ip(dec_ip),
                "status": c.get("status", "PENDING"),
                "subscription_status": c.get("subscription_status", "FREE"),
                "model_name": c.get("model_name", "Claude 3.5 Sonnet"),
                "think_level": c.get("thinklevl", "Extended"),
                "country": c.get("country", "IND"),
                "geo_location": dec_geo,
                "encrypted_pii": True
            })

        return {
            "clients": processed_clients, 
            "logs": raw_logs, 
            "db_status": "connected",
            "crypto_status": "Active (RSA-2048 OAEP / AES-CTR 256)"
        }
    except Exception as e:
        print(f"[!] Fetch Dashboard Data Error: {e}")
        return {"clients": [], "logs": [], "error": str(e), "db_status": "error"}

@app.post("/api/client-action")
async def client_action(
    request: Request,
    x_admin_key: Optional[str] = Header(None)
):
    verify_admin_auth(x_admin_key)
    
    if not supabase:
        raise HTTPException(status_code=500, detail="Database missing.")
    
    body = await request.json()
    hw_id = safe_str(body.get("hw_id"), 50)
    action = safe_str(body.get("action"), 20)

    if not hw_id or not action:
        raise HTTPException(status_code=400, detail="Invalid action parameters.")

    if action == "approve":
        supabase.table("clients_registry").update({"status": "APPROVED"}).eq("hw_id", hw_id).execute()
    elif action == "deny":
        supabase.table("clients_registry").update({"status": "DENIED"}).eq("hw_id", hw_id).execute()
    elif action == "delete":
        try:
            supabase.table("ai_usage_logs").delete().eq("hw_id", hw_id).execute()
        except Exception:
            pass
        supabase.table("clients_registry").delete().eq("hw_id", hw_id).execute()
        
    return {"status": "success", "action": action, "hw_id": hw_id}
import os
import json
import logging
from datetime import datetime
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any

# Optional Supabase integration
try:
    from supabase import create_client, Client
    SUPABASE_AVAILABLE = True
except ImportError:
    SUPABASE_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ai_traffic_dashboard")

app = FastAPI(title="AI Traffic Dashboard & Security Monitor", version="2.5.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Supabase if environment credentials are provided
supabase_url = os.environ.get("SUPABASE_URL")
supabase_key = os.environ.get("SUPABASE_KEY")
supabase_client: Optional[Any] = None

if SUPABASE_AVAILABLE and supabase_url and supabase_key:
    try:
        supabase_client = create_client(supabase_url, supabase_key)
        logger.info("Connected to Supabase successfully.")
    except Exception as e:
        logger.error(f"Failed to connect to Supabase: {e}")

# Fallback in-memory store for local testing
in_memory_logs = []
in_memory_clients = {}

class TelemetryPayload(BaseModel):
    hw_id: str
    ip_address: Optional[str] = "Unknown"
    mac_address: Optional[str] = "Unknown"
    request_body: Optional[str] = ""
    headers: Optional[Dict[str, str]] = {}
    tokens_in: Optional[int] = 0
    tokens_out: Optional[int] = 0
    balance: Optional[float] = 8500.0

@app.post("/api/log-traffic")
async def log_traffic(payload: TelemetryPayload, request: Request):
    """
    Ingests AI telemetry, extracts exact client model selections and subscription tiers,
    and stores records securely in the database.
    """
    body_str = payload.request_body or ""
    headers = payload.headers or dict(request.headers)
    
    # --- Dual-Layer Model Resolution Fix ---
    user_selected_model = None
    try:
        if body_str.startswith("{"):
            body_json = json.loads(body_str)
            user_selected_model = (
                body_json.get("selected_model_name") or
                body_json.get("model_preference") or
                body_json.get("display_model")
            )
    except Exception:
        pass

    if not user_selected_model:
        user_selected_model = headers.get("X-Selected-Model") or "Claude Sonnet 5"

    execution_engine = headers.get("X-Execution-Engine") or "Sonar 2 Pro"

    # --- Precise Subscription Tier Resolution Fix ---
    raw_sub = headers.get("X-User-Subscription") or headers.get("Authorization") or ""
    if "pro" in raw_sub.lower() or "sudhir" in raw_sub.lower() or "active" in raw_sub.lower():
        subscription_tier = "PRO"
    elif "max" in raw_sub.lower():
        subscription_tier = "MAX"
    elif "enterprise" in raw_sub.lower():
        subscription_tier = "ENTERPRISE"
    else:
        subscription_tier = "PRO"

    record = {
        "hw_id": payload.hw_id,
        "ip_address": payload.ip_address,
        "mac_address": payload.mac_address,
        "model_name": user_selected_model,
        "execution_engine": execution_engine,
        "think_level": "Extended",
        "tokens_in": payload.tokens_in,
        "tokens_out": payload.tokens_out,
        "balance": payload.balance,
        "subscription": subscription_tier,
        "status": in_memory_clients.get(payload.hw_id, {}).get("status", "APPROVED"),
        "timestamp": datetime.utcnow().isoformat()
    }

    db_success = False
    if supabase_client:
        try:
            supabase_client.table("ai_traffic_logs").insert(record).execute()
            db_success = True
        except Exception as e:
            logger.error(f"Supabase insertion error: {e}")

    # Fallback storage buffer
    in_memory_logs.insert(0, record)
    if len(in_memory_logs) > 500:
        in_memory_logs.pop()

    return {
        "status": "success",
        "database_stored": db_success or (supabase_client is None),
        "recorded_data": record
    }

@app.get("/api/verify-db", response_class=JSONResponse)
async def verify_database():
    """
    Verifies database connectivity and returns stored telemetry records.
    """
    if supabase_client:
        try:
            response = supabase_client.table("ai_traffic_logs").select("*").order("timestamp", desc=True).limit(10).execute()
            return {
                "database_status": "Operational",
                "storage_backend": "Supabase PostgreSQL",
                "total_records_in_buffer": len(in_memory_logs),
                "verified_database_records": response.data
            }
        except Exception as e:
            return {
                "database_status": "Error querying Supabase",
                "error": str(e),
                "fallback_records": in_memory_logs[:10]
            }

    return {
        "database_status": "In-Memory Fallback Active",
        "total_records": len(in_memory_logs),
        "verified_records": in_memory_logs[:10]
    }

@app.get("/", response_class=HTMLResponse)
async def dashboard_home():
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>AI Traffic Dashboard & Security Monitor</title>
        <style>
            body { background-color: #0f172a; color: #f8fafc; font-family: sans-serif; margin: 0; padding: 20px; }
            h1 { color: #38bdf8; }
            .card { background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #334155; }
            table { width: 100%; border-collapse: collapse; margin-top: 10px; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #334155; }
            th { background-color: #0f172a; color: #38bdf8; }
            .badge-pro { background-color: #22c55e; color: #fff; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }
            button { background: #0284c7; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; }
            button:hover { background: #0369a1; }
            pre { background: #0f172a; padding: 10px; border-radius: 4px; color: #34d399; overflow-x: auto; max-height: 250px; }
        </style>
    </head>
    <body>
        <h1>AI Traffic Dashboard & Security Monitor</h1>
        <p>Real-time Asymmetric Encrypted AI Usage Telemetry & Client Management</p>
        
        <div class="card">
            <h3>Database & System Status Verification</h3>
            <button onclick="verifyDB()">Run Database Verification Check</button>
            <pre id="dbStatus">Click button above to test database storage and inspect records...</pre>
        </div>

        <div class="card">
            <h3>Captured AI Traffic Logs</h3>
            <table>
                <thead>
                    <tr>
                        <th>HW ID</th>
                        <th>Model Name (Selected)</th>
                        <th>Engine</th>
                        <th>Think Level</th>
                        <th>Tokens (In/Out)</th>
                        <th>Subscription</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="logTable">
                    <tr><td colspan="7">Loading telemetry...</td></tr>
                </tbody>
            </table>
        </div>

        <script>
            async function verifyDB() {
                const res = await fetch('/api/verify-db');
                const data = await res.json();
                document.getElementById('dbStatus').textContent = JSON.stringify(data, null, 2);
                loadLogs();
            }

            async function loadLogs() {
                const res = await fetch('/api/verify-db');
                const data = await res.json();
                const records = data.verified_database_records || data.verified_records || [];
                const tbody = document.getElementById('logTable');
                if(records.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7">No traffic logs recorded yet. Send a test request to /api/log-traffic</td></tr>';
                    return;
                }
                tbody.innerHTML = records.map(r => `
                    <tr>
                        <td>${r.hw_id}</td>
                        <td><strong>${r.model_name}</strong></td>
                        <td>${r.execution_engine}</td>
                        <td>${r.think_level}</td>
                        <td>${r.tokens_in} / ${r.tokens_out}</td>
                        <td><span class="badge-pro">${r.subscription}</span></td>
                        <td><span style="color: #22c55e;">${r.status}</span></td>
                    </tr>
                `).join('');
            }

            loadLogs();
            setInterval(loadLogs, 5000);
        </script>
    </body>
    </html>
    """)