import os, json, logging
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from supabase import create_client
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

app = FastAPI()
logging.basicConfig(level=logging.INFO)

# Initialize Supabase with Service Role Key for backend administrative access
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_ROLE_KEY"])

# --- Security Helper: PII Masking (GDPR Compliance) ---
def mask_ip(ip: str) -> str:
    parts = ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx" if len(parts) == 4 else "0.0.0.0"

# --- Secure Key Loading ---
def get_private_key():
    secret_path = "/etc/secrets/private_key.pem"
    if os.path.exists(secret_path):
        with open(secret_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    return None

private_key = get_private_key()

# --- Routes ---
@app.get("/", response_class=HTMLResponse)
async def serve_index():
    with open("index.html", "r") as f: return HTMLResponse(f.read())

@app.get("/api/get-data")
async def get_data():
    """Fetches clients and logs for the dashboard."""
    clients = supabase.table("client_devices").select("*").execute().data
    logs = supabase.table("ai_usage_logs").select("*").order("created_at", desc=True).limit(50).execute().data
    return {"clients": clients, "logs": logs}

@app.post("/api/update-status/{hw_id}")
async def update_status(hw_id: str, request: Request):
    """Updates client status to Approved/Denied."""
    body = await request.json()
    new_status = body.get("status")
    supabase.table("client_devices").update({"status": new_status}).eq("hw_id", hw_id).execute()
    return {"status": "success"}

@app.post("/log-ai-usage")
async def log_usage(request: Request):
    if not private_key: return {"status": "error"}
    encrypted_body = await request.body()
    try:
        decrypted_data = private_key.decrypt(
            encrypted_body,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        data = json.loads(decrypted_data)
        log_entry = {
            "hw_id": str(data.get("hw_id")),
            "hostname": str(data.get("hostname")),
            "model_name": str(data.get("model_name")),
            "input_tokens": int(data.get("input_tokens", 0)),
            "output_tokens": int(data.get("output_tokens", 0)),
            "subscription_name": str(data.get("subscription_name"))
        }
        supabase.table("ai_usage_logs").insert(log_entry).execute()
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error"}