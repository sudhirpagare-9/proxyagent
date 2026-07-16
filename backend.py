import os, json, logging
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from supabase import create_client
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from dotenv import load_dotenv

# 1. Initialization
load_dotenv()
app = FastAPI()
logging.basicConfig(level=logging.INFO)

# 2. Database Setup
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])

# 3. Secure Key Management
def get_private_key():
    """Load key from Env Var or Render Secret File path."""
    # Priority 1: Env Var (for local dev)
    key_data = os.environ.get("PRIVATE_KEY")
    if key_data:
        return serialization.load_pem_private_key(key_data.encode(), password=None)
    
    # Priority 2: Render Secret Mount
    secret_path = "/etc/secrets/private_key.pem"
    if os.path.exists(secret_path):
        try:
            with open(secret_path, "rb") as f:
                return serialization.load_pem_private_key(f.read(), password=None)
        except Exception as e:
            logging.error(f"Failed to load key from {secret_path}: {e}")
    return None

private_key = get_private_key()

# 4. API Endpoints
@app.get("/", response_class=HTMLResponse)
async def serve_index():
    with open("index.html", "r") as f: 
        return HTMLResponse(f.read())

@app.post("/log-ai-usage")
async def log_usage(request: Request):
    if not private_key:
        return {"status": "error", "message": "Key not loaded"}

    encrypted_body = await request.body()
    try:
        # Decrypt payload
        decrypted_data = private_key.decrypt(
            encrypted_body,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), 
                algorithm=hashes.SHA256(), 
                label=None
            )
        )
        data = json.loads(decrypted_data)
        
        # Schema Validation: Prevent unauthorized fields from hitting DB
        log_entry = {
            "hw_id": str(data.get("hw_id")),
            "model_name": str(data.get("model_name", "unknown")),
            "input_tokens": int(data.get("input_tokens", 0)),
            "output_tokens": int(data.get("output_tokens", 0))
        }
        
        supabase.table("ai_usage_logs").insert(log_entry).execute()
        return {"status": "ok"}
    except Exception as e:
        logging.error(f"Security Alert: Decryption/Insertion failed: {e}")
        return {"status": "error"}

@app.get("/api/clients")
async def get_clients(): 
    return supabase.table("clients_registry").select("*").execute().data

@app.get("/api/logs/{hw_id}")
async def get_logs(hw_id: str):
    return supabase.table("ai_usage_logs").select("*").eq("hw_id", hw_id).order("created_at", desc=True).execute().data

@app.post("/api/status/{hw_id}/{status}")
async def update_status(hw_id: str, status: str):
    return supabase.table("clients_registry").update({"status": status}).eq("hw_id", hw_id).execute()