import os, json, logging, base64
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from supabase import create_client
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from dotenv import load_dotenv

load_dotenv()
app = FastAPI()

# Supabase Setup
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])

logging.basicConfig(level=logging.INFO)


# Decryption Logic
def get_private_key():
    b64_key = os.environ.get("PRIVATE_KEY")
    return serialization.load_pem_private_key(base64.b64decode(b64_key), password=None)

private_key = get_private_key()

@app.post("/log-ai-usage")
async def log_usage(request: Request):
    # 1. Decrypt incoming payload
    encrypted_body = await request.body()
    try:
        decrypted_data = private_key.decrypt(
            encrypted_body,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        data = json.loads(decrypted_data)
        
        # 2. Strict Validation (Secure by Design)
        # Ensure we only log allowed fields
        log_entry = {
            "hw_id": data.get("hw_id"),
            "model_name": str(data.get("model_name")),
            "version": str(data.get("version")),
            "model_type": str(data.get("model_type")),
            "input_tokens": int(data.get("input_tokens", 0)),
            "output_tokens": int(data.get("output_tokens", 0)),
            "balance_tokens": str(data.get("balance_tokens")),
            "created_at": str(data.get("created_at")),
            "subscription_name": str(data.get("subscription_name"))
        }
        
        # 3. Insert to Supabase
        supabase.table("ai_usage_logs").insert(log_entry).execute()
        return {"status": "ok"}
    except Exception as e:
        logging.error(f"Security Alert: Failed decryption/insertion: {e}")
        return {"status": "error"}

# ... existing endpoints (get_clients, get_logs) remain the same
# Key Management
def get_private_key():
    key_data = os.environ.get("PRIVATE_KEY")
    if key_data:
        return serialization.load_pem_private_key(key_data.encode(), password=None)
    try:
        with open("private_key.pem", "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    except: return None

private_key = get_private_key()

# -- Endpoints --
@app.get("/", response_class=HTMLResponse)
async def serve_index():
    with open("index.html", "r") as f: return HTMLResponse(f.read())


@app.get("/api/clients")
async def get_clients(): 
    return supabase.table("clients_registry").select("*").execute().data

@app.get("/api/logs/{hw_id}")
async def get_logs(hw_id: str):
    return supabase.table("ai_usage_logs").select("*").eq("hw_id", hw_id).order("created_at", desc=True).execute().data

@app.post("/api/status/{hw_id}/{status}")
async def update_status(hw_id: str, status: str):
    return supabase.table("clients_registry").update({"status": status}).eq("hw_id", hw_id).execute()