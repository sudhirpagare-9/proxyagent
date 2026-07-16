import os, json, logging
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from supabase import create_client
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

app = FastAPI()
logging.basicConfig(level=logging.INFO)

# 1. Initialize Supabase with the SERVICE_ROLE_KEY to bypass RLS issues
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_ROLE_KEY"])

# 2. Secure Key Loading (Render Secret File)
def get_private_key():
    secret_path = "/etc/secrets/private_key.pem"
    try:
        with open(secret_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    except Exception as e:
        logging.error(f"Critical: Failed to load key from {secret_path}: {e}")
        return None

private_key = get_private_key()

# 3. Endpoints
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
        decrypted_data = private_key.decrypt(
            encrypted_body,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        data = json.loads(decrypted_data)
        
        # Insert into Supabase
        # Ensure 'ai_usage_logs' table exists in your Supabase project
        supabase.table("ai_usage_logs").insert({
            "hw_id": str(data.get("hw_id")),
            "model_name": str(data.get("model_name", "unknown")),
            "input_tokens": int(data.get("input_tokens", 0)),
            "output_tokens": int(data.get("output_tokens", 0))
        }).execute()
        
        return {"status": "ok"}
    except Exception as e:
        logging.error(f"Decryption/Log failure: {e}")
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