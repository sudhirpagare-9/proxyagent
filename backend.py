import os, json, logging
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from supabase import create_client
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

app = FastAPI()
logging.basicConfig(level=logging.INFO)

# Initialize Supabase
# NOTE: Ensure SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are set in your Render Env Vars
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_ROLE_KEY"])

def get_private_key():
    """Load key from Render secret file or fallback to Environment Variable."""
    secret_path = "/etc/secrets/private_key.pem"
    if os.path.exists(secret_path):
        try:
            with open(secret_path, "rb") as f:
                return serialization.load_pem_private_key(f.read(), password=None)
        except Exception as e:
            logging.error(f"Failed to load key from {secret_path}: {e}")
    
    # Fallback to env var
    key_data = os.environ.get("PRIVATE_KEY")
    if key_data:
        return serialization.load_pem_private_key(key_data.encode(), password=None)
    return None

private_key = get_private_key()

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
        log_entry = {
            "hw_id": str(data.get("hw_id")),
            "model_name": str(data.get("model_name", "unknown")),
            "input_tokens": int(data.get("input_tokens", 0)),
            "output_tokens": int(data.get("output_tokens", 0))
        }
        supabase.table("ai_usage_logs").insert(log_entry).execute()
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