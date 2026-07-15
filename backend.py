import os
import json
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from supabase import create_client
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = FastAPI()

# Initialize Supabase
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])

# --- SECURITY: PRIVATE KEY LOADING ---
def get_private_key():
    # Looks for Render Secret File path
    key_path = "/etc/secrets/private_key.pem"
    
    # Fallback to local file for testing
    if not os.path.exists(key_path):
        key_path = "private_key.pem"
        
    try:
        with open(key_path, "rb") as key_file:
            # Loads raw PEM file
            return serialization.load_pem_private_key(key_file.read(), password=None)
    except Exception as e:
        print(f"CRITICAL: Failed to load key: {e}")
        return None

private_key = get_private_key()

# --- ROUTES ---

# 1. Serve Dashboard
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    try:
        with open("index.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Dashboard file (index.html) not found</h1>", status_code=404)

# 2. Log AI Usage (Encrypted)
@app.post("/log-ai-usage")
async def log_ai_usage(request: Request):
    if not private_key:
        raise HTTPException(status_code=500, detail="Private key not initialized")
    try:
        encrypted_blob = await request.body()
        decrypted_data = private_key.decrypt(
            encrypted_blob,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        data = json.loads(decrypted_data)
        
        # Upsert client info (Update if exists, insert if new)
        supabase.table("clients_registry").upsert({
            "hw_id": data["hw_id"],
            "hostname": data.get("hostname", "Unknown"),
            "status": "online"
        }).execute()
        
        # Insert log
        supabase.table("ai_usage_logs").insert({
            "hw_id": data["hw_id"],
            "model_name": data["model_name"],
            "version_name": data.get("version_name"),
            "thinking_level": data.get("thinking_level"),
            "input_tokens": data["input_tokens"],
            "output_tokens": data["output_tokens"],
            "balance": data.get("balance"),
            "subscription_name": data.get("subscription_name")
        }).execute()
        
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# 3. API: Fetch All Clients
@app.get("/api/get-clients")
async def get_clients():
    return supabase.table("clients_registry").select("*").execute().data

# 4. API: Update Status
@app.post("/api/status/{hw_id}/{status}")
async def set_client_status(hw_id: str, status: str):
    supabase.table("clients_registry").update({"status": status}).eq("hw_id", hw_id).execute()
    return {"status": "success"}

# 5. API: Fetch Logs
@app.get("/api/get-logs/{hw_id}")
async def get_logs(hw_id: str):
    return supabase.table("ai_usage_logs").select("*").eq("hw_id", hw_id).order("created_at", desc=True).execute().data