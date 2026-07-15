import os
import json
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from supabase import create_client
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from dotenv import load_dotenv

# 1. Initialization
load_dotenv()
app = FastAPI()

# Ensure Supabase variables are set
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# 2. RSA Private Key Loading (Render Secret File)
def get_private_key():
    # Render mounts Secret Files here automatically
    key_path = "/etc/secrets/private_key.pem"
    if not os.path.exists(key_path):
        key_path = "private_key.pem" # Local dev fallback
    
    try:
        with open(key_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    except Exception as e:
        print(f"CRITICAL: Could not load PEM key: {e}")
        return None

private_key = get_private_key()

# 3. Routes

# Serve the Dashboard UI
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    with open("index.html", "r") as f:
        return HTMLResponse(content=f.read())

# Receive Encrypted AI Usage Data
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
        
        # Upsert Client Registry (Updates host/ip/status)
        supabase.table("clients_registry").upsert({
            "hw_id": data["hw_id"],
            "hostname": data.get("hostname", "Unknown"),
            "ip_address": data.get("ip_address"),
            "country": data.get("country", "Unknown"),
            "status": "pending" # Default new clients to pending
        }).execute()
        
        # Insert Usage Log
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

# API: Get all clients for Sidebar
@app.get("/api/get-clients")
async def get_clients():
    return supabase.table("clients_registry").select("*").execute().data

# API: Approve Client
@app.post("/api/approve-client/{hw_id}")
async def approve_client(hw_id: str):
    supabase.table("clients_registry").update({"status": "approved"}).eq("hw_id", hw_id).execute()
    return {"status": "success"}

# API: Get logs for a specific client
@app.get("/api/get-logs/{hw_id}")
async def get_logs(hw_id: str):
    return supabase.table("ai_usage_logs").select("*").eq("hw_id", hw_id).order("created_at", desc=True).execute().data