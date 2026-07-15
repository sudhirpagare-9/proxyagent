import os
import json
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from supabase import create_client
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from dotenv import load_dotenv

# Initialize
load_dotenv()
app = FastAPI()
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])

# RSA Private Key Setup
def get_private_key():
    key_path = "/etc/secrets/private_key.pem"
    if not os.path.exists(key_path): key_path = "private_key.pem"
    try:
        with open(key_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    except Exception as e:
        return None

private_key = get_private_key()

@app.get("/", response_class=HTMLResponse)
async def serve():
    with open("index.html", "r") as f:
        return HTMLResponse(content=f.read())

@app.post("/log-ai-usage")
async def log_usage(request: Request):
    if not private_key:
        raise HTTPException(status_code=500, detail="Private key not loaded")
        
    try:
        raw_body = await request.body()
        
        # 1. Decrypt the payload
        decrypted_bytes = private_key.decrypt(
            raw_body,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        log_entry = json.loads(decrypted_bytes)
        
        # 2. Clean/Sanitize for Supabase Schema
        # Remove 'hostname' as it is not in the 'ai_usage_logs' table
        if 'hostname' in log_entry:
            del log_entry['hostname']
            
        # Add default values for required columns missing from client payload
        log_entry.setdefault("version", "1.0")
        log_entry.setdefault("model_type", "chat")
        log_entry.setdefault("balance_tokens", 0)
        
        # 3. Insert into Supabase
        response = supabase.table("ai_usage_logs").insert(log_entry).execute()
        
        return {"status": "success"}
    except Exception as e:
        # Print the specific error to the Render log console
        print(f"CRITICAL INSERTION ERROR: {str(e)}") 
        raise HTTPException(status_code=400, detail=str(e))

# API Endpoints
@app.get("/api/get-clients")
async def get_clients(): return supabase.table("clients_registry").select("*").execute().data

@app.post("/api/approve/{hw_id}")
async def approve(hw_id: str): return supabase.table("clients_registry").update({"status": "approved"}).eq("hw_id", hw_id).execute()

@app.get("/api/get-logs/{hw_id}")
async def get_logs(hw_id: str):
    res = supabase.table("ai_usage_logs").select("*").eq("hw_id", hw_id).order("created_at", desc=True).execute()
    return res.data