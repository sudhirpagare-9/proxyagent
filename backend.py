import os
import json
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from supabase import create_client
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from dotenv import load_dotenv

load_dotenv()
app = FastAPI()
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])

def get_private_key():
    key_path = "/etc/secrets/private_key.pem"
    if not os.path.exists(key_path): key_path = "private_key.pem"
    try:
        with open(key_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    except Exception as e:
        return None

private_key = get_private_key()

@app.post("/log-ai-usage")
async def log_usage(request: Request):
    if not private_key:
        raise HTTPException(status_code=500, detail="Private key missing")
    try:
        raw_body = await request.body()
        # Decrypt
        decrypted_bytes = private_key.decrypt(
            raw_body,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )
        data = json.loads(decrypted_bytes)
        # Remove host field if not in table
        if 'hostname' in data: del data['hostname']
        
        # Insert
        response = supabase.table("ai_usage_logs").insert(data).execute()
        return {"status": "success"}
    except Exception as e:
        print(f"CRITICAL ERROR: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/get-clients")
async def get_clients(): return supabase.table("clients_registry").select("*").execute().data

@app.get("/api/get-logs/{hw_id}")
async def get_logs(hw_id: str):
    return supabase.table("ai_usage_logs").select("*").eq("hw_id", hw_id).execute().data