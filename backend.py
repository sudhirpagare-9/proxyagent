import os
import json
from fastapi import FastAPI, Request, HTTPException
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
        raise HTTPException(status_code=500, detail="Private key not loaded")
    try:
        raw_body = await request.body()
        
        # 1. Decrypt
        decrypted_bytes = private_key.decrypt(
            raw_body,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        data = json.loads(decrypted_bytes)
        
        # 2. Insert into Supabase
        supabase.table("ai_usage_logs").insert(data).execute()
        return {"status": "success"}
    except Exception as e:
        print(f"CRITICAL ERROR: {str(e)}") # This shows up in your Render Logs
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/get-logs/{hw_id}")
async def get_logs(hw_id: str):
    return supabase.table("ai_usage_logs").select("*").eq("hw_id", hw_id).order("created_at", desc=True).execute().data