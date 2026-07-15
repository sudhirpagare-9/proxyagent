import os
import json
from fastapi import FastAPI, Request, HTTPException
from supabase import create_client
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from dotenv import load_dotenv

# Initialize
load_dotenv()
app = FastAPI()
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])

def get_private_key():
    # Ensure private_key.pem is in the same directory as this file
    try:
        with open("private_key.pem", "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    except Exception as e:
        print(f"Error loading private key: {e}")
        return None

private_key = get_private_key()

@app.post("/log-ai-usage")
async def log_usage(request: Request):
    if not private_key:
        raise HTTPException(status_code=500, detail="Private key not loaded")
    try:
        raw_body = await request.body()
        
        # Decrypt payload
        decrypted_bytes = private_key.decrypt(
            raw_body,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        log_entry = json.loads(decrypted_bytes)
        
        # Insert into Supabase
        # Ensure your table 'ai_usage_logs' has columns: hw_id, model_name, input_tokens, output_tokens
        supabase.table("ai_usage_logs").insert(log_entry).execute()
        
        return {"status": "success"}
    except Exception as e:
        print(f"CRITICAL ERROR: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/get-clients")
async def get_clients(): 
    return supabase.table("clients_registry").select("*").execute().data

@app.get("/api/get-logs/{hw_id}")
async def get_logs(hw_id: str):
    res = supabase.table("ai_usage_logs").select("*").eq("hw_id", hw_id).order("created_at", desc=True).execute()
    return res.data