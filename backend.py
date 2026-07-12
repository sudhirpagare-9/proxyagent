import os
import json
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from supabase import create_client
from pydantic import BaseModel, ValidationError
from typing import Optional
from cryptography.fernet import Fernet

app = FastAPI()

# Configuration
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
fernet = Fernet(ENCRYPTION_KEY.encode())
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Models
class AIUsageLog(BaseModel):
    hw_id: str
    model_name: str
    version: str
    model_type: str
    input_tokens: int
    output_tokens: int
    balance_tokens: Optional[int] = 0

# Security Helper
def decrypt_payload(encrypted_blob: bytes):
    decrypted_data = fernet.decrypt(encrypted_blob)
    return json.loads(decrypted_data)

@app.post("/log-ai-usage")
async def log_ai_usage(request: Request):
    try:
        # Get raw encrypted body
        body = await request.body()
        data_dict = decrypt_payload(body)
        
        # Validate against model
        data = AIUsageLog(**data_dict)
        
        # Insert into database
        supabase.table("ai_usage_logs").insert({
            "hw_id": data.hw_id,
            "model_name": data.model_name,
            "version": data.version,
            "model_type": data.model_type,
            "input_tokens": data.input_tokens,
            "output_tokens": data.output_tokens,
            "balance_tokens": data.balance_tokens
        }).execute()
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Decryption or validation failed")

# Standard Routes
@app.get("/")
async def read_index(): return FileResponse("index.html")

@app.get("/api/get-clients")
async def get_clients():
    try: return supabase.table("clients_registry").select("*").execute().data
    except Exception: return []

@app.get("/api/get-logs/{hw_id}")
async def get_logs(hw_id: str):
    try: return supabase.table("ai_usage_logs").select("*").eq("hw_id", hw_id).order("created_at", desc=True).execute().data
    except Exception: return []

@app.post("/api/approve/{hw_id}")
async def approve_client(hw_id: str):
    try:
        supabase.table("clients_registry").update({"status": "approved"}).eq("hw_id", hw_id).execute()
        return {"status": "success"}
    except Exception: raise HTTPException(status_code=500)