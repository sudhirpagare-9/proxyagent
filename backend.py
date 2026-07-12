import os
import json
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from supabase import create_client
from pydantic import BaseModel
from typing import Optional
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()
app = FastAPI()

# Configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
fernet = Fernet(ENCRYPTION_KEY.encode())
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

class AIUsageLog(BaseModel):
    hw_id: str
    hostname: str
    mac_address: str
    ip_address: str
    country: str
    model_name: str
    input_tokens: int
    output_tokens: int

@app.post("/log-ai-usage")
async def log_ai_usage(request: Request):
    try:
        body = await request.body()
        data = json.loads(fernet.decrypt(body))
        
        # 1. Upsert Client Registry (Register/Update client info)
        supabase.table("clients_registry").upsert({
            "hw_id": data['hw_id'],
            "hostname": data['hostname'],
            "mac_address": data['mac_address'],
            "ip_address": data['ip_address'],
            "country": data['country'],
            "status": "PENDING" # Default for new clients
        }, on_conflict="hw_id").execute()
        
        # 2. Insert into usage logs
        supabase.table("ai_usage_logs").insert({
            "hw_id": data['hw_id'],
            "model_name": data['model_name'],
            "input_tokens": data['input_tokens'],
            "output_tokens": data['output_tokens']
        }).execute()
        
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/update-status/{hw_id}/{status}")
async def update_status(hw_id: str, status: str):
    supabase.table("clients_registry").update({"status": status}).eq("hw_id", hw_id).execute()
    return {"status": "success"}

@app.get("/api/get-clients")
async def get_clients():
    return supabase.table("clients_registry").select("*").execute().data

@app.get("/api/get-logs/{hw_id}")
async def get_logs(hw_id: str):
    return supabase.table("ai_usage_logs").select("*").eq("hw_id", hw_id).execute().data
    
# Add this to your backend.py
@app.post("/api/status/{hw_id}/{status}")
async def set_client_status(hw_id: str, status: str):
    try:
        # Validate status to prevent malicious input
        if status not in ["approved", "denied"]:
            raise HTTPException(status_code=400, detail="Invalid status")
            
        supabase.table("clients_registry").update({"status": status}).eq("hw_id", hw_id).execute()
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
        
@app.get("/")
async def read_index(): return FileResponse("index.html")