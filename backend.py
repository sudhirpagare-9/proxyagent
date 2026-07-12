import os
import json
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from supabase import create_client
from pydantic import BaseModel
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()
app = FastAPI()

# Init Supabase & Encryption
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])
fernet = Fernet(os.environ["ENCRYPTION_KEY"].encode())

class AIUsageLog(BaseModel):
    hw_id: str
    hostname: str
    model_name: str
    input_tokens: int
    output_tokens: int

@app.get("/")
async def read_index():
    return FileResponse("index.html")

@app.post("/log-ai-usage")
async def log_ai_usage(request: Request):
    try:
        # Decrypt and Parse
        data = json.loads(fernet.decrypt(await request.body()))
        log = AIUsageLog(**data)
        
        # Upsert Registry
        supabase.table("clients_registry").upsert(
            {"hw_id": log.hw_id, "hostname": log.hostname, "status": "pending"},
            on_conflict="hw_id"
        ).execute()
        
        # Log Usage
        supabase.table("ai_usage_logs").insert(log.dict()).execute()
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/get-clients")
async def get_clients():
    return supabase.table("clients_registry").select("*").execute().data

@app.get("/api/get-logs/{hw_id}")
async def get_logs(hw_id: str):
    return supabase.table("ai_usage_logs").select("*").eq("hw_id", hw_id).execute().data

@app.post("/api/approve/{hw_id}")
async def approve_client(hw_id: str):
    supabase.table("clients_registry").update({"status": "approved"}).eq("hw_id", hw_id).execute()
    return {"status": "approved"}