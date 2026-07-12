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

# Configuration
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")

fernet = Fernet(ENCRYPTION_KEY.encode())
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

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
        body = await request.body()
        data = json.loads(fernet.decrypt(body))
        log = AIUsageLog(**data)
        
        # Upsert client
        supabase.table("clients_registry").upsert({
            "hw_id": log.hw_id,
            "hostname": log.hostname,
            "status": "pending"
        }, on_conflict="hw_id").execute()
        
        # Insert log
        supabase.table("ai_usage_logs").insert({
            "hw_id": log.hw_id,
            "model_name": log.model_name,
            "input_tokens": log.input_tokens,
            "output_tokens": log.output_tokens
        }).execute()
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/get-clients")
async def get_clients():
    return supabase.table("clients_registry").select("*").execute().data

@app.get("/api/get-logs/{hw_id}")
async def get_logs(hw_id: str):
    return supabase.table("ai_usage_logs").select("*").eq("hw_id", hw_id).order("created_at", desc=True).execute().data

@app.post("/api/status/{hw_id}/{status}")
async def set_client_status(hw_id: str, status: str):
    supabase.table("clients_registry").update({"status": status}).eq("hw_id", hw_id).execute()
    return {"status": "success"}