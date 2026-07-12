import os
import json
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from supabase import create_client
from pydantic import BaseModel
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Initialize Environment
load_dotenv()
app = FastAPI()

# Configuration & Clients
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")

if not ENCRYPTION_KEY or not SUPABASE_URL or not SUPABASE_KEY:
    raise EnvironmentError("Missing required environment variables.")

fernet = Fernet(ENCRYPTION_KEY.encode())
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Data Models
class AIUsageLog(BaseModel):
    hw_id: str
    hostname: str
    model_name: str
    input_tokens: int
    output_tokens: int

# --- Routes ---

@app.get("/")
async def read_index():
    """Serves the frontend dashboard."""
    return FileResponse("index.html")

@app.post("/log-ai-usage")
async def log_ai_usage(request: Request):
    """Decrypts incoming logs and updates Supabase."""
    try:
        body = await request.body()
        data = json.loads(fernet.decrypt(body))
        log = AIUsageLog(**data)
        
        # 1. Upsert client into registry (Set status to 'pending' if new)
        supabase.table("clients_registry").upsert({
            "hw_id": log.hw_id,
            "hostname": log.hostname,
            "status": "pending"
        }, on_conflict="hw_id").execute()
        
        # 2. Insert usage record
        supabase.table("ai_usage_logs").insert(log.dict()).execute()
        
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/get-clients")
async def get_clients():
    """Retrieves all registered agents."""
    return supabase.table("clients_registry").select("*").execute().data

@app.get("/api/get-logs/{hw_id}")
async def get_logs(hw_id: str):
    """Retrieves logs for a specific client."""
    return supabase.table("ai_usage_logs").select("*").eq("hw_id", hw_id).order("created_at", desc=True).execute().data

@app.post("/api/status/{hw_id}/{status}")
async def set_client_status(hw_id: str, status: str):
    """Updates client status (e.g., approved/denied)."""
    supabase.table("clients_registry").update({"status": status}).eq("hw_id", hw_id).execute()
    return {"status": "success"}