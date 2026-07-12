import os
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from supabase import create_client
from pydantic import BaseModel
from typing import Optional

app = FastAPI()

# Configuration
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Data Models
class RegisterData(BaseModel):
    hw_id: str
    hostname: str
    mac_address: str
    ip_address: str
    public_key: str
    country: str
    geo_location: str

class AIUsageLog(BaseModel):
    hw_id: str
    model_name: str
    version: str
    model_type: str
    input_tokens: int
    output_tokens: int
    balance_tokens: Optional[int] = 0

# Routes
@app.get("/")
async def read_index():
    return FileResponse("index.html")

@app.get("/api/get-clients")
async def get_clients():
    try:
        response = supabase.table("clients_registry").select("*").execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
@app.post("/api/approve/{hw_id}")
async def approve_client(hw_id: str):
    """Updates the client status to 'approved' in Supabase."""
    try:
        response = supabase.table("clients_registry").update(
            {"status": "approved"}
        ).eq("hw_id", hw_id).execute()
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
@app.post("/register")
async def register(data: RegisterData):
    try:
        response = supabase.table("clients_registry").upsert({
            "hw_id": data.hw_id,
            "hostname": data.hostname,
            "mac_address": data.mac_address,
            "ip_address": data.ip_address,
            "public_key": data.public_key,
            "country": data.country,
            "geo_location": data.geo_location,
            "status": "ACTIVE"
        }).execute()
        return {"status": "registered"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/log-ai-usage")
async def log_ai_usage(data: AIUsageLog):
    """Logs AI usage details into the ai_usage_logs table."""
    try:
        response = supabase.table("ai_usage_logs").insert({
            "hw_id": data.hw_id,
            "model_name": data.model_name,
            "version": data.version,
            "model_type": data.model_type,
            "input_tokens": data.input_tokens,
            "output_tokens": data.output_tokens,
            "balance_tokens": data.balance_tokens
        }).execute()
        return {"status": "logged"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))