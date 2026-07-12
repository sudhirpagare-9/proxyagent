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

# Models
class RegisterData(BaseModel):
    hw_id: str
    hostname: str
    public_key: str
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    country: Optional[str] = None
    geo_location: Optional[str] = None

class AIUsageLog(BaseModel):
    hw_id: str
    model_name: str
    version: str
    model_type: str
    input_tokens: int
    output_tokens: int
    balance_tokens: Optional[int] = 0

# Endpoints
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

@app.post("/register")
async def register(data: RegisterData, request: Request):
    try:
        response = supabase.table("clients_registry").upsert({
            "hw_id": data.hw_id,
            "hostname": data.hostname,
            "public_key": data.public_key,
            "ip_address": data.ip_address,
            "mac_address": data.mac_address,
            "country": data.country,
            "geo_location": data.geo_location,
            "status": "pending",
            "last_ip": request.client.host
        }).execute()
        return {"status": "registered"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/approve/{hw_id}")
async def approve_client(hw_id: str):
    try:
        response = supabase.table("clients_registry").update({"status": "approved"}).eq("hw_id", hw_id).execute()
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/log-ai-usage")
async def log_ai_usage(data: AIUsageLog):
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

@app.get("/api/get-logs/{hw_id}")
async def get_logs(hw_id: str):
    try:
        response = supabase.table("ai_usage_logs").select("*").eq("hw_id", hw_id).order("created_at", desc=True).execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))