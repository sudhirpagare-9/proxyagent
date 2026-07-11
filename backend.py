import os
import json
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from supabase import create_client
from pydantic import BaseModel

app = FastAPI()

# Configuration
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Data Model
class RegisterData(BaseModel):
    hw_id: str
    hostname: str
    public_key: str

# Routes
@app.get("/")
async def read_index():
    return FileResponse("index.html")

@app.get("/api/get-clients")
async def get_clients():
    """Secure endpoint for the dashboard to fetch data."""
    try:
        # Fetching data from Supabase
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
            "status": "pending",
            "last_ip": request.client.host
        }).execute()
        return {"status": "registered"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/status/{hw_id}")
async def get_status(hw_id: str):
    try:
        response = supabase.table("clients_registry").select("status").eq("hw_id", hw_id).single().execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="Client not found")
        return {"status": response.data.get("status")}
    except Exception:
        raise HTTPException(status_code=404, detail="Client not found")