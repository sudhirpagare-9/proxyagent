from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from supabase import create_client
import os
from typing import Optional
import sys

# Configuration
required_vars = ["SUPABASE_URL", "SUPABASE_KEY", "SHARED_SECRET"]
for var in required_vars:
    if not os.environ.get(var):
        sys.exit(1)

app = FastAPI()
supabase = create_client(os.environ.get("SUPABASE_URL"), os.environ.get("SUPABASE_KEY"))
SHARED_SECRET = os.environ.get("SHARED_SECRET")

def validate_key(api_key: Optional[str]):
    if api_key != SHARED_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")

@app.get("/", response_class=HTMLResponse)
async def read_root():
    with open("index.html", "r") as f:
        return f.read()

@app.get("/clients")
async def get_clients(api_key: str = Header(...)):
    validate_key(api_key)
    response = supabase.table("clients_registry").select("*").execute()
    return {"data": response.data}

@app.get("/analytics")
async def get_analytics(api_key: str = Header(...)):
    validate_key(api_key)
    response = supabase.table("ai_usage_logs").select("*").order("created_at", desc=True).limit(20).execute()
    return {"data": response.data}

@app.post("/register")
async def register(data: dict, api_key: str = Header(...)):
    validate_key(api_key)
    return supabase.table("clients_registry").upsert(data).execute()

@app.post("/toggle-status")
async def toggle_status(data: dict, api_key: str = Header(...)):
    validate_key(api_key)
    return supabase.table("clients_registry").update({"status": data["status"]}).eq("hw_id", data["hw_id"]).execute()

@app.post("/update-usage")
async def update_usage(data: dict, api_key: str = Header(...)):
    validate_key(api_key)
    # Update client info and log usage
    supabase.table("clients_registry").update({
        "model_name": data.get("model_name"),
        "input_tokens": data.get("input_tokens"),
        "output_tokens": data.get("output_tokens")
    }).eq("hw_id", data["hw_id"]).execute()
    return supabase.table("ai_usage_logs").insert(data).execute()