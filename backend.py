from fastapi import FastAPI, Header, HTTPException, Request
from supabase import create_client
import os

app = FastAPI()

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
SHARED_SECRET = os.environ.get("MY_SHARED_SECRET")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# 1. Register Device
@app.post("/register")
async def register(data: dict, api_key: str = Header(...)):
    if api_key != SHARED_SECRET: raise HTTPException(status_code=401)
    return supabase.table("clients_registry").upsert(data).execute()

# 2. Get Clients (Frontend needs this)
@app.get("/clients")
async def get_clients(api_key: str = Header(...)):
    if api_key != SHARED_SECRET: raise HTTPException(status_code=401)
    response = supabase.table("clients_registry").select("*").execute()
    return {"data": response.data}

# 3. Toggle Status (Matches index.html)
@app.post("/toggle-status")
async def toggle_status(data: dict, api_key: str = Header(...)):
    if api_key != SHARED_SECRET: raise HTTPException(status_code=401)
    return supabase.table("clients_registry").update({"status": data["status"]}).eq("hw_id", data["hw_id"]).execute()

# 4. Update Usage
@app.post("/update-usage")
async def update_usage(data: dict, api_key: str = Header(...)):
    if api_key != SHARED_SECRET: raise HTTPException(status_code=401)
    return supabase.table("clients_registry").update(data).eq("hw_id", data["hw_id"]).execute()