from fastapi import FastAPI, Header, HTTPException
from supabase import create_client
import os

app = FastAPI()

# Configuration (Pulled from Environment Variables)
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
SHARED_SECRET = os.environ.get("SHARED_SECRET")

# Initialize Supabase
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Security Check
def verify_token(api_key: str):
    if api_key != SHARED_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")

@app.post("/register")
async def register_device(data: dict, api_key: str = Header(...)):
    verify_token(api_key)
    return supabase.table("clients_registry").upsert(data).execute()

@app.post("/update-usage")
async def update_usage(data: dict, api_key: str = Header(...)):
    verify_token(api_key)
    return supabase.table("clients_registry").update(data).eq("hw_id", data["hw_id"]).execute()

@app.get("/clients")
async def get_clients(api_key: str = Header(...)):
    verify_token(api_key)
    return supabase.table("clients_registry").select("*").execute()

@app.post("/toggle-status")
async def toggle_status(data: dict, api_key: str = Header(...)):
    verify_token(api_key)
    return supabase.table("clients_registry").update({"status": data["status"]}).eq("hw_id", data["hw_id"]).execute()