from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from supabase import create_client
import os
from typing import Optional

# 1. Initialize app
app = FastAPI()

# 2. Configuration
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
# Ensure this matches your Render Environment Variable key exactly
SHARED_SECRET = os.environ.get("SHARED_SECRET")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Helper function for authorization
def validate_key(api_key: Optional[str]):
    if api_key != SHARED_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")

# 3. Serve the dashboard
@app.get("/", response_class=HTMLResponse)
async def read_root():
    with open("index.html", "r") as f:
        return f.read()

# 4. API Routes
@app.post("/register")
async def register(data: dict, api_key: str = Header(...)):
    validate_key(api_key)
    # This handles the new fields: ip_address, hostname, country, etc.
    return supabase.table("clients_registry").upsert(data).execute()

@app.get("/clients")
async def get_clients(api_key: str = Header(...)):
    validate_key(api_key)
    # Fetches all current client data
    response = supabase.table("clients_registry").select("*").execute()
    return {"data": response.data}

@app.post("/toggle-status")
async def toggle_status(data: dict, api_key: str = Header(...)):
    validate_key(api_key)
    return supabase.table("clients_registry").update({"status": data["status"]}).eq("hw_id", data["hw_id"]).execute()

@app.post("/update-usage")
async def update_usage(data: dict, api_key: str = Header(...)):
    validate_key(api_key)
    # 1. Update the client's last active model/stats
    supabase.table("clients_registry").update({
        "model_name": data.get("model_name"),
        "input_tokens": data.get("input_tokens"),
        "output_tokens": data.get("output_tokens")
    }).eq("hw_id", data["hw_id"]).execute()
    
    # 2. Insert into usage logs for analytics history
    return supabase.table("ai_usage_logs").insert(data).execute()

@app.get("/analytics")
async def get_analytics(api_key: str = Header(...)):
    validate_key(api_key)
    # Fetches aggregated usage data for analytics
    response = supabase.table("ai_usage_logs").select("*").execute()
    return {"data": response.data}