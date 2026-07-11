from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from supabase import create_client
import os
from typing import Optional
# Force a crash with a clear message if environment variables are missing
import sys

required_vars = ["SUPABASE_URL", "SUPABASE_KEY", "SHARED_SECRET"]
for var in required_vars:
    if not os.environ.get(var):
        print(f"CRITICAL ERROR: Environment variable {var} is not set!")
        sys.exit(1) # This will show the error in your Render logs

app = FastAPI()

# Configuration
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
SHARED_SECRET = os.environ.get("SHARED_SECRET")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

def validate_key(api_key: Optional[str]):
    if api_key != SHARED_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")

@app.get("/", response_class=HTMLResponse)
async def read_root():
    with open("index.html", "r") as f:
        return f.read()

@app.get("/analytics")
async def get_analytics(api_key: str = Header(...)):
    validate_key(api_key)
    # Order by time descending, limit to 20 recent items
    response = supabase.table("ai_usage_logs").select("*").order("created_at", desc=True).limit(20).execute()
    return {"data": response.data}

# ... [Keep your existing /register, /clients, /toggle-status, and /update-usage routes here]


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

# @app.get("/analytics")
# async def get_analytics(api_key: str = Header(...)):
    # validate_key(api_key)
    #Fetches aggregated usage data for analytics
    # response = supabase.table("ai_usage_logs").select("*").execute()
    # return {"data": response.data}
    
@app.get("/analytics")
async def get_analytics(api_key: str = Header(...)):
    if api_key != SHARED_SECRET: 
        raise HTTPException(status_code=401)
    
    # This queries your 'ai_usage_logs' table. 
    # Make sure this table exists in your Supabase database.
    response = supabase.table("ai_usage_logs").select("*").order("created_at", desc=True).limit(20).execute()
    return {"data": response.data}