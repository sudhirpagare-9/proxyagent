import os
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client

app = FastAPI()

# Enable CORS for frontend interaction
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration: Use os.getenv() to prevent crashes
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
SHARED_SECRET = os.getenv("MY_SHARED_SECRET")

# Initialize Supabase
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

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