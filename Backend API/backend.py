from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client
import os

app = FastAPI()

# FIX: Add CORS to allow your dashboard to talk to this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this to your actual dashboard domain
    allow_methods=["*"],
    allow_headers=["*"],
)

# FIX: Get the *names* of the env variables, not the values
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_KEY")
SHARED_SECRET = os.environ.get("MY_SHARED_SECRET")

# Initialize Supabase
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

@app.post("/register")
async def register_device(data: dict, api_key: str = Header(...)):
    if api_key != SHARED_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return supabase.table("clients_registry").upsert(data).execute()

@app.post("/update-usage")
async def update_usage(data: dict, api_key: str = Header(...)):
    if api_key != SHARED_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return supabase.table("clients_registry").update(data).eq("hw_id", data["hw_id"]).execute()

@app.get("/clients")
async def get_clients(api_key: str = Header(...)):
    if api_key != SHARED_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return supabase.table("clients_registry").select("*").execute()