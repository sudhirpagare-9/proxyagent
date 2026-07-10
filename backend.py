from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from supabase import create_client
import os

# Initialize app FIRST
app = FastAPI()

# Configuration
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
SHARED_SECRET = os.environ.get("MY_SHARED_SECRET")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Routes
@app.get("/", response_class=HTMLResponse)
async def read_root():
    with open("index.html", "r") as f:
        return f.read()

@app.post("/register")
async def register(data: dict, api_key: str = Header(...)):
    if api_key != SHARED_SECRET: raise HTTPException(status_code=401)
    return supabase.table("clients_registry").upsert(data).execute()

@app.get("/clients")
async def get_clients(api_key: str = Header(...)):
    if api_key != SHARED_SECRET: raise HTTPException(status_code=401)
    response = supabase.table("clients_registry").select("*").execute()
    return {"data": response.data}

@app.post("/toggle-status")
async def toggle_status(data: dict, api_key: str = Header(...)):
    if api_key != SHARED_SECRET: raise HTTPException(status_code=401)
    return supabase.table("clients_registry").update({"status": data["status"]}).eq("hw_id", data["hw_id"]).execute()