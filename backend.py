import os, json
import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from supabase import create_client
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from dotenv import load_dotenv

load_dotenv()
app = FastAPI()

# Supabase Setup
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])

load_dotenv()
app = FastAPI()
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])

logging.basicConfig(level=logging.INFO)

@app.post("/log-ai-usage")
async def log_usage(request: Request):
    raw_body = await request.body()
    logging.info(f"[BACKEND-TRACE] Received body: {raw_body}")
    
    try:
        data = json.loads(raw_body)
        result = supabase.table("ai_usage_logs").insert(data).execute()
        logging.info(f"[BACKEND-TRACE] Supabase Insert Result: {result.data}")
        return {"status": "ok"}
    except Exception as e:
        logging.error(f"[BACKEND-TRACE] ERROR: {str(e)}")
        return {"status": "error", "message": str(e)}
# Key Management
def get_private_key():
    key_data = os.environ.get("PRIVATE_KEY")
    if key_data:
        return serialization.load_pem_private_key(key_data.encode(), password=None)
    try:
        with open("private_key.pem", "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    except: return None

private_key = get_private_key()

# -- Endpoints --
@app.get("/", response_class=HTMLResponse)
async def serve_index():
    with open("index.html", "r") as f: return HTMLResponse(f.read())


@app.get("/api/clients")
async def get_clients(): 
    return supabase.table("clients_registry").select("*").execute().data

@app.get("/api/logs/{hw_id}")
async def get_logs(hw_id: str):
    return supabase.table("ai_usage_logs").select("*").eq("hw_id", hw_id).order("created_at", desc=True).execute().data

@app.post("/api/status/{hw_id}/{status}")
async def update_status(hw_id: str, status: str):
    return supabase.table("clients_registry").update({"status": status}).eq("hw_id", hw_id).execute()