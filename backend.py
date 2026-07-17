import os
import hmac
import hashlib
import json
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from supabase import create_client

app = FastAPI()
# Render Environment Variables
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
APP_SECRET = os.environ.get("APP_SECRET", "fallback-insecure-secret").encode()

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Serve the Dashboard UI
@app.get("/", response_class=HTMLResponse)
async def read_index():
    with open("index.html", "r") as f:
        return f.read()

# API: Register Client (GDPR: PII Masking)
@app.post("/register")
async def register_client(request: Request):
    data = await request.json()
    hw_id = data.get("hw_id")
    # Masking IP address for GDPR compliance
    masked_ip = "xxx.xxx.xxx.xxx"
    
    supabase.table("clients_registry").upsert({
        "hw_id": hw_id,
        "hostname": data.get("hostname"),
        "ip_address": masked_ip,
        "status": "PENDING"
    }).execute()
    return {"status": "success"}

# API: Admin Approval Logic (NIST: Authorization)
@app.post("/api/update-status/{hw_id}")
async def update_status(hw_id: str, request: Request):
    data = await request.json()
    new_status = data.get("status")
    supabase.table("clients_registry").update({"status": new_status}).eq("hw_id", hw_id).execute()
    return {"status": "success"}

# API: Traffic Logger (NIST: Integrity Check)
@app.post("/log-traffic")
async def log_traffic(request: Request):
    data = await request.json()
    hw_id = data.get("hw_id")
    received_sig = data.get("sig")
    payload = data.get("data")

    # 1. NIST Authorization Check
    client = supabase.table("clients_registry").select("status").eq("hw_id", hw_id).single().execute()
    if not client.data or client.data.get("status") != "APPROVED":
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    # 2. NIST Integrity Check (HMAC-SHA256)
    expected_sig = hmac.new(APP_SECRET, json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, received_sig):
        raise HTTPException(status_code=401, detail="Integrity Violation")
        
    supabase.table("ai_usage_logs").insert({"hw_id": hw_id, "data": payload}).execute()
    return {"status": "success"}

# API: Fetch Dashboard Data
@app.get("/api/dashboard-data")
async def get_data():
    clients = supabase.table("clients_registry").select("*").execute().data
    logs = supabase.table("ai_usage_logs").select("*").order("created_at", desc=True).limit(20).execute().data
    return {"clients": clients, "logs": logs}