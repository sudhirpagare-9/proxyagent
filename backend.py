import os, hmac, hashlib, json
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from supabase import create_client

app = FastAPI()
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
APP_SECRET = os.environ.get("APP_SECRET", "default-dev-secret").encode()

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Serve Dashboard
@app.get("/", response_class=HTMLResponse)
async def read_index():
    with open("index.html", "r") as f: return f.read()

# Register: Captures full Machine/Network profile
@app.post("/register")
async def register_client(request: Request):
    data = await request.json()
    supabase.table("clients_registry").upsert({
        "hw_id": data["hw_id"],
        "hostname": data["hostname"],
        "mac_address": data["mac_address"],
        "ip_address": data["ip_address"],
        "country": data["country"],
        "status": "PENDING"
    }).execute()
    return {"status": "success"}

# Admin: Approval Logic
@app.post("/api/update-status/{hw_id}")
async def update_status(hw_id: str, request: Request):
    data = await request.json()
    supabase.table("clients_registry").update({"status": data["status"]}).eq("hw_id", hw_id).execute()
    return {"status": "success"}

# Traffic Log: Authenticated & Validated
@app.post("/log-traffic")
async def log_traffic(request: Request):
    data = await request.json()
    payload = data["data"]
    
    # 1. NIST/Secure-by-Design: Integrity Verification
    expected_sig = hmac.new(APP_SECRET, json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, data["sig"]):
        raise HTTPException(status_code=401, detail="Invalid Signature")

    # 2. Authorization Check
    client = supabase.table("clients_registry").select("status").eq("hw_id", data["hw_id"]).single().execute()
    if client.data["status"] != "APPROVED":
        raise HTTPException(status_code=403, detail="Client Not Approved")

    supabase.table("ai_usage_logs").insert({"hw_id": data["hw_id"], **payload}).execute()
    return {"status": "success"}

@app.get("/api/dashboard-data")
async def get_data():
    return {
        "clients": supabase.table("clients_registry").select("*").execute().data,
        "logs": supabase.table("ai_usage_logs").select("*").order("created_at", desc=True).limit(50).execute().data
    }