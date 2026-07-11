import os
import json
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from supabase import create_client
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel

app = FastAPI()

# Configuration
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Data Model
class RegisterData(BaseModel):
    hw_id: str
    hostname: str
    public_key: str

# Signature Verification Helper
def verify_signature(data: dict, sig_hex: str, pub_key_hex: str):
    try:
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_key_hex))
        message = json.dumps(data, sort_keys=True).encode()
        pub_key.verify(bytes.fromhex(sig_hex), message)
        return True
    except Exception:
        return False

# --- Routes ---

@app.get("/")
async def read_index():
    return FileResponse("index.html")

@app.get("/api/get-clients")
async def get_clients():
    """Secure endpoint for dashboard to fetch client data."""
    try:
        response = supabase.table("clients_registry").select("*").execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/register")
async def register(data: RegisterData, request: Request):
    """Registers a client as 'pending'."""
    try:
        response = supabase.table("clients_registry").upsert({
            "hw_id": data.hw_id,
            "hostname": data.hostname,
            "public_key": data.public_key,
            "status": "pending",
            "last_ip": request.client.host
        }).execute()
        return {"status": "registered"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/status/{hw_id}")
async def get_status(hw_id: str):
    """Client polls this to check status."""
    try:
        response = supabase.table("clients_registry").select("status").eq("hw_id", hw_id).single().execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="Client not found")
        return {"status": response.data.get("status")}
    except Exception:
        raise HTTPException(status_code=404, detail="Client not found")

@app.post("/update-usage")
async def update_usage(req: dict):
    """Verifies approval status and signature before logging data."""
    data = req.get("data")
    sig = req.get("sig")
    hw_id = data.get("hw_id")

    client = supabase.table("clients_registry").select("status, public_key").eq("hw_id", hw_id).single().execute()
    
    if not client.data or client.data.get("status") != "approved":
        raise HTTPException(status_code=403, detail="Access denied")
    
    if not verify_signature(data, sig, client.data.get("public_key")):
        raise HTTPException(status_code=403, detail="Signature invalid")
    
    try:
        supabase.table("ai_usage_logs").insert(data).execute()
        return {"status": "success"}
    except Exception:
        raise HTTPException(status_code=500, detail="Database write error")