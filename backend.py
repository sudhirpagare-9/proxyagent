import os
import json
from fastapi import FastAPI, HTTPException, Request
from supabase import create_client
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel

from fastapi.responses import FileResponse

# Add this route to serve the dashboard at the root URL
@app.get("/")
async def read_index():
    return FileResponse("index.html")
app = FastAPI()

# Supabase Initialization
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Data Models
class RegisterData(BaseModel):
    hw_id: str
    hostname: str
    public_key: str

# Signature Verification Helper
def verify_signature(data: dict, sig_hex: str, pub_key_hex: str):
    try:
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_key_hex))
        # Sort keys to ensure the signature matches the client's serialization
        message = json.dumps(data, sort_keys=True).encode()
        pub_key.verify(bytes.fromhex(sig_hex), message)
        return True
    except Exception as e:
        print(f"Signature Verification Failed: {e}")
        return False

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
    """Client polls this to check if Admin approved them."""
    try:
        response = supabase.table("clients_registry").select("status").eq("hw_id", hw_id).single().execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="Client not found")
        return {"status": response.data.get("status")}
    except Exception as e:
        raise HTTPException(status_code=404, detail="Client not found")

@app.post("/update-usage")
async def update_usage(req: dict):
    """Verifies approval status and signature before logging data."""
    data = req.get("data")
    sig = req.get("sig")
    hw_id = data.get("hw_id")

    # 1. Fetch Client Status
    client = supabase.table("clients_registry").select("status, public_key").eq("hw_id", hw_id).single().execute()
    
    if not client.data:
        raise HTTPException(status_code=403, detail="Client not registered")
    
    # 2. Status Check
    if client.data.get("status") != "approved":
        raise HTTPException(status_code=403, detail="Client pending approval")
    
    # 3. Security: Verify Signature
    if not verify_signature(data, sig, client.data.get("public_key")):
        raise HTTPException(status_code=403, detail="Signature invalid")
    
    # 4. Log to DB
    try:
        supabase.table("ai_usage_logs").insert(data).execute()
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Database write error")