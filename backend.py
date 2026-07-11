import os
import json
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from supabase import create_client
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel

app = FastAPI()
@app.get("/api/get-clients")
async def get_clients():
    try:
        # The backend uses the environment variables securely
        # The frontend never sees these keys
        response = supabase.table("clients_registry").select("*").execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
@app.get("/")
async def read_index():
    # Ensure index.html is in the same directory as backend.py
    return FileResponse("index.html")

# Keep your other existing routes below this...
app = FastAPI()

# Configuration: Ensure SUPABASE_URL and SUPABASE_KEY are in your Render Environment Variables
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

class RegisterData(BaseModel):
    hw_id: str
    hostname: str
    public_key: str

def verify_signature(data: dict, sig_hex: str, pub_key_hex: str):
    try:
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_key_hex))
        message = json.dumps(data, sort_keys=True).encode()
        pub_key.verify(bytes.fromhex(sig_hex), message)
        return True
    except Exception:
        return False

@app.get("/")
async def read_index():
    return FileResponse("index.html")

@app.post("/register")
async def register(data: RegisterData, request: Request):
    try:
        supabase.table("clients_registry").upsert({
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
    response = supabase.table("clients_registry").select("status").eq("hw_id", hw_id).single().execute()
    if not response.data:
        raise HTTPException(status_code=404, detail="Client not found")
    return {"status": response.data.get("status")}

@app.post("/update-usage")
async def update_usage(req: dict):
    data = req.get("data")
    sig = req.get("sig")
    hw_id = data.get("hw_id")

    client = supabase.table("clients_registry").select("status, public_key").eq("hw_id", hw_id).single().execute()
    
    if not client.data or client.data.get("status") != "approved":
        raise HTTPException(status_code=403, detail="Access denied")
    
    if not verify_signature(data, sig, client.data.get("public_key")):
        raise HTTPException(status_code=403, detail="Signature invalid")
    
    supabase.table("ai_usage_logs").insert(data).execute()
    return {"status": "success"}