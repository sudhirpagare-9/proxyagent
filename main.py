import os
import json
import base64
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from supabase import create_client
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

app = FastAPI()

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")

RAW_PRIVATE_KEY = os.environ.get("RSA_PRIVATE_KEY")
RAW_PUBLIC_KEY = os.environ.get("RSA_PUBLIC_KEY")

# Load Private Key for Decryption
private_key = None
if RAW_PRIVATE_KEY:
    private_key = serialization.load_pem_private_key(
        RAW_PRIVATE_KEY.encode('utf-8'),
        password=None
    )

if SUPABASE_URL and SUPABASE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
else:
    supabase = None

@app.get("/", response_class=HTMLResponse)
async def read_index():
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Dashboard UI file (index.html) not found.</h1>"

# Public Endpoint exposing the RSA Public Key
@app.get("/public-key", response_class=PlainTextResponse)
async def get_public_key():
    if not RAW_PUBLIC_KEY:
        raise HTTPException(status_code=500, detail="Public key not configured on server.")
    return RAW_PUBLIC_KEY

@app.post("/register")
async def register_client(request: Request):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database connection missing.")
    
    try:
        data = await request.json()
        supabase.table("clients_registry").upsert({
            "hw_id": data.get("hw_id"),
            "hostname": data.get("hostname"),
            "mac_address": data.get("mac_address"),
            "status": "APPROVED"
        }, on_conflict="hw_id").execute()
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration error: {str(e)}")

@app.post("/log-traffic")
async def log_traffic(request: Request):
    if not private_key:
        raise HTTPException(status_code=500, detail="Private key missing on backend.")
    if not supabase:
        raise HTTPException(status_code=500, detail="Database connection missing.")
        
    try:
        data = await request.json()
        encrypted_payload_b64 = data.get("encrypted_payload")
        hw_id = data.get("hw_id")

        if not encrypted_payload_b64:
            raise HTTPException(status_code=400, detail="Missing encrypted payload.")

        # Decode base64 encrypted packet
        encrypted_data = base64.b64decode(encrypted_payload_b64)

        # Decrypt using Server's Private Key
        decrypted_bytes = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        payload = json.loads(decrypted_bytes.decode('utf-8'))

        # Insert Decrypted Metrics into Database
        supabase.table("ai_usage_logs").insert({
            "hw_id": hw_id, 
            "model_name": payload.get("model_name", "unknown"),
            "input_tokens": payload.get("input_tokens", 0),
            "output_tokens": payload.get("output_tokens", 0),
            "balance": payload.get("balance", 0.0)
        }).execute()
            
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Decryption/Verification Failed: {str(e)}")

@app.get("/api/dashboard-data")
async def get_data():
    if not supabase:
        return {"clients": [], "logs": []}
        
    clients = supabase.table("clients_registry").select("*").execute().data
    logs = supabase.table("ai_usage_logs").select("*").order("created_at", desc=True).limit(50).execute().data
    return {"clients": clients, "logs": logs}