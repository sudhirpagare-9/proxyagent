from fastapi import FastAPI, HTTPException, Header
from supabase import create_client
import os
from cryptography.hazmat.primitives.asymmetric import ed25519
import json

app = FastAPI()
supabase = create_client(os.environ.get("SUPABASE_URL"), os.environ.get("SUPABASE_KEY"))

# Helper: Verify Digital Signature
def verify_signature(data: dict, signature_hex: str, public_key_hex: str):
    try:
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        data_bytes = json.dumps(data, sort_keys=True).encode()
        pub_key.verify(bytes.fromhex(signature_hex), data_bytes)
        return True
    except Exception:
        return False

@app.post("/register")
async def register(data: dict):
    # Register client with their Public Key
    return supabase.table("clients_registry").upsert({
        "hw_id": data["hw_id"],
        "hostname": data["hostname"],
        "public_key": data["public_key"],
        "status": "approved"
    }).execute()

@app.post("/update-usage")
async def update_usage(payload: dict):
    hw_id = payload["data"]["hw_id"]
    # 1. Get Public Key from DB
    client = supabase.table("clients_registry").select("public_key").eq("hw_id", hw_id).single().execute()
    if not client.data:
        raise HTTPException(status_code=404, detail="Client not found")
    
    # 2. Verify Data Integrity
    if not verify_signature(payload["data"], payload["sig"], client.data["public_key"]):
        raise HTTPException(status_code=403, detail="Invalid Signature")
    
    # 3. Save to logs
    return supabase.table("ai_usage_logs").insert(payload["data"]).execute()