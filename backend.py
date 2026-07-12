import os
import json
import base64
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from supabase import create_client
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from dotenv import load_dotenv

# 1. Environment Loading
load_dotenv()

# 2. Key Loading
def get_private_key():
    raw_b64 = os.environ.get("PRIVATE_KEY")
    if not raw_b64:
        raise RuntimeError("PRIVATE_KEY missing from environment variables!")
    try:
        # Decode Base64 to binary
        pem_bytes = base64.b64decode(raw_b64)
        # Load the PEM key
        return serialization.load_pem_private_key(pem_bytes, password=None)
    except Exception as e:
        raise RuntimeError(f"Failed to load PRIVATE_KEY. Ensure it is Base64 encoded. Error: {e}")

# Global Initialization
app = FastAPI()
private_key = get_private_key()
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])

# 3. Routes
@app.get("/")
async def read_index():
    return FileResponse("index.html")

@app.post("/log-ai-usage")
async def log_ai_usage(request: Request):
    try:
        # Read the raw encrypted bytes from the request
        encrypted_blob = await request.body()
        
        # Decrypt using RSA Private Key
        decrypted_data = private_key.decrypt(
            encrypted_blob,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        data = json.loads(decrypted_data)
        
        # Insert into Supabase
        supabase.table("ai_usage_logs").insert({
            "hw_id": data["hw_id"],
            "hostname": data.get("hostname", "Unknown"),
            "model_name": data["model_name"],
            "input_tokens": data["input_tokens"],
            "output_tokens": data["output_tokens"]
        }).execute()
        
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption/Database error: {str(e)}")

@app.get("/api/get-clients")
async def get_clients():
    return supabase.table("clients_registry").select("*").execute().data

@app.get("/api/get-logs/{hw_id}")
async def get_logs(hw_id: str):
    return supabase.table("ai_usage_logs").select("*").eq("hw_id", hw_id).order("created_at", desc=True).execute().data

@app.post("/api/status/{hw_id}/{status}")
async def set_client_status(hw_id: str, status: str):
    supabase.table("clients_registry").update({"status": status}).eq("hw_id", hw_id).execute()
    return {"status": "success"}