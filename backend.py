import os
import json
import base64
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from supabase import create_client
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from dotenv import load_dotenv

# Load .env file (for local development)
load_dotenv()

app = FastAPI()

# 1. Initialize Supabase
# Ensure SUPABASE_URL and SUPABASE_KEY are set in Render Environment
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])

# 2. Load and Decode Private Key
# To avoid 'MalformedFraming' errors, we decode from Base64
try:
    raw_b64_key = os.environ["PRIVATE_KEY"]
    private_key_bytes = base64.b64decode(raw_b64_key)
    private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
except Exception as e:
    raise RuntimeError(f"Failed to load PRIVATE_KEY. Ensure it is Base64 encoded. Error: {e}")

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
        
        # Parse JSON data
        data = json.loads(decrypted_data)
        
        # Insert into Supabase
        # Ensure your table 'ai_usage_logs' matches these column names
        supabase.table("ai_usage_logs").insert({
            "hw_id": data["hw_id"],
            "hostname": data.get("hostname", "Unknown"),
            "model_name": data["model_name"],
            "input_tokens": data["input_tokens"],
            "output_tokens": data["output_tokens"]
        }).execute()
        
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption or Database error: {str(e)}")

@app.get("/api/get-clients")
async def get_clients():
    return supabase.table("clients_registry").select("*").execute().data

@app.get("/api/get-logs/{hw_id}")
async def get_logs(hw_id: str):
    return supabase.table("ai_usage_logs").select("*").eq("hw_id", hw_id).order("created_at", desc=True).execute().data