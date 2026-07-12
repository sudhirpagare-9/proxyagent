import os
import json
import base64
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from supabase import create_client
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from dotenv import load_dotenv

# Load env variables
load_dotenv()

app = FastAPI()

# 1. Initialize Supabase
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])

# 2. Load Private Key safely
def get_private_key():
    raw_b64 = os.environ.get("PRIVATE_KEY")
    if not raw_b64:
        raise RuntimeError("PRIVATE_KEY environment variable is missing!")
    
    # Strip any potential whitespace
    clean_key = raw_b64.strip()
    
    try:
        # Decode base64
        pem_bytes = base64.b64decode(clean_key)
        # Load PEM
        return serialization.load_pem_private_key(pem_bytes, password=None)
    except Exception as e:
        raise RuntimeError(f"Failed to load PRIVATE_KEY. Check formatting. Error: {e}")

# Single source of truth for the key
private_key = get_private_key()

@app.get("/")
async def read_index():
    # If this returns 404, ensure index.html is in your root directory
    return FileResponse("index.html")

@app.post("/log-ai-usage")
async def log_ai_usage(request: Request):
    try:
        encrypted_blob = await request.body()
        decrypted_data = private_key.decrypt(
            encrypted_blob,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        data = json.loads(decrypted_data)
        
        supabase.table("ai_usage_logs").insert({
            "hw_id": data["hw_id"],
            "hostname": data.get("hostname", "Unknown"),
            "model_name": data["model_name"],
            "input_tokens": data["input_tokens"],
            "output_tokens": data["output_tokens"]
        }).execute()
        
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))