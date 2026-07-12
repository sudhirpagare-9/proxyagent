import os
import json
import base64
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from supabase import create_client
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from dotenv import load_dotenv

load_dotenv()
app = FastAPI()

# Initialize Supabase
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])

# Single, clean key loading function
def get_private_key():
    raw_b64 = os.environ.get("PRIVATE_KEY")
    if not raw_b64:
        raise RuntimeError("PRIVATE_KEY environment variable is missing!")
    
    # Sanitization: Remove newlines, spaces, and backslashes that cause crashes
    clean_b64 = raw_b64.strip().replace("\\", "").replace("\n", "").replace("\r", "")
    
    try:
        pem_bytes = base64.b64decode(clean_b64)
        return serialization.load_pem_private_key(pem_bytes, password=None)
    except Exception as e:
        raise RuntimeError(f"CRITICAL: Failed to load PRIVATE_KEY. Error: {e}")

private_key = get_private_key()

@app.get("/")
async def read_index():
    # If index.html is in a subfolder (e.g., 'dist'), change this to "dist/index.html"
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

@app.get("/api/get-clients")
async def get_clients():
    return supabase.table("clients_registry").select("*").execute().data

# Added this missing route to fix your 404 error
@app.post("/api/status/{hw_id}/{status}")
async def set_client_status(hw_id: str, status: str):
    supabase.table("clients_registry").update({"status": status}).eq("hw_id", hw_id).execute()
    return {"status": "success"}

@app.get("/api/get-logs/{hw_id}")
async def get_logs(hw_id: str):
    return supabase.table("ai_usage_logs").select("*").eq("hw_id", hw_id).order("created_at", desc=True).execute().data