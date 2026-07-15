import os
import json
from fastapi import FastAPI, HTTPException, Request
from supabase import create_client
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from dotenv import load_dotenv

load_dotenv()
app = FastAPI()

supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])

def get_private_key():
    # Render mounts secret files at this path
    key_path = "/etc/secrets/private_key.pem"
    
    # If we are on your local computer, look here
    if not os.path.exists(key_path):
        key_path = "private_key.pem"
        
    with open(key_path, "rb") as key_file:
        # Load the raw PEM data
        return serialization.load_pem_private_key(key_file.read(), password=None)

# Initialize key once on startup
private_key = get_private_key()

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

@app.post("/api/status/{hw_id}/{status}")
async def set_client_status(hw_id: str, status: str):
    supabase.table("clients_registry").update({"status": status}).eq("hw_id", hw_id).execute()
    return {"status": "success"}

@app.get("/api/get-logs/{hw_id}")
async def get_logs(hw_id: str):
    return supabase.table("ai_usage_logs").select("*").eq("hw_id", hw_id).order("created_at", desc=True).execute().data