import os
import json
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from supabase import create_client
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load variables
load_dotenv()
app = FastAPI()

# Validate environment variables exist
required_vars = ["ENCRYPTION_KEY", "SUPABASE_URL", "SUPABASE_KEY"]
if not all(os.environ.get(var) for var in required_vars):
    raise EnvironmentError("Missing required environment variables.")

# Initialize
fernet = Fernet(os.environ["ENCRYPTION_KEY"].encode())
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])

@app.get("/")
async def read_index():
    # Ensure index.html is in the same directory as backend.py
    return FileResponse("index.html")

@app.post("/log-ai-usage")
async def log_ai_usage(request: Request):
    try:
        # Decrypt body
        encrypted_body = await request.body()
        data = json.loads(fernet.decrypt(encrypted_body))
        
        # Insert into Supabase
        supabase.table("ai_usage_logs").insert({
            "hw_id": data["hw_id"],
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

@app.get("/api/get-logs/{hw_id}")
async def get_logs(hw_id: str):
    return supabase.table("ai_usage_logs").select("*").eq("hw_id", hw_id).order("created_at", desc=True).execute().data