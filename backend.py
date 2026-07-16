import os, json, hashlib
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from supabase import create_client
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from dotenv import load_dotenv

load_dotenv()
app = FastAPI()
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])

# Decrypt utility
def get_private_key():
    try:
        with open("private_key.pem", "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    except: return None

private_key = get_private_key()

@app.post("/log-ai-usage")
async def log_usage(request: Request):
    if not private_key: raise HTTPException(status_code=500, detail="Key Error")
    try:
        raw_body = await request.body()
        decrypted = private_key.decrypt(raw_body, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        data = json.loads(decrypted)
        # Direct insert (Data is already hashed/masked by client)
        supabase.table("ai_usage_logs").insert(data).execute()
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/clients")
async def get_clients(): 
    return supabase.table("clients_registry").select("*").execute().data

@app.post("/api/update-status/{hw_id}/{status}")
async def update_status(hw_id: str, status: str):
    return supabase.table("clients_registry").update({"status": status}).eq("hw_id", hw_id).execute()