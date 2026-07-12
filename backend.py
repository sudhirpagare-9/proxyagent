import os
import json
from fastapi import FastAPI, Request
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from supabase import create_client

app = FastAPI()
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])

# Load Private Key from Render Environment Variable
# Use .replace() to handle newlines if you pasted it into a single line variable
PRIVATE_KEY_PEM = os.environ["PRIVATE_KEY"].replace('\\n', '\n').encode()
private_key = serialization.load_pem_private_key(PRIVATE_KEY_PEM, password=None)

@app.post("/log-ai-usage")
async def log_ai_usage(request: Request):
    encrypted_blob = await request.body()
    
    # Decrypt with Private Key
    decrypted_data = private_key.decrypt(
        encrypted_blob,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    data = json.loads(decrypted_data)
    
    # Insert into Supabase
    supabase.table("ai_usage_logs").insert(data).execute()
    return {"status": "success"}