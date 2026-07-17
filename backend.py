import os, logging
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from supabase import create_client

app = FastAPI()
logging.basicConfig(level=logging.INFO)

# Initialize Supabase with Service Role Key
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_ROLE_KEY"])

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    with open("index.html", "r") as f: return HTMLResponse(f.read())

@app.get("/api/get-data")
async def get_data():
    """Fetches all client registry data."""
    try:
        # Fetching all data. If empty, it returns an empty list, which the frontend handles.
        response = supabase.table("clients_registry").select("*").execute()
        return {"clients": response.data}
    except Exception as e:
        logging.error(f"Database error: {e}")
        return {"clients": []}

@app.post("/api/update-status/{hw_id}")
async def update_status(hw_id: str, request: Request):
    """Updates client status (Manual override)."""
    body = await request.json()
    new_status = body.get("status")
    supabase.table("clients_registry").update({"status": new_status}).eq("hw_id", hw_id).execute()
    return {"status": "success"}

@app.post("/log-ai-usage")
async def log_ai_usage(request: Request):
    """
    RECEIVES DATA FROM PROXY AGENT.
    Using .upsert() ensures that if the HW ID is missing (Table Empty),
    it performs an INSERT. If it exists, it performs an UPDATE.
    """
    data = await request.json()
    
    # Prepare the payload mapping exactly to your table schema
    payload = {
        "hw_id": data.get("hw_id"),
        "hostname": data.get("hostname"),
        "model_used": data.get("model_used"),
        "model_version": data.get("model_version"),
        "thinklevl": data.get("thinklevl"),
        "input_tokens": data.get("input_tokens"),
        "output_tokens": data.get("output_tokens"),
        "balance_tokens": data.get("balance_tokens"),
        "subscription_status": data.get("subscription_status"),
        # Status defaults to PENDING if not provided
        "status": "PENDING" 
    }
    
    try:
        supabase.table("clients_registry").upsert(payload).execute()
        return {"status": "success"}
    except Exception as e:
        logging.error(f"Upsert failed: {e}")
        return {"status": "error", "message": str(e)}