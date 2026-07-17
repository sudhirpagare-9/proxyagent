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
        response = supabase.table("clients_registry").select("*").execute()
        logging.info(f"DB Response: {len(response.data)} records found.")
        return {"clients": response.data}
    except Exception as e:
        logging.error(f"Database error: {e}")
        return {"clients": []}

@app.post("/api/update-status/{hw_id}")
async def update_status(hw_id: str, request: Request):
    """Updates client status to APPROVED or DENIED."""
    body = await request.json()
    new_status = body.get("status")
    supabase.table("clients_registry").update({"status": new_status}).eq("hw_id", hw_id).execute()
    return {"status": "success"}

@app.post("/log-ai-usage")
async def log_usage(request: Request):
    """Logs AI usage metrics to the registry."""
    data = await request.json()
    hw_id = data.get("hw_id")
    # Using 'upsert' logic based on your registry schema
    supabase.table("clients_registry").update({
        "model_used": data.get("model_used"),
        "model_version": data.get("model_version"),
        "thinklevl": data.get("thinklevl"),
        "input_tokens": data.get("input_tokens"),
        "output_tokens": data.get("output_tokens"),
        "balance_tokens": data.get("balance_tokens"),
        "subscription_status": data.get("subscription_status")
    }).eq("hw_id", hw_id).execute()
    return {"status": "success"}