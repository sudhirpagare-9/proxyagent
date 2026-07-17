import os, logging
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from supabase import create_client
from datetime import datetime

app = FastAPI()
logging.basicConfig(level=logging.INFO)

supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_ROLE_KEY"])

# In-memory debug log buffer
debug_logs = [{"time": datetime.now().strftime("%H:%M:%S"), "msg": "System Initialized"}]

def add_log(msg):
    debug_logs.insert(0, {"time": datetime.now().strftime("%H:%M:%S"), "msg": msg})
    if len(debug_logs) > 5: debug_logs.pop()

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    with open("index.html", "r") as f: return HTMLResponse(f.read())

@app.get("/api/get-data")
async def get_data():
    try:
        response = supabase.table("clients_registry").select("*").execute()
        return {"clients": response.data, "debug": debug_logs}
    except Exception as e:
        add_log(f"Error: {str(e)}")
        return {"clients": [], "debug": debug_logs}

@app.post("/log-ai-usage")
async def log_ai_usage(request: Request):
    data = await request.json()
    hw_id = data.get("hw_id")
    add_log(f"Received traffic from {hw_id}")
    
    try:
        supabase.table("clients_registry").upsert({
            "hw_id": hw_id,
            "hostname": data.get("hostname"),
            "model_name": data.get("model_name"),
            "input_tokens": data.get("input_tokens"),
            "status": "PENDING"
        }).execute()
        return {"status": "success"}
    except Exception as e:
        add_log(f"DB Error: {str(e)}")
        return {"status": "error"}