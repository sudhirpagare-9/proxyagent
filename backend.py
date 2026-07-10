from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from supabase import create_client
import os

app = FastAPI()

# Configuration
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
SHARED_SECRET = os.environ.get("MY_SHARED_SECRET")

# Initialize Supabase
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# 1. Dashboard (The Root Route)
@app.get("/", response_class=HTMLResponse)
async def index():
    return """
    <script src="https://cdn.tailwindcss.com"></script>
    <body class="bg-gray-900 text-white p-8">
        <h1 class="text-2xl mb-4">Device Management</h1>
        <table class="w-full bg-gray-800 rounded">
            <tbody id="device-table"><tr><td class="p-4">Loading...</td></tr></tbody>
        </table>
        <script>
            function updateStatus(id, status) {
                fetch(`/toggle-status/${id}/${status}`).then(() => location.reload());
            }
            fetch('/api/admin/devices').then(res => res.json()).then(data => {
                const tbody = document.getElementById('device-table');
                tbody.innerHTML = '';
                data.forEach(d => {
                    tbody.innerHTML += `<tr>
                        <td class="p-2">${d.hw_id}</td>
                        <td class="p-2">${d.status}</td>
                        <td class="p-2">
                            <button onclick="updateStatus('${d.hw_id}', 'approved')" class="bg-green-600 px-2 rounded">Approve</button>
                        </td>
                    </tr>`;
                });
            });
        </script>
    </body>
    """

# 2. Existing API Routes
@app.get("/api/admin/devices")
async def get_devices():
    # Fetch all clients
    response = supabase.table("clients_registry").select("*").execute()
    return response.data

@app.get("/toggle-status/{hw_id}/{new_status}")
async def toggle_status(hw_id: str, new_status: str):
    # Update client status
    return supabase.table("clients_registry").update({"status": new_status}).eq("hw_id", hw_id).execute()

@app.post("/update-usage")
async def update_usage(data: dict, api_key: str = Header(...)):
    # Simple auth check
    if api_key != SHARED_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return supabase.table("clients_registry").update(data).eq("hw_id", data["hw_id"]).execute()