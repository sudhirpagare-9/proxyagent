import os
from flask import Flask, Response, request, jsonify

app = Flask(__name__)

# Supabase Config
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase = None

if SUPABASE_URL and SUPABASE_KEY:
    try:
        from supabase import create_client
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    except: pass

# --- HTML UI ---
HTML = """
<!DOCTYPE html>
<html>
<head><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-slate-900 text-white p-8">
    <h1 class="text-2xl font-bold mb-4">Proxy Control Center</h1>
    <table class="w-full bg-slate-800 rounded shadow-lg">
        <tbody id="rows"></tbody>
    </table>
    <script>
        async function fetchDevices() {
            const res = await fetch('/api/devices');
            const data = await res.json();
            document.getElementById("rows").innerHTML = data.map(d => `
                <tr class="border-b border-slate-700">
                    <td class="p-3">${d.hostname}</td>
                    <td class="p-3 font-bold ${d.status === 'APPROVED' ? 'text-green-400' : 'text-red-400'}">${d.status}</td>
                    <td class="p-3">
                        <button onclick="update('${d.hw_id}', 'APPROVED')" class="bg-green-600 px-2 py-1 rounded text-xs">Approve</button>
                        <button onclick="update('${d.hw_id}', 'BLOCKED')" class="bg-red-600 px-2 py-1 rounded text-xs ml-1">Block</button>
                    </td>
                </tr>
            `).join('');
        }
        async function update(hw_id, status) {
            await fetch('/api/update', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ hw_id, status })});
            fetchDevices();
        }
        setInterval(fetchDevices, 5000);
        fetchDevices();
    </script>
</body>
</html>
"""

@app.route("/")
def home(): return Response(HTML, mimetype='text/html')

@app.route("/api/devices")
def get_devices():
    if not supabase: return jsonify([])
    return jsonify(supabase.table("clients_registry").select("*").execute().data or [])

@app.route("/api/update", methods=["POST"])
def update():
    supabase.table("clients_registry").update({"status": request.json["status"]}).eq("hw_id", request.json["hw_id"]).execute()
    return "OK"

@app.route("/api/client/status/<hw_id>")
def check_status(hw_id):
    if not supabase: return jsonify({"status": "BLOCKED"})
    res = supabase.table("clients_registry").select("status").eq("hw_id", hw_id).single().execute()
    return jsonify({"status": res.data.get("status", "BLOCKED") if res.data else "BLOCKED"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))