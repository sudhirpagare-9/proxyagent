import os
from flask import Flask, Response, request, jsonify

app = Flask(__name__)

# --- Supabase Setup ---
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

supabase = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        from supabase import create_client
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    except: pass

# --- HTML (Raw String) ---
HTML_CODE = """
<!DOCTYPE html>
<html>
<head><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-900 text-white p-10">
    <h1 class="text-2xl font-bold mb-5">AI Proxy Dashboard</h1>
    <table class="w-full bg-gray-800 rounded">
        <tbody id="rows"></tbody>
    </table>
    <script>
        async function fetchDevices() {
            const res = await fetch('/api/devices');
            const data = await res.json();
            document.getElementById("rows").innerHTML = data.map(d => `
                <tr class="border-b border-gray-700">
                    <td class="p-3">${d.hostname}</td>
                    <td class="p-3">${d.status}</td>
                    <td class="p-3"><button onclick="update('${d.hw_id}', 'APPROVED')" class="bg-green-600 px-2 py-1 rounded text-xs">Approve</button></td>
                </tr>
            `).join('');
        }
        async function update(hw_id, status) {
            await fetch('/api/update', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ hw_id, status })
            });
            fetchDevices();
        }
        setInterval(fetchDevices, 3000);
        fetchDevices();
    </script>
</body>
</html>
"""

@app.route("/")
def home():
    return Response(HTML_CODE, mimetype='text/html')

@app.route("/api/devices")
def get_devices():
    if not supabase: return jsonify([])
    return jsonify(supabase.table("clients_registry").select("*").execute().data or [])

@app.route("/api/update", methods=["POST"])
def update():
    data = request.json
    supabase.table("clients_registry").update({"status": data["status"]}).eq("hw_id", data["hw_id"]).execute()
    return "OK"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))