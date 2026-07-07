import os
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# --- Supabase Setup ---
# Do NOT hardcode keys here. Use environment variables.
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

supabase = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        from supabase import create_client
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as e:
        print(f"Supabase Init Error: {e}")

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <script src="https://cdn.tailwindcss.com"></script>
    <title>AI Proxy Dashboard</title>
</head>
<body class="bg-[#0b1329] text-gray-100 p-8">
    <div class="max-w-7xl mx-auto">
        <h1 class="text-3xl font-bold text-indigo-400 mb-8">☁️ AI Proxy Analytics</h1>
        <table class="w-full bg-gray-800 rounded-lg overflow-hidden">
            <thead class="bg-gray-700 text-left">
                <tr><th class="p-3">Device ID</th><th class="p-3">Status</th><th class="p-3 text-right">Actions</th></tr>
            </thead>
            <tbody id="device-table"></tbody>
        </table>
    </div>
    <script>
        async function fetchDevices() {
            try {
                // Fetch relative to the current domain
                const response = await fetch('/api/admin/devices');
                const data = await response.json();
                const tbody = document.getElementById('device-table');
                tbody.innerHTML = '';
                data.forEach(d => {
                    const row = document.createElement('tr');
                    row.innerHTML = `<td class="p-3">${d.hw_id}</td>
                        <td class="p-3"><span class="${d.status === 'APPROVED' ? 'text-green-500' : 'text-yellow-500'}">${d.status}</span></td>
                        <td class="p-3 text-right">...</td>`;
                    tbody.appendChild(row);
                });
            } catch(e) { console.error("Fetch Error:", e); }
        }
        fetchDevices();
    </script>
</body>
</html>
"""

@app.route("/")
def home():
    return render_template_string(DASHBOARD_HTML)

@app.route("/api/admin/devices")
def admin_get_devices():
    if not supabase: 
        return jsonify({"error": "Supabase not configured"}), 500
    try:
        # Ensure your table name 'clients_registry' exists in Supabase
        res = supabase.table("clients_registry").select("*").execute()
        return jsonify(res.data or [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)