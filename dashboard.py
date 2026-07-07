import os
import logging
from flask import Flask, jsonify, render_template_string
from supabase import create_client

# Setup logging
logging.basicConfig(level=logging.INFO)
app = Flask(__name__)

# Initialize Supabase safely
url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")

if not url or not key:
    logging.error("SUPABASE_URL or SUPABASE_KEY missing!")
    supabase = None
else:
    supabase = create_client(url, key)

@app.route("/api/admin/toggle_status/<hw_id>/<new_status>")
def toggle_status(hw_id, new_status):
    if not supabase: return jsonify({"error": "DB config missing"}), 500
    if new_status not in ['approved', 'blocked', 'pending']:
        return jsonify({"error": "Invalid status"}), 400
    
    supabase.table("clients_registry").update({"status": new_status}).eq("hw_id", hw_id).execute()
    return jsonify({"success": True})

@app.route("/")
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html class="bg-gray-900 text-white">
    <head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="p-8">
        <h1 class="text-2xl font-bold mb-4">Proxy Control Center</h1>
        <table class="w-full bg-gray-800 rounded p-4 text-sm">
            <thead>
                <tr class="text-gray-400 border-b border-gray-700">
                    <th class="p-2">HW ID</th>
                    <th class="p-2">Hostname</th>
                    <th class="p-2">Status</th>
                    <th class="p-2">Actions</th>
                </tr>
            </thead>
            <tbody id="device-table"></tbody>
        </table>
        <script>
            function updateStatus(id, status) {
                fetch(`/api/admin/toggle_status/${id}/${status}`)
                    .then(() => location.reload());
            }

            fetch('/api/admin/devices')
                .then(res => res.json())
                .then(data => {
                    const tbody = document.getElementById('device-table');
                    data.forEach(d => {
                        tbody.innerHTML += `
                            <tr class="border-b border-gray-700">
                                <td class="p-2">${d.hw_id}</td>
                                <td class="p-2">${d.hostname || 'N/A'}</td>
                                <td class="p-2">${d.status || 'pending'}</td>
                                <td class="p-2">
                                    <button onclick="updateStatus('${d.hw_id}', 'approved')" class="bg-green-600 px-2 py-1 rounded mr-2">Approve</button>
                                    <button onclick="updateStatus('${d.hw_id}', 'blocked')" class="bg-red-600 px-2 py-1 rounded">Block</button>
                                </td>
                            </tr>`;
                    });
                });
        </script>
    </body>
    </html>
    """)

@app.route("/api/admin/devices")
def get_devices():
    if not supabase: return jsonify({"error": "DB config missing"}), 500
    try:
        response = supabase.table("clients_registry").select("*").execute()
        return jsonify(response.data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)