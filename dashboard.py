import os
import logging
from flask import Flask, jsonify, render_template_string
from supabase import create_client

app = Flask(__name__)
url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")
supabase = create_client(url, key) if url and key else None

@app.route("/api/admin/toggle_status/<hw_id>/<new_status>")
def toggle_status(hw_id, new_status):
    if not supabase: return jsonify({"error": "DB config missing"}), 500
    supabase.table("clients_registry").update({"status": new_status}).eq("hw_id", hw_id).execute()
    return jsonify({"success": True})

@app.route("/")
def index():
    return render_template_string("""
    <script src="https://cdn.tailwindcss.com"></script>
    <body class="bg-gray-900 text-white p-8">
        <table class="w-full bg-gray-800 rounded">
            <tbody id="device-table">
                <tr><td class="p-4">Loading...</td></tr>
            </tbody>
        </table>
        <script>
            function updateStatus(id, status) {
                fetch(`/api/admin/toggle_status/${id}/${status}`).then(() => location.reload());
            }
            fetch('/api/admin/devices').then(res => res.json()).then(data => {
                const tbody = document.getElementById('device-table');
                tbody.innerHTML = ''; // Clear loading
                if (!data || data.length === 0) tbody.innerHTML = '<tr><td class="p-4">No data</td></tr>';
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
    """)

@app.route("/api/admin/devices")
def get_devices():
    try:
        response = supabase.table("clients_registry").select("*").execute()
        return jsonify(response.data if response.data else [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(port=5000)