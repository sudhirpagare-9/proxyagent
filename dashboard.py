import os
import logging
from flask import Flask, jsonify, render_template_string
from supabase import create_client

# Set up logging to help debug on Render
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Initialize Supabase
url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")

supabase = None
if url and key:
    supabase = create_client(url, key)
    logger.info("Supabase client initialized successfully")
else:
    logger.error("Supabase URL or KEY missing from environment variables")

@app.route("/")
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html class="bg-gray-900 text-white">
    <head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="p-8">
        <h1 class="text-2xl font-bold mb-4">Proxy Control Center</h1>
        <table class="w-full bg-gray-800 rounded p-4">
            <thead><tr><th class="p-2 text-left">Client ID</th><th class="p-2 text-left">Last Sync</th></tr></thead>
            <tbody id="device-table"></tbody>
        </table>
        <script>
            fetch('/api/admin/devices')
                .then(res => {
                    if (!res.ok) throw new Error('Network response was not ok');
                    return res.json();
                })
                .then(data => {
                    const tbody = document.getElementById('device-table');
                    tbody.innerHTML = '';
                    data.forEach(d => {
                        tbody.innerHTML += `<tr><td class="p-2">${d.hw_id || 'Unknown'}</td><td class="p-2">${d.last_sync || 'N/A'}</td></tr>`;
                    });
                })
                .catch(err => console.error("Fetch error:", err));
        </script>
    </body>
    </html>
    """)

@app.route("/api/admin/devices")
def get_devices():
    if not supabase:
        return jsonify({"error": "Supabase not configured"}), 500
    try:
        # Fetching from the table
        response = supabase.table("clients_registry").select("*").execute()
        return jsonify(response.data)
    except Exception as e:
        logger.error(f"Supabase query failed: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run()