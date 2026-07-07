import os
from flask import Flask, jsonify, render_template_string
from supabase import create_client

app = Flask(__name__)

# Fetch variables directly from Environment
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

@app.route("/")
def home():
    # If connection fails, this will still render the shell
    return render_template_string("""
    <!DOCTYPE html>
    <html class="bg-[#0b1329] text-white">
    <head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="p-10">
        <h1 class="text-2xl font-bold">Proxy Control Center</h1>
        <div id="status" class="mt-4 p-4 bg-gray-800 rounded">Loading data...</div>
        <table class="w-full mt-4">
            <thead class="bg-gray-700"><tr><th class="p-2">Client ID</th><th class="p-2">Last Sync</th></tr></thead>
            <tbody id="data-body"></tbody>
        </table>
        <script>
            fetch('/api/admin/devices')
                .then(r => r.json())
                .then(data => {
                    if(data.error) document.getElementById('status').innerText = "Error: " + data.error;
                    else document.getElementById('status').innerText = "Connected";
                    // Populate data-body here
                });
        </script>
    </body>
    </html>
    """)

@app.route("/api/admin/devices")
def admin_get_devices():
    if not SUPABASE_URL or not SUPABASE_KEY:
        return jsonify({"error": "Supabase keys missing in Environment Variables"}), 500
    
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        # Ensure 'clients_registry' matches your table name exactly
        response = supabase.table("clients_registry").select("*").execute()
        return jsonify(response.data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)