import os
from flask import Flask, jsonify, render_template_string
from supabase import create_client

app = Flask(__name__)

# Initialize Supabase using environment variables set on Render
url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")
supabase = create_client(url, key)

@app.route("/")
def index():
    # Serve the frontend
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
                .then(res => res.json())
                .then(data => {
                    const tbody = document.getElementById('device-table');
                    data.forEach(d => {
                        tbody.innerHTML += `<tr><td class="p-2">${d.hw_id}</td><td class="p-2">${d.last_sync || 'N/A'}</td></tr>`;
                    });
                })
                .catch(err => console.error("Fetch error:", err));
        </script>
    </body>
    </html>
    """)

@app.route("/api/admin/devices")
def get_devices():
    try:
        # Fetch data from your 'clients_registry' table
        response = supabase.table("clients_registry").select("*").execute()
        return jsonify(response.data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run()