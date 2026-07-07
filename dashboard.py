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
    <head>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="p-8">
        <h1 class="text-2xl font-bold mb-4">Proxy Control Center</h1>
        <div class="overflow-x-auto bg-gray-800 rounded p-4">
            <table class="w-full text-left">
                <thead>
                    <tr class="text-gray-400 border-b border-gray-700">
                        <th class="p-2">HW ID</th>
                        <th class="p-2">Hostname</th>
                        <th class="p-2">mac_address</th>
                        <th class="p-2">IP Address</th>
                        <th class="p-2">Status</th>
                        <th class="p-2">client_name</th>
						<th class="p-2">created_at</th>
                    </tr>
                </thead>
                <tbody id="device-table">
                    <tr><td colspan="4" class="p-4 text-center text-gray-500">Loading data...</td></tr>
                </tbody>
            </table>
        </div>
        <script>
            fetch('/api/admin/devices')
                .then(res => res.json())
                .then(data => {
                    const tbody = document.getElementById('device-table');
                    tbody.innerHTML = '';
                    
                    if (!data || data.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="4" class="p-4 text-center text-gray-500">No records found</td></tr>';
                        return;
                    }

                    data.forEach(d => {
                        tbody.innerHTML += `
                            <tr class="border-b border-gray-700">
                                <td class="p-2">${d.hw_id || 'N/A'}</td>
                                <td class="p-2">${d.hostname || 'N/A'}</td>
                                <td class="p-2">${d.mac_address || 'N/A'}</td>
                                <td class="p-2">${d.ip_address || 'N/A'}</td>
                                <td class="p-2 text-green-400">${d.status || 'N/A'}</td>
                                <td class="p-2">${d.client_name || 'N/A'}</td>
								<td class="p-2">${d.created_at || 'N/A'}</td>
                            </tr>`;
                    });
                })
                .catch(err => {
                    console.error("Fetch error:", err);
                    document.getElementById('device-table').innerHTML = '<tr><td colspan="4" class="p-4 text-red-500 text-center">Error loading data</td></tr>';
                });
        </script>
    </body>
    </html>
    """)

@app.route("/api/admin/devices")
def get_devices():
    if not supabase:
        return jsonify({"error": "Supabase not configured"}), 500
    try:
        # Fetching all columns from the table
        response = supabase.table("clients_registry").select("*").execute()
        return jsonify(response.data)
    except Exception as e:
        logger.error(f"Supabase query failed: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run()