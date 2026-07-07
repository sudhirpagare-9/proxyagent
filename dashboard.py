import os
from flask import Flask, jsonify, render_template_string
from supabase import create_client

app = Flask(__name__)

# Initialize Supabase
url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")
supabase = create_client(url, key)

@app.route("/")
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html class="bg-gray-900 text-white">
    <head><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="p-8">
        <h1 class="text-2xl font-bold mb-4">Proxy Control Center</h1>
        <div class="overflow-x-auto">
            <table class="w-full bg-gray-800 rounded p-4 text-sm">
                <thead>
                    <tr class="text-gray-400 border-b border-gray-700">
                        <th class="p-2 text-left">HW ID</th>
                        <th class="p-2 text-left">Hostname</th>
                        <th class="p-2 text-left">IP Address</th>
                        <th class="p-2 text-left">Status</th>
                    </tr>
                </thead>
                <tbody id="device-table">
                    <tr><td colspan="4" class="p-4 text-center">Loading...</td></tr>
                </tbody>
            </table>
        </div>
        <script>
            // Use an absolute path or relative path carefully
            fetch('/api/admin/devices')
                .then(res => {
                    if (!res.ok) throw new Error('HTTP ' + res.status);
                    return res.json();
                })
                .then(data => {
                    const tbody = document.getElementById('device-table');
                    tbody.innerHTML = '';
                    if (data.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="4" class="p-4 text-center">No records found</td></tr>';
                    } else {
                        data.forEach(d => {
                            tbody.innerHTML += `
                                <tr class="border-b border-gray-700">
                                    <td class="p-2">${d.hw_id || 'N/A'}</td>
                                    <td class="p-2">${d.hostname || 'N/A'}</td>
                                    <td class="p-2">${d.ip_address || 'N/A'}</td>
                                    <td class="p-2 text-green-400">${d.status || 'N/A'}</td>
                                </tr>`;
                        });
                    }
                })
                .catch(err => {
                    document.getElementById('device-table').innerHTML = 
                        `<tr><td colspan="4" class="p-4 text-center text-red-500">Error: ${err.message}</td></tr>`;
                    console.error("Fetch error:", err);
                });
        </script>
    </body>
    </html>
    """)

@app.route("/api/admin/devices")
def get_devices():
    try:
        # Ensure 'clients_registry' matches your table name exactly
        response = supabase.table("clients_registry").select("*").execute()
        return jsonify(response.data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)