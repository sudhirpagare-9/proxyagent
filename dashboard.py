import os
import time
import json
from flask import Flask, render_template_string, Response
from supabase import create_client, Client

app = Flask(__name__)

# Fetch environment configuration variables from Render settings securely
SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://your-project.supabase.co")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "your-anon-key")

# Initialize the Supabase Client connection engine
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Cloud Proxy Analytics</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-[#0b1329] text-gray-100 font-sans min-h-screen p-8">
    <div class="max-w-5xl mx-auto">
        <h1 class="text-3xl font-bold mb-8 text-indigo-400 flex items-center gap-3">
            ☁️ Cloud AI Proxy Analytics Dashboard
        </h1>
        
        <!-- Metrics Container Grid Layout -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div class="bg-[#1c2541] p-6 rounded-xl border border-gray-700 shadow-lg">
                <p class="text-xs font-semibold text-gray-400 uppercase tracking-wider">Active Status</p>
                <p id="status-card" class="text-2xl font-bold mt-2 text-emerald-400">Cloud Live</p>
            </div>
            <div class="bg-[#1c2541] p-6 rounded-xl border border-gray-700 shadow-lg">
                <p class="text-xs font-semibold text-gray-400 uppercase tracking-wider">Total Streams Intercepted</p>
                <p id="total-count" class="text-2xl font-bold mt-2 text-white">0</p>
            </div>
            <div class="bg-[#1c2541] p-6 rounded-xl border border-gray-700 shadow-lg">
                <p class="text-xs font-semibold text-gray-400 uppercase tracking-wider">Security Rule Profile</p>
                <p class="text-2xl font-bold mt-2 text-blue-400">NIST Compliant</p>
            </div>
        </div>

        <!-- Dynamic Database Log Matrix View -->
        <div class="bg-[#1c2541] rounded-xl border border-gray-700 shadow-lg overflow-hidden">
            <div class="p-6 border-b border-gray-700">
                <h2 class="text-lg font-semibold text-gray-300">Live Traffic Logs (Fetched from Cloud DB)</h2>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="bg-[#111a36] text-gray-400 text-xs uppercase tracking-wider border-b border-gray-700">
                            <th class="p-4">Timestamp</th>
                            <th class="p-4">Captured Model</th>
                            <th class="p-4">Status / Event Description</th>
                        </tr>
                    </thead>
                    <tbody id="db-traffic-rows">
                        <tr>
                            <td colspan="3" class="p-4 text-center text-gray-500">Awaiting incoming cloud data pipeline...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Long-Polling Script to Query Database updates dynamically without hard page reloads -->
    <script>
        async function fetchLatestLogs() {
            try {
                const response = await fetch('/api/get-logs');
                const logs = await response.json();
                
                const tbody = document.getElementById("db-traffic-rows");
                document.getElementById("total-count").innerText = logs.length;
                
                if (logs.length === 0) return;
                
                tbody.innerHTML = "";
                logs.forEach(log => {
                    const row = document.createElement("tr");
                    row.className = "border-b border-gray-800 text-sm hover:bg-[#111a36]/50 transition-colors";
                    row.innerHTML = `
                        <td class="p-4 text-gray-400 font-mono">${new Date(log.created_at).toLocaleTimeString()}</td>
                        <td class="p-4 font-semibold text-indigo-300">${log.model || 'Unknown'}</td>
                        <td class="p-4 text-gray-300">${log.tokens || 'Payload Captured'}</td>
                    `;
                    tbody.appendChild(row);
                });
            } catch (err) {
                console.error("Failed fetching latest telemetry logs from server:", err);
            }
        }
        
        // Polling interval cycle: every 3 seconds
        setInterval(fetchLatestLogs, 3000);
        fetchLatestLogs();
    </script>
</body>
</html>
"""

@app.route("/")
def home():
    return render_template_string(DASHBOARD_TEMPLATE)

@app.route("/api/get-logs")
def get_logs():
    try:
        # Pull down the latest 25 intercepted events stored in Supabase
        response = supabase.table("network_logs").select("*").order("created_at", descending=True).limit(25).execute()
        return json.dumps(response.data)
    except Exception as e:
        return json.dumps([])
    
    if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(host="0.0.0.0", port=port, debug=False)