import os
import json
from flask import Flask, render_template_string

app = Flask(__name__)

# Fetch production environment configurations safely
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

supabase = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        from supabase import create_client
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        print("[Production] Connected to live database instance.")
    except Exception as e:
        print(f"[Production Error] Client setup failed: {e}")
else:
    print("[Production Warning] Application running without active Supabase credentials.")

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
    <div class="max-w-7xl mx-auto">
        <h1 class="text-3xl font-bold mb-8 text-indigo-400 flex items-center gap-3">
            ☁️ Advanced AI Proxy Token Matrix
        </h1>
        
        <!-- Top Summary Metrics Cards (Preserved) -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div class="bg-[#1c2541] p-6 rounded-xl border border-gray-700 shadow-lg">
                <p class="text-xs font-semibold text-gray-400 uppercase tracking-wider">Active Status</p>
                <p class="text-2xl font-bold mt-2 text-emerald-400">Live & Protected</p>
            </div>
            <div class="bg-[#1c2541] p-6 rounded-xl border border-gray-700 shadow-lg">
                <p class="text-xs font-semibold text-gray-400 uppercase tracking-wider">Total Streams Intercepted</p>
                <p id="total-count" class="text-2xl font-bold mt-2 text-white">0</p>
            </div>
            <div class="bg-[#1c2541] p-6 rounded-xl border border-gray-700 shadow-lg">
                <p class="text-xs font-semibold text-gray-400 uppercase tracking-wider">Security Profile</p>
                <p class="text-2xl font-bold mt-2 text-blue-400">NIST / GDPR Framework</p>
            </div>
        </div>

        <!-- Granular LLM Usage Metrics Table View -->
        <div class="bg-[#1c2541] rounded-xl border border-gray-700 shadow-lg overflow-hidden">
            <div class="p-6 border-b border-gray-700">
                <h2 class="text-lg font-semibold text-gray-300">Granular LLM Usage Metrics</h2>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="bg-[#111a36] text-gray-400 text-xs uppercase tracking-wider border-b border-gray-700">
                            <th class="p-4">Timestamp</th>
                            <th class="p-4">Model Name</th>
                            <th class="p-4">Version</th>
                            <th class="p-4">Thinking Level</th>
                            <th class="p-4">Input Tokens</th>
                            <th class="p-4">Output Tokens</th>
                            <th class="p-4">Balance Tokens</th>
                            <th class="p-4">Subscription</th>
                        </tr>
                    </thead>
                    <tbody id="db-traffic-rows">
                        <tr>
                            <td colspan="8" class="p-4 text-center text-gray-500">Connecting to telemetry storage...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        async function fetchLatestLogs() {
            try {
                const response = await fetch('/api/get-logs');
                const logs = await response.json();
                const tbody = document.getElementById("db-traffic-rows");
                
                if (logs.length === 1 && logs[0].model_name === "System Status") {
                    document.getElementById("total-count").innerText = "0";
                    tbody.innerHTML = `<tr><td colspan="8" class="p-4 text-center text-gray-400 font-mono">${logs[0].subscription_details}</td></tr>`;
                    return;
                }
                
                document.getElementById("total-count").innerText = logs.length;
                tbody.innerHTML = "";
                
                logs.forEach(log => {
                    const row = document.createElement("tr");
                    row.className = "border-b border-gray-800 text-sm hover:bg-[#111a36]/50 transition-colors";
                    
                    let timeStr = "N/A";
                    if (log.created_at) {
                        const d = new Date(log.created_at);
                        timeStr = d.toLocaleTimeString();
                    }

                    row.innerHTML = `
                        <td class="p-4 text-gray-400 font-mono">${timeStr}</td>
                        <td class="p-4 font-semibold text-indigo-300">${log.model_name || 'N/A'}</td>
                        <td class="p-4 text-gray-300">${log.version || 'N/A'}</td>
                        <td class="p-4"><span class="px-2 py-1 text-xs rounded bg-purple-900/50 text-purple-300 border border-purple-700">${log.thinking_level || 'None'}</span></td>
                        <td class="p-4 font-mono text-emerald-400">${log.input_tokens ?? 0}</td>
                        <td class="p-4 font-mono text-orange-400">${log.output_tokens ?? 0}</td>
                        <td class="p-4 font-mono text-blue-400">${log.balance_tokens ?? 0}</td>
                        <td class="p-4 text-gray-400 text-xs">${log.subscription_details || 'N/A'}</td>
                    `;
                    tbody.appendChild(row);
                });
            } catch (err) {
                console.error("Dashboard engine long-polling error:", err);
            }
        }
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
    if not supabase:
        return json.dumps([{"model_name": "System Status", "subscription_details": "Environment URL keys missing on host settings."}])
    try:
        response = supabase.table("network_logs").select("*").limit(40).execute()
        data = response.data or []
        if not data:
            return json.dumps([{"model_name": "System Status", "subscription_details": "✓ Database connected. Waiting for local proxy streams..."}])
        data.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return json.dumps(data)
    except Exception as e:
        return json.dumps([{"model_name": "System Status", "subscription_details": f"Database Error: {str(e)}"}])

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(host="0.0.0.0", port=port, debug=False)