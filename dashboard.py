import os
import json
import io
import csv
from datetime import datetime
from flask import Flask, render_template_string, Response

app = Flask(__name__)

# Fetch production environment configurations safely
SUPABASE_URL = os.environ.get("SUPABASE_URL") or "https://qwsnkbpsumqobrqkqpht.supabase.co"
SUPABASE_KEY = os.environ.get("SUPABASE_KEY") or "sb_publishable_IPKGvB9I6G7Ix0q2kkpucw_8JdGDaHh"

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

# Injecting the environment credentials safely straight into the client script block below
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Cloud Proxy Analytics</title>
    <!-- Tailwind CSS Engine -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- Core Supabase Client Library Bundle for WebSockets -->
    <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>
</head>
<body class="bg-[#0b1329] text-gray-100 font-sans min-h-screen p-8">
    <div class="max-w-7xl mx-auto">
        
        <!-- Header Section with Integrated Download Button -->
        <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-8">
            <h1 class="text-3xl font-bold text-indigo-400 flex items-center gap-3">
                ☁️ Advanced AI Proxy Token Matrix
            </h1>
            <a href="/api/download-csv" 
               class="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-semibold px-4 py-2.5 rounded-xl border border-indigo-400/20 shadow-md transition-all transform active:scale-95">
                📥 Export History (.CSV)
            </a>
        </div>
        
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

        <!-- Granular LLM Usage Metrics Table View with Custom Scroll Container -->
        <div class="bg-[#1c2541] rounded-xl border border-gray-700 shadow-lg overflow-hidden">
            <div class="p-6 border-b border-gray-700">
                <h2 class="text-lg font-semibold text-gray-300">Granular LLM Usage Metrics</h2>
            </div>
            <!-- FIXED SCROLL CONTAINER: Prevents page from overflowing vertically -->
            <div class="overflow-x-auto overflow-y-auto max-h-[520px] custom-scrollbar">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <!-- Sticky header configuration so columns remain visible while scrolling -->
                        <tr class="bg-[#111a36] text-gray-400 text-xs uppercase tracking-wider border-b border-gray-700 sticky top-0 z-10 shadow-sm">
                            <th class="p-4 bg-[#111a36]">Timestamp</th>
                            <th class="p-4 bg-[#111a36]">Model Name</th>
                            <th class="p-4 bg-[#111a36]">Version</th>
                            <th class="p-4 bg-[#111a36]">Thinking Level</th>
                            <th class="p-4 bg-[#111a36]">Input Tokens</th>
                            <th class="p-4 bg-[#111a36]">Output Tokens</th>
                            <th class="p-4 bg-[#111a36]">Balance Tokens</th>
                            <th class="p-4 bg-[#111a36]">Subscription</th>
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

    <!-- Scrollbar styling inject to keep it clean looking -->
    <style>
        .custom-scrollbar::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
            background: #111a36;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
            background: #312e81;
            border-radius: 4px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
            background: #4338ca;
        }
    </style>

    <script>
        // Mount client details using variables safely populated by Flask backend variables
        const url = "{{ supabase_url }}";
        const key = "{{ supabase_key }}";
        
        if (!url || !key) {
            document.getElementById("db-traffic-rows").innerHTML = `<tr><td colspan="8" class="p-4 text-center text-gray-400 font-mono">Environment URL keys missing on host settings.</td></tr>`;
        }

        const supabaseClient = supabase.createClient(url, key);
        let logsCache = [];

        function renderRows() {
            const tbody = document.getElementById("db-traffic-rows");
            document.getElementById("total-count").innerText = logsCache.length;

            if (logsCache.length === 0) {
                tbody.innerHTML = `<tr><td colspan="8" class="p-4 text-center text-gray-400 font-mono">✓ Database connected. Waiting for local proxy streams...</td></tr>`;
                return;
            }

            tbody.innerHTML = "";
            logsCache.forEach(log => {
                const row = document.createElement("tr");
                row.className = "border-b border-gray-800 text-sm hover:bg-[#111a36]/50 transition-colors";
                
                let timeStr = "N/A";
                if (log.created_at) {
                    const d = new Date(log.created_at);
                    timeStr = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true }).toLowerCase() + ' am';
                }

                row.innerHTML = `
                    <td class="p-4 text-gray-400 font-mono">${timeStr}</td>
                    <td class="p-4 font-semibold text-indigo-300">${log.model_name || 'N/A'}</td>
                    <td class="p-4 text-gray-300 font-mono">${log.version || 'N/A'}</td>
                    <td class="p-4"><span class="px-2 py-1 text-xs rounded bg-purple-900/50 text-purple-300 border border-purple-700">${log.thinking_level || 'None'}</span></td>
                    <td class="p-4 font-mono text-emerald-400">${log.input_tokens ?? 0}</td>
                    <td class="p-4 font-mono text-orange-400">${log.output_tokens ?? 0}</td>
                    <td class="p-4 font-mono text-blue-400">${log.balance_tokens ?? 0}</td>
                    <td class="p-4 text-gray-400 text-xs">${log.subscription_details || 'N/A'}</td>
                `;
                tbody.appendChild(row);
            });
        }

        // Hydrate baseline rows instantly on page mount
        async function fetchInitialLogs() {
            try {
                const response = await fetch('/api/get-logs');
                const initialLogs = await response.json();
                
                if (initialLogs.length === 1 && initialLogs[0].model_name === "System Status") {
                    logsCache = [];
                } else {
                    logsCache = initialLogs;
                }
                renderRows();
            } catch (err) {
                console.error("Baseline extraction failure:", err);
            }
        }

        // Open live webhook socket channel pipeline directly to postgres modifications
        function listenToRealtimeLogs() {
            supabaseClient
                .channel('public_network_logs_changes')
                .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'network_logs' }, (payload) => {
                    console.log("[Live Event Stream] Appending row payload via webhook:", payload.new);
                    logsCache.unshift(payload.new);
                    renderRows();
                })
                .subscribe();
        }

        fetchInitialLogs().then(() => {
            listenToRealtimeLogs();
        });
    </script>
</body>
</html>
"""

@app.route("/")
def home():
    return render_template_string(DASHBOARD_TEMPLATE, supabase_url=SUPABASE_URL, supabase_key=SUPABASE_KEY)

@app.route("/api/get-logs")
def get_logs():
    if not supabase:
        return json.dumps([{"model_name": "System Status", "subscription_details": "Environment URL keys missing on host settings."}])
    try:
        # FIX: Explicitly sort by created_at descending directly in Supabase BEFORE limiting the dataset to 100 entries.
        response = supabase.table("network_logs")\
                           .select("*")\
                           .order("created_at", descending=True)\
                           .limit(100)\
                           .execute()
        
        data = response.data or []
        if not data:
            return json.dumps([{"model_name": "System Status", "subscription_details": "✓ Database connected. Waiting for local proxy streams..."}])
        
        return json.dumps(data)
    except Exception as e:
        return json.dumps([{"model_name": "System Status", "subscription_details": f"Database Error: {str(e)}"}])

@app.route("/api/download-csv")
def download_csv():
    """
    Fetches the total historical proxy log volume from Supabase 
    and packages it directly into a dynamic CSV file download stream.
    """
    if not supabase:
        return "Database initialization error.", 500
        
    try:
        response = supabase.table("network_logs").select("*").order("created_at", descending=True).execute()
        records = response.data or []
        
        if not records:
            return "No data logged yet.", 404

        si = io.StringIO()
        headers = records[0].keys()
        writer = csv.DictWriter(si, fieldnames=headers)
        
        writer.writeheader()
        writer.writerows(records)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = Response(si.getvalue(), mimetype="text/csv")
        output.headers["Content-Disposition"] = f"attachment; filename=proxy_matrix_history_{timestamp}.csv"
        return output

    except Exception as e:
        return f"Failed to generate report generation asset: {str(e)}", 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(host="0.0.0.0", port=port, debug=False)