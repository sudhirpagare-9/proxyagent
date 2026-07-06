import os
import json
import io
import csv
from datetime import datetime
from flask import Flask, render_template_string, Response, request, jsonify

app = Flask(__name__)

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
        
        <!-- Header -->
        <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-8">
            <h1 class="text-3xl font-bold text-indigo-400 flex items-center gap-3">☁️ Advanced AI Proxy Token Matrix</h1>
            <a href="/api/download-csv" class="bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-semibold px-4 py-2.5 rounded-xl border border-indigo-400/20 shadow-md transition-all">📥 Export History (.CSV)</a>
        </div>

        <!-- Hardware Device Authorization Registry Control Section -->
        <div class="bg-[#1c2541] rounded-xl border border-gray-700 shadow-lg p-6 mb-8">
            <h2 class="text-xl font-bold text-indigo-300 mb-4">🛡️ Hardware Device Authorization Registry</h2>
            <div class="overflow-x-auto">
                <table class="w-full text-left text-sm" style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr class="bg-[#111a36] text-gray-400 uppercase text-xs tracking-wider border-b border-gray-700">
                            <th style="padding: 12px; text-align: left;" class="p-3">Device Hostname</th>
                            <th style="padding: 12px; text-align: left;" class="p-3">MAC Address</th>
                            <th style="padding: 12px; text-align: left;" class="p-3">Last Known IP</th>
                            <th style="padding: 12px; text-align: left;" class="p-3">Authorization Status</th>
                            <th style="padding: 12px; text-align: right;" class="p-3 text-right">Actions Control Menu</th>
                        </tr>
                    </thead>
                    <tbody id="admin-device-rows">
                        <tr><td colspan="5" style="padding: 20px; text-align: center;" class="p-3 text-center text-gray-500">Querying terminal nodes framework...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Granular LLM Usage Metrics Table View -->
        <div class="bg-[#1c2541] rounded-xl border border-gray-700 shadow-lg overflow-hidden">
            <div class="p-6 border-b border-gray-700">
                <h2 class="text-lg font-semibold text-gray-300">Granular LLM Usage Metrics</h2>
            </div>
            <div class="overflow-x-auto overflow-y-auto max-h-[400px]">
                <table class="w-full text-left border-collapse" style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr class="bg-[#111a36] text-gray-400 text-xs uppercase tracking-wider border-b border-gray-700 sticky top-0 z-10">
                            <th style="padding: 12px; text-align: left; background-color: #111a36;" class="p-4">Timestamp</th>
                            <th style="padding: 12px; text-align: left; background-color: #111a36;" class="p-4">Client Device</th>
                            <th style="padding: 12px; text-align: left; background-color: #111a36;" class="p-4">Source Application</th>
                            <th style="padding: 12px; text-align: left; background-color: #111a36;" class="p-4">Model Name</th>
                            <th style="padding: 12px; text-align: left; background-color: #111a36;" class="p-4">Version</th>
                            <th style="padding: 12px; text-align: left; background-color: #111a36;" class="p-4">Thinking Level</th>
                            <th style="padding: 12px; text-align: left; background-color: #111a36;" class="p-4">Input Tokens</th>
                            <th style="padding: 12px; text-align: left; background-color: #111a36;" class="p-4">Output Tokens</th>
                            <th style="padding: 12px; text-align: left; background-color: #111a36;" class="p-4">Subscription</th>
                        </tr>
                    </thead>
                    <tbody id="db-traffic-rows">
                        <tr><td colspan="9" style="padding: 20px; text-align: center;" class="p-4 text-center text-gray-500">Connecting to telemetry storage...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        async function fetchDevices() {
            try {
                const r = await fetch('/api/admin/devices');
                const devices = await r.json();
                const tbody = document.getElementById("admin-device-rows");
                
                if (devices.error) {
                    tbody.innerHTML = `<tr><td colspan="5" style="padding: 16px; text-align: center; color: #f87171;">⚠️ Database Query Interruption: \${devices.message}</td></tr>`;
                    return;
                }
                
                tbody.innerHTML = "";
                if (devices.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="5" style="padding: 16px; text-align: center; color: #9ca3af;">No client machines profiled yet. Pending node requests will appear here automatically.</td></tr>`;
                    return;
                }

                devices.forEach(d => {
                    let statusBadge = `<span class="px-2 py-0.5 rounded text-xs bg-yellow-900/50 text-yellow-300 border border-yellow-700">PENDING APPROVAL</span>`;
                    if (d.status === 'APPROVED') statusBadge = `<span class="px-2 py-0.5 rounded text-xs bg-emerald-900/50 text-emerald-300 border border-emerald-700">APPROVED</span>`;
                    if (d.status === 'BLOCKED') statusBadge = `<span class="px-2 py-0.5 rounded text-xs bg-red-900/50 text-red-300 border border-red-700">BLOCKED</span>`;

                    tbody.innerHTML += `
                        <tr class="border-b border-gray-800 hover:bg-[#111a36]/30">
                            <td style="padding: 12px;" class="p-3 font-mono font-bold">\${d.hostname}</td>
                            <td style="padding: 12px;" class="p-3 font-mono text-gray-400">\${d.mac_address}</td>
                            <td style="padding: 12px;" class="p-3 font-mono text-indigo-300">\${d.ip_address || 'N/A'}</td>
                            <td style="padding: 12px;" class="p-3">\${statusBadge}</td>
                            <td style="padding: 12px; text-align: right;" class="p-3 text-right space-x-2">
                                <button onclick="updateDevice('\${d.hw_id}', 'APPROVED')" class="bg-emerald-600 hover:bg-emerald-500 text-xs px-2.5 py-1 rounded font-semibold text-white transition-all">Approve</button>
                                <button onclick="updateDevice('\${d.hw_id}', 'BLOCKED')" class="bg-amber-600 hover:bg-amber-500 text-xs px-2.5 py-1 rounded font-semibold text-white transition-all">Block</button>
                                <button onclick="deleteDevice('\${d.hw_id}')" class="bg-red-600 hover:bg-red-500 text-xs px-2.5 py-1 rounded font-semibold text-white transition-all">Delete</button>
                            </td>
                        </tr>
                    `;
                });
            } catch(e) { 
                console.error("JSON UI Stream parsing exception thrown:", e); 
            }
        }

        async function updateDevice(hw_id, status) {
            await fetch('/api/admin/device/update', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ hw_id, status })
            });
            fetchDevices();
            fetchLogs();
        }

        async function deleteDevice(hw_id) {
            if (!confirm("Are you sure you want to completely remove this node profile from the registry?")) return;
            await fetch('/api/admin/device/delete', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ hw_id })
            });
            fetchDevices();
        }

        async function fetchLogs() {
            try {
                const response = await fetch('/api/get-logs');
                const logs = await response.json();
                const tbody = document.getElementById("db-traffic-rows");
                
                if (logs.error) {
                    tbody.innerHTML = `<tr><td colspan="9" style="padding: 16px; text-align: center; color: #f87171;">⚠️ Telemetry Processing Interruption: \${logs.error}</td></tr>`;
                    return;
                }
                
                tbody.innerHTML = "";
                if (logs.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="9" style="padding: 16px; text-align: center; color: #9ca3af;">Waiting for local client proxy activations...</td></tr>`;
                    return;
                }

                // Cleaned interpolation loops: Removed the broken backslash escape markers completely
                logs.forEach(log => {
                    let timeStr = "N/A";
                    if (log.created_at) {
                        const d = new Date(log.created_at);
                        timeStr = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true }).toLowerCase();
                    }

                    tbody.innerHTML += `
                        <tr class="border-b border-gray-800 text-sm hover:bg-[#111a36]/50 transition-colors">
                            <td style="padding: 16px;" class="p-4 text-gray-400 font-mono">\${timeStr}</td>
                            <td style="padding: 16px;" class="p-4 font-bold text-emerald-400 font-mono">\${log.client_id || 'Unknown'}</td>
                            <td style="padding: 16px;" class="p-4 text-sky-400 font-medium font-mono">\${log.app_name || 'Generic HTTP App'}</td>
                            <td style="padding: 16px;" class="p-4 font-semibold text-indigo-300">\${log.model_name || 'N/A'}</td>
                            <td style="padding: 16px;" class="p-4 text-gray-300 font-mono">\${log.version || 'N/A'}</td>
                            <td style="padding: 16px;" class="p-4"><span class="px-2 py-1 text-xs rounded bg-purple-900/50 text-purple-300 border border-purple-700">\${log.thinking_level || 'None'}</span></td>
                            <td style="padding: 16px;" class="p-4 font-mono text-emerald-400">\${log.input_tokens ?? 0}</td>
                            <td style="padding: 16px;" class="p-4 font-mono text-orange-400">\${log.output_tokens ?? 0}</td>
                            <td style="padding: 16px;" class="p-4 text-gray-400 text-xs">\${log.subscription_details || 'N/A'}</td>
                        </tr>
                    `;
                });
            } catch (err) { 
                console.error("Traffic render thread runtime execution failure:", err); 
            }
        }

        fetchDevices();
        fetchLogs();
        setInterval(fetchDevices, 4000); 
        setInterval(fetchLogs, 4000);    
    </script>
</body>
</html>
"""

@app.route("/")
def home():
    return render_template_string(DASHBOARD_TEMPLATE)

@app.route("/api/ingest", methods=["POST"])
def ingest_log():
    if not supabase:
        return jsonify({"error": "Database context engine offline."}), 500
    
    payload = request.json
    if not payload:
        return "Missing payload data layer.", 400

    hw_id = payload.get("hw_id", "HW-UNKNOWN")
    hostname = payload.get("hostname", "Unknown-Host")
    mac_address = payload.get("mac_address", "00:00:00:00:00:00")
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(',')[0].strip()

    try:
        check = supabase.table("clients_registry").select("*").eq("hw_id", hw_id).execute()
        device_status = "PENDING"
        
        if not check.data:
            new_device = {
                "hw_id": hw_id, "hostname": hostname, 
                "mac_address": mac_address, "ip_address": client_ip, 
                "status": "PENDING", "client_name": hostname
            }
            supabase.table("clients_registry").insert(new_device).execute()
        else:
            device_status = check.data[0].get("status", "PENDING")
        
        if device_status == "BLOCKED":
            return "Access Privileges Suspended by Dashboard Admin Control.", 403
            
        if device_status == "PENDING":
            return "Registration pending admin approval.", 202

        # Fixed relational mapping constraint layout: Pass exact primary hw_id keys directly into client_id columns to avoid DB Error 400
        log_entry = {
            "model_name": payload.get("model_name"),
            "version": payload.get("version"),
            "thinking_level": payload.get("thinking_level"),
            "input_tokens": payload.get("input_tokens"),
            "output_tokens": payload.get("output_tokens"),
            "balance_tokens": payload.get("balance_tokens"),
            "subscription_details": payload.get("subscription_details"),
            "client_id": hw_id, 
            "app_name": payload.get("app_name", "Generic HTTP App")
        }
        supabase.table("network_logs").insert(log_entry).execute()
        return "Log Telemetry Sync Success", 200

    except Exception as e:
        print(f"[Ingest Server Crash Avoided]: {e}")
        return f"Ingest Pipeline Exception Interruption: {str(e)}", 400

@app.route("/api/admin/devices")
def admin_get_devices():
    if not supabase: return jsonify([])
    try:
        res = supabase.table("clients_registry").select("*").order("created_at", desc=True).execute()
        return jsonify(res.data or [])
    except Exception as e:
        return jsonify({"error": "missing_table", "message": str(e)})

@app.route("/api/admin/device/update", methods=["POST"])
def admin_update_device():
    if not supabase: return "Error", 500
    try:
        data = request.json
        supabase.table("clients_registry").update({"status": data["status"]}).eq("hw_id", data["hw_id"]).execute()
        return "OK", 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/admin/device/delete", methods=["POST"])
def admin_delete_device():
    if not supabase: return "Error", 500
    try:
        data = request.json
        supabase.table("clients_registry").delete().eq("hw_id", data["hw_id"]).execute()
        return "OK", 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/get-logs")
def get_logs():
    if not supabase: return jsonify([])
    try:
        # Relational Mapping Layer: Fetch metrics logs and map names on the fly
        response = supabase.table("network_logs").select("*").order("created_at", desc=True).limit(100).execute()
        logs = response.data or []
        
        devices_res = supabase.table("clients_registry").select("hw_id", "client_name", "hostname").execute()
        devices = devices_res.data or []
        device_map = {}
        for d in devices:
            friendly_name = d.get("client_name") or d.get("hostname") or d.get("hw_id")
            if not friendly_name or str(friendly_name).lower() == "unknown":
                friendly_name = d.get("hostname") or d.get("hw_id")
            device_map[d["hw_id"]] = friendly_name

        for log in logs:
            cid = log.get("client_id")
            if cid in device_map:
                log["client_id"] = device_map[cid]

        return Response(json.dumps(logs), mimetype="application/json")
    except Exception as e:
        return Response(json.dumps({"error": f"Schema match failure: {str(e)}"}), mimetype="application/json")

@app.route("/api/download-csv")
def download_csv():
    if not supabase: return "Database link error.", 500
    try:
        response = supabase.table("network_logs").select("*").order("created_at", desc=True).execute()
        records = response.data or []
        if not records: return "No records data generated yet.", 404
            
        si = io.StringIO()
        writer = csv.DictWriter(si, fieldnames=records[0].keys())
        writer.writeheader()
        writer.writerows(records)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = Response(si.getvalue(), mimetype="text/csv")
        output.headers["Content-Disposition"] = f"attachment; filename=proxy_history_{timestamp}.csv"
        return output
    except Exception as e:
        return f"Report error: {str(e)}", 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(host="0.0.0.0", port=port, debug=False)