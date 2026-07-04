import json
import time
from flask import Flask, render_template_string, request, Response

app = Flask(__name__)

# Base system memory registry dictionary state
latest_event = {
    "model": "Awaiting...",
    "prompt_score": "-",
    "reasoning": "0",
    "client": "No traffic captured yet",
    "tokens": "Awaiting live data..."
}

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Live Proxy Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-[#0b1329] text-gray-100 font-sans min-h-screen p-8">
    <div class="max-w-5xl mx-auto">
        <h1 class="text-3xl font-bold mb-8 text-indigo-400 flex items-center gap-3">
            🤖 Local AI Proxy Analytics Dashboard
        </h1>
        
        <!-- Metrics Panel Grid -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div class="bg-[#1c2541] p-6 rounded-xl border border-gray-700 shadow-lg">
                <p class="text-xs font-semibold text-gray-400 uppercase tracking-wider">Active Model</p>
                <p id="model" class="text-2xl font-bold mt-2 text-white truncate">Awaiting...</p>
            </div>
            <div class="bg-[#1c2541] p-6 rounded-xl border border-gray-700 shadow-lg">
                <p class="text-xs font-semibold text-gray-400 uppercase tracking-wider">Prompt Score</p>
                <p id="prompt_score" class="text-2xl font-bold mt-2 text-emerald-400">-</p>
            </div>
            <div class="bg-[#1c2541] p-6 rounded-xl border border-gray-700 shadow-lg">
                <p class="text-xs font-semibold text-gray-400 uppercase tracking-wider">Reasoning Status</p>
                <p id="reasoning" class="text-2xl font-bold mt-2 text-blue-400">0</p>
            </div>
        </div>

        <!-- Interception Log Board -->
        <div class="bg-[#1c2541] rounded-xl border border-gray-700 shadow-lg overflow-hidden">
            <div class="p-6 border-b border-gray-700">
                <h2 class="text-lg font-semibold text-gray-300">Live Traffic Interception Logs</h2>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="bg-[#111a36] text-gray-400 text-xs uppercase tracking-wider border-b border-gray-700">
                            <th class="p-4">Client IP / Host</th>
                            <th class="p-4">Intercepted Model</th>
                            <th class="p-4">Tokens / Content Status</th>
                        </tr>
                    </thead>
                    <tbody id="traffic-rows">
                        <tr class="border-b border-gray-800 text-sm">
                            <td id="client" class="p-4 text-gray-400">Waiting...</td>
                            <td id="table_model" class="p-4 font-mono text-indigo-300">Awaiting...</td>
                            <td id="tokens" class="p-4 text-gray-400 font-medium">Awaiting live data...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Active Stream Listener to handle push notifications perfectly without refreshing -->
    <script>
        const eventSource = new EventSource("/stream");
        eventSource.onmessage = function(event) {
            const data = JSON.parse(event.data);
            if (data.model !== "Awaiting...") {
                document.getElementById("model").innerText = data.model;
                document.getElementById("table_model").innerText = data.model;
                document.getElementById("prompt_score").innerText = data.prompt_score;
                document.getElementById("reasoning").innerText = data.reasoning;
                document.getElementById("client").innerText = data.client;
                document.getElementById("tokens").innerText = data.tokens;
            }
        };
    </script>
</body>
</html>
"""

@app.route("/")
def home():
    return render_template_string(DASHBOARD_TEMPLATE)

@app.route("/api/ingest-event", methods=["POST"])
def ingest_event():
    global latest_event
    try:
        data = request.get_json(force=True)
        latest_event = {
            "model": data.get("model", "Unknown Agent"),
            "prompt_score": data.get("prompt_score", "Pass"),
            "reasoning": str(data.get("reasoning", "Active")),
            "client": data.get("client", request.remote_addr),
            "tokens": data.get("tokens", "Data packet processed")
        }
        print(f"[Dashboard Update Log] Active telemetry payload logged: {latest_event}")
        return {"status": "success"}, 200
    except Exception as e:
        return {"status": "error", "message": str(e)}, 400

@app.route("/stream")
def stream():
    def event_generator():
        while True:
            json_data = json.dumps(latest_event)
            yield f"data: {json_data}\\n\\n"
            time.sleep(1)
    return Response(event_generator(), mimetype="text/event-stream")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=False)