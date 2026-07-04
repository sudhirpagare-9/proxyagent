import os
from flask import Flask, render_template_string

app = Flask(__name__)

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
        <div class="bg-[#1c2541] rounded-xl border border-gray-700 p-6 shadow-lg">
            <h2 class="text-lg font-semibold text-gray-300 mb-4">Live Logs</h2>
            <p class="text-emerald-400 font-mono">✓ Network Dashboard Routing Engine Online</p>
        </div>
    </div>
</body>
</html>
"""

@app.route("/")
def home():
    return render_template_string(DASHBOARD_TEMPLATE)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(host="0.0.0.0", port=port, debug=False)