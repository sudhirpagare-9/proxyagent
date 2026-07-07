# dashboard.py (Update your existing file with this)
from flask import Flask, render_template_string
import requests

app = Flask(__name__)

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<script src="https://cdn.tailwindcss.com"></script>
<body class="bg-gray-900 text-white p-10">
    <h1 class="text-2xl font-bold mb-5">Proxy Control Center</h1>
    <table class="w-full bg-gray-800 rounded">
        <tbody id="device-list"></tbody>
    </table>
    <script>
        fetch('/api/admin/devices')
            .then(res => res.json())
            .then(data => {
                const list = document.getElementById('device-list');
                data.forEach(d => list.innerHTML += `<tr><td class="p-2">${d.hw_id}</td></tr>`);
            });
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)