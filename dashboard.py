import os
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Load keys from Render Environment Variables
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

supabase = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        from supabase import create_client
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as e:
        print(f"Supabase Init Error: {e}")

@app.route("/")
def home():
    # Looks for 'templates/dashboard.html'
    return render_template("dashboard.html")

@app.route("/api/admin/devices")
def admin_get_devices():
    if not supabase: return jsonify([])
    res = supabase.table("clients_registry").select("*").execute()
    return jsonify(res.data or [])

@app.route("/api/admin/device/update", methods=["POST"])
def admin_update_device():
    data = request.json
    supabase.table("clients_registry").update({"status": data["status"]}).eq("hw_id", data["hw_id"]).execute()
    return "OK", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5050)))