# server_backend.py (Deploy this on your Render dashboard)
import os
from flask import Flask, request, jsonify
from supabase import create_client

app = Flask(__name__)
# Load keys from Render Environment Variables (Do NOT hardcode)
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])

@app.route("/api/ingest", methods=["POST"])
def ingest_data():
    data = request.json
    # Ensure RLS is enabled in Supabase to keep this secure
    supabase.table("clients_registry").insert(data).execute()
    return jsonify({"status": "success"}), 200

@app.route("/api/admin/devices")
def get_devices():
    # Only return data from the table
    return jsonify(supabase.table("clients_registry").select("*").execute().data)

if __name__ == "__main__":
    app.run(port=5000)