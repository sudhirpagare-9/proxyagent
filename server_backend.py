# server_backend.py (Deploy to Render/Railway)
import os
from flask import Flask, request, jsonify
from supabase import create_client

app = Flask(__name__)
# Load these from your Environment Variables on the Server, NOT in code
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])

@app.route("/api/ingest", methods=["POST"])
def ingest():
    data = request.json
    # Basic Validation to prevent SQL injection/garbage data
    if "hw_id" not in data:
        return jsonify({"error": "Unauthorized"}), 403
        
    try:
        # Supabase RLS (Row Level Security) should be enabled on your table
        supabase.table("client_logs").insert(data).execute()
        return jsonify({"status": "OK"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(port=5000)