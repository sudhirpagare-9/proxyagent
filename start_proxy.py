import os
import sys
from mitmproxy import http
from supabase import create_client

# Retrieve credentials from Environment Variables
url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")

if not url or not key:
    print("Error: SUPABASE_URL or SUPABASE_KEY not found in environment variables.")
    sys.exit(1)

supabase = create_client(url, key)

def request(flow: http.HTTPFlow):
    """
    Called when a client sends an HTTP request.
    """
    client_ip = flow.client_conn.ip_address
    target_host = flow.request.pretty_host
    
    # Prepare data for Supabase
    data = {
        "hw_id": client_ip, 
        "hostname": target_host,
        "ip_address": client_ip,
        "status": "ACTIVE",
        "client_name": "Proxy_Client"
    }
    
    try:
        # Upsert: Updates the record if hw_id matches, otherwise inserts a new one
        supabase.table("clients_registry").upsert(data).execute()
    except Exception as e:
        print(f"Supabase update error: {e}")

# This script is intended to be run via: mitmdump -s start_proxy.py