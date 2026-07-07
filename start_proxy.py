import os
import sys
import subprocess
import uuid
import time
from mitmproxy import http
from supabase import create_client

# Load Credentials
url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")
supabase = create_client(url, key)

# --- ID GENERATION LOGIC ---
def get_unique_id():
    if os.path.exists("client_id.txt"):
        with open("client_id.txt", "r") as f:
            return f.read().strip()
    
    # Fallback: BIOS serial -> MAC -> UUID
    try: 
        cmd = "wmic bios get serialnumber"
        output = subprocess.check_output(cmd, shell=True).decode().split('\n')[1].strip()
        if output and output.lower() not in ["to be filled by o.e.m.", "system serial number"]:
            return output
    except: pass
    
    return str(uuid.getnode())

MY_HW_ID = get_unique_id()
if not os.path.exists("client_id.txt"):
    with open("client_id.txt", "w") as f: f.write(MY_HW_ID)

# --- STATUS CACHING ---
last_check = 0
is_allowed = False

def check_approval_status():
    global last_check, is_allowed
    # Check DB every 60 seconds
    if time.time() - last_check > 60:
        try:
            response = supabase.table("clients_registry").select("status").eq("hw_id", MY_HW_ID).single().execute()
            is_allowed = (response.data.get("status") == "approved")
        except:
            is_allowed = False
        last_check = time.time()
    return is_allowed

def request(flow: http.HTTPFlow):
    if not check_approval_status():
        flow.kill()
        return

    # If approved, log traffic
    try:
        # Corrected: peername[0] gets the IP
        client_ip = flow.client_conn.peername[0]
        
        data = {
            "hw_id": MY_HW_ID, 
            "hostname": flow.request.pretty_host, 
            "status": "approved",
            "ip_address": client_ip
        }
        supabase.table("clients_registry").upsert(data).execute()
    except Exception as e:
        print(f"Sync error: {e}")