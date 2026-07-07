import threading
import time
import requests
import sys
import os

# --- Robust Check ---
def check_status(hw_id):
    """Checks if the user is authorized every 30s."""
    DASHBOARD_URL = "https://proxyagent-dashboard.onrender.com"
    while True:
        try:
            r = requests.get(f"{DASHBOARD_URL}/api/client/status/{hw_id}", timeout=5)
            if r.json().get("status") == "BLOCKED":
                print("Access Revoked by Admin.")
                os._exit(0) # Force shutdown
        except: 
            pass
        time.sleep(30)

# Start this in a background thread inside your App's __init__
# threading.Thread(target=check_status, args=(self.hw_id,), daemon=True).start()