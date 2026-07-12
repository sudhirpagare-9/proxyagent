import uuid
import socket
import requests
import json
import os
from cryptography.fernet import Fernet

SERVER_URL = "https://proxyagent-dashboard.onrender.com"
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
fernet = Fernet(ENCRYPTION_KEY.encode())

def get_metadata():
    try:
        # Get IP and Country
        geo = requests.get("https://ipapi.co/json/", timeout=5).json()
        return {
            "hostname": socket.gethostname(),
            "mac_address": str(uuid.getnode()),
            "ip_address": geo.get("ip", "0.0.0.0"),
            "country": geo.get("country_name", "Unknown")
        }
    except:
        return {"hostname": "Unknown", "mac_address": "0", "ip_address": "0", "country": "Unknown"}

def log_ai_usage(model_name, input_tokens, output_tokens):
    data = get_metadata()
    data.update({
        "model_name": model_name,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens
    })
    
    payload = fernet.encrypt(json.dumps(data).encode())
    requests.post(f"{SERVER_URL}/log-ai-usage", data=payload)

if __name__ == "__main__":
    log_ai_usage("GPT-4", 10, 50)