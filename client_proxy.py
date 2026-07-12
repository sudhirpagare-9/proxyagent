import uuid
import requests
import json
import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()
fernet = Fernet(os.getenv("ENCRYPTION_KEY").encode())
SERVER_URL = os.getenv("SERVER_URL")

def get_sys_data():
    try:
        geo = requests.get("https://ipapi.co/json/", timeout=5).json()
        return {
            "hw_id": str(uuid.getnode()),
            "ip_address": geo.get("ip", "0.0.0.0"),
            "country": geo.get("country_name", "Unknown")
        }
    except:
        return {"hw_id": str(uuid.getnode()), "ip_address": "0.0.0.0", "country": "Unknown"}

def log_ai_usage(model_name, input_tokens, output_tokens):
    data = get_sys_data()
    data.update({
        "model_name": model_name,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens
    })
    
    payload = fernet.encrypt(json.dumps(data).encode())
    try:
        requests.post(f"{SERVER_URL}/log-ai-usage", data=payload, timeout=5)
    except Exception as e:
        print(f"Transmission failed: {e}")

if __name__ == "__main__":
    log_ai_usage("GPT-4", 100, 200)