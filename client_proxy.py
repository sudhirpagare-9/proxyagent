import requests
import uuid
import json
import os
import logging
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

# Configuration
SERVER_URL = os.getenv("SERVER_URL", "https://your-render-url.onrender.com")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
API_KEY = os.getenv("API_KEY") 

fernet = Fernet(ENCRYPTION_KEY.encode())

def log_ai_usage(model_name, version, model_type, input_tokens, output_tokens):
    data = {
        "hw_id": str(uuid.getnode()),
        "model_name": model_name, "version": version, "model_type": model_type,
        "input_tokens": input_tokens, "output_tokens": output_tokens
    }
    
    try:
        payload = fernet.encrypt(json.dumps(data).encode())
        headers = {"X-API-KEY": API_KEY}
        response = requests.post(f"{SERVER_URL}/log-ai-usage", data=payload, headers=headers, timeout=5)
        response.raise_for_status()
        print("Log sent successfully.")
    except Exception as e:
        print(f"Failed to log: {e}")

if __name__ == "__main__":
    log_ai_usage("GPT-4", "v1", "chat", 10, 50)