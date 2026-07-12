import uuid
import platform
import requests
import json
import os
import logging
from cryptography.fernet import Fernet

# Configuration
SERVER_URL = "https://proxyagent-dashboard.onrender.com"
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")

if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY must be set in environment variables.")

fernet = Fernet(ENCRYPTION_KEY.encode())
logging.basicConfig(level=logging.INFO)

def log_ai_usage(model_name: str, input_tokens: int, output_tokens: int):
    """
    Collects system metadata, encrypts, and transmits to the backend.
    """
    payload = {
        "hw_id": str(uuid.getnode()),
        "hostname": platform.node(),
        "model_name": model_name,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens
    }
    
    try:
        encrypted_payload = fernet.encrypt(json.dumps(payload).encode())
        response = requests.post(f"{SERVER_URL}/log-ai-usage", data=encrypted_payload, timeout=5)
        response.raise_for_status()
        logging.info("Log transmission successful.")
    except Exception as e:
        logging.error(f"Transmission failed: {e}")

if __name__ == "__main__":
    log_ai_usage("GPT-4", 100, 250)