import time
import requests
import logging
import platform
import uuid
import json
import os
from cryptography.fernet import Fernet

# Configuration
SERVER_URL = "https://proxyagent-dashboard.onrender.com"
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY") # Ensure this is set on your local machine
fernet = Fernet(ENCRYPTION_KEY.encode())

logging.basicConfig(level=logging.INFO)

def log_ai_usage(model_name, version, model_type, input_tokens, output_tokens, balance=0):
    data = {
        "hw_id": str(uuid.getnode()),
        "model_name": model_name, "version": version, "model_type": model_type,
        "input_tokens": input_tokens, "output_tokens": output_tokens, "balance_tokens": balance
    }
    
    # Encrypt the payload
    encrypted_payload = fernet.encrypt(json.dumps(data).encode())
    
    try:
        # Send raw encrypted bytes
        requests.post(f"{SERVER_URL}/log-ai-usage", data=encrypted_payload, timeout=5)
    except Exception as e:
        logging.error(f"Encrypted log transmission failed: {e}")

if __name__ == "__main__":
    # Test call
    log_ai_usage("GPT-4", "v1", "chat", 10, 50)