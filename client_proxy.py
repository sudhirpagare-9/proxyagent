import os
import uuid
import json
import logging
import requests
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load configuration from .env
load_dotenv()

# Setup security
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
API_KEY = os.getenv("API_KEY")
SERVER_URL = os.getenv("SERVER_URL")

if not ENCRYPTION_KEY:
    raise ValueError("CRITICAL: ENCRYPTION_KEY not found in .env file.")

fernet = Fernet(ENCRYPTION_KEY.encode())

def log_ai_usage(model_name, version, model_type, input_tokens, output_tokens):
    data = {
        "hw_id": str(uuid.getnode()),
        "model_name": model_name, "version": version, "model_type": model_type,
        "input_tokens": input_tokens, "output_tokens": output_tokens
    }
    
    try:
        encrypted_payload = fernet.encrypt(json.dumps(data).encode())
        headers = {"X-API-KEY": API_KEY}
        
        # Secure transmission
        response = requests.post(
            f"{SERVER_URL}/log-ai-usage", 
            data=encrypted_payload, 
            headers=headers, 
            timeout=10
        )
        response.raise_for_status()
    except Exception as e:
        # Avoid logging raw data if transmission fails
        logging.error("Transmission failed. Security breach prevented.")

if __name__ == "__main__":
    log_ai_usage("GPT-4", "v1", "chat", 10, 50)