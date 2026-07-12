import uuid, platform, requests, json, os, logging
from cryptography.fernet import Fernet

SERVER_URL = "https://proxyagent-dashboard.onrender.com"
fernet = Fernet(os.environ["ENCRYPTION_KEY"].encode())

def log_ai_usage(model_name, input_tokens, output_tokens):
    data = {
        "hw_id": str(uuid.getnode()),
        "hostname": platform.node(),
        "model_name": model_name,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens
    }
    try:
        encrypted_payload = fernet.encrypt(json.dumps(data).encode())
        requests.post(f"{SERVER_URL}/log-ai-usage", data=encrypted_payload, timeout=5)
    except Exception as e:
        logging.error(f"Transmission failed: {e}")