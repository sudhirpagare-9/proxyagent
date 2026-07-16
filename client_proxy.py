import json
import urllib.request
from mitmproxy import http
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Load the key from a file instead of hardcoding
from cryptography.hazmat.primitives import serialization

def load_public_key():
    try:
        with open("public_key.pem", "rb") as key_file:
            # .strip() removes any invisible newlines or whitespace at ends
            raw_data = key_file.read().strip() 
            return serialization.load_pem_public_key(raw_data)
    except Exception as e:
        print(f"DEBUG: Error loading key: {e}")
        # Print the start of the data to verify what the script actually sees
        return None

public_key = load_public_key()

SERVER_URL = "https://proxyagent-dashboard.onrender.com"

def response(flow: http.HTTPFlow):
    # Only process target AI API
    if "api.openai.com" in flow.request.pretty_host:
        try:
            if not public_key: return
            
            req_data = json.loads(flow.request.content)
            resp_data = json.loads(flow.response.content)
            
            data = {
                "hw_id": "YOUR_UNIQUE_ID",
                "model_name": req_data.get("model", "unknown"),
                "input_tokens": resp_data.get("usage", {}).get("prompt_tokens", 0),
                "output_tokens": resp_data.get("usage", {}).get("completion_tokens", 0)
            }
            
            # Encrypt and send
            encrypted_payload = public_key.encrypt(
                json.dumps(data).encode(),
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            
            req = urllib.request.Request(
                f"{SERVER_URL}/log-ai-usage", 
                data=encrypted_payload, 
                method='POST',
                headers={'Content-Type': 'application/octet-stream'}
            )
            urllib.request.urlopen(req)
        except Exception as e:
            print(f"Logging error: {e}")