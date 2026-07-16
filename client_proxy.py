import json, urllib.request, os
from mitmproxy import http
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Ensure public_key.pem is in the same directory as the script
def load_public_key():
    try:
        with open("public_key.pem", "rb") as key_file:
            return serialization.load_pem_public_key(key_file.read())
    except:
        return None

public_key = load_public_key()
SERVER_URL = "https://proxyagent-dashboard.onrender.com"

def response(flow: http.HTTPFlow):
    if "api.openai.com" in flow.request.pretty_host and public_key:
        try:
            req_data = json.loads(flow.request.content)
            resp_data = json.loads(flow.response.content)
            
            payload = {
                "hw_id": "YOUR_UNIQUE_ID", # Replace with dynamic ID
                "model_name": req_data.get("model", "unknown"),
                "input_tokens": resp_data.get("usage", {}).get("prompt_tokens", 0),
                "output_tokens": resp_data.get("usage", {}).get("completion_tokens", 0)
            }
            
            encrypted = public_key.encrypt(
                json.dumps(payload).encode(),
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            
            req = urllib.request.Request(f"{SERVER_URL}/log-ai-usage", data=encrypted, method='POST')
            urllib.request.urlopen(req)
        except Exception:
            pass # Keep silent to avoid disrupting AI traffic