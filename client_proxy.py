import http.server, socketserver, urllib.request, json, threading, uuid, platform
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

SERVER_URL = "https://proxyagent-dashboard.onrender.com"
# Ensure this matches your backend's expected public key
PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
...YOUR_KEY_HERE...
-----END PUBLIC KEY-----"""
public_key = serialization.load_pem_public_key(PUBLIC_KEY_PEM)

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def log_metrics(self, request_body, response_body):
        try:
            req_data = json.loads(request_body)
            resp_data = json.loads(response_body)
            data = {
                "hw_id": str(uuid.getnode()),
                "hostname": platform.node(),
                "model_name": req_data.get("model", "unknown"),
                "input_tokens": resp_data.get("usage", {}).get("prompt_tokens", 0),
                "output_tokens": resp_data.get("usage", {}).get("completion_tokens", 0)
            }
            encrypted = public_key.encrypt(json.dumps(data).encode(), 
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            
            req = urllib.request.Request(f"{SERVER_URL}/log-ai-usage", data=encrypted, method='POST', headers={'Content-Type': 'application/octet-stream'})
            with urllib.request.urlopen(req): pass
        except Exception as e: print(f"Proxy Log Failed: {e}")

    # ... (Keep your existing do_POST/do_GET proxy forwarding logic here) ...