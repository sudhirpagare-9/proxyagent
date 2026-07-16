import http.server, socketserver, urllib.request, json, uuid, platform, hashlib, requests
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# --- CONFIGURATION ---
TARGET_API = "https://api.openai.com/v1/chat/completions"
SERVER_URL = "https://proxyagent-dashboard.onrender.com"
PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxTGa+YXCW31VpSX69rJ0
6lD1tSSckWVHJC7xMQWYT7eOe6fB8besMmLMvln1XOlJT+IdPZYis0xb16gVq5BJ
JKP6YqDsXNpt/JMG/1a7vEQlsCPqyu+HzOsmx/a4z5BcqOvugrF1ZRtVBHDO0Lfx
/EIp5qAirFRhDUG0GoR866+/TDHwIfph7teC6ZAQYvLGp4z5lM6/SE6QdHkSj2mC
bj/ueTd7/NU2WdbGW4fvXHvz1EsyX7SxAIizn1tYPkrHRkhJXDmy6rOJUKDgBPbK
XJ3zgMAioGI9df09HK+ZcZFUHMvjwezCvfA0zvucdvUSVUzXdZqqmarnd+bVt1pn
vwIDAQAB
-----END PUBLIC KEY-----"""
public_key = serialization.load_pem_public_key(PUBLIC_KEY_PEM)

def secure_hash(data: str):
    return hashlib.sha256(data.encode()).hexdigest()[:16]

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        # 1. Forward traffic to Target API
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        
        try:
            response = requests.post(TARGET_API, data=body, headers={'Authorization': self.headers.get('Authorization'), 'Content-Type': 'application/json'})
            self.send_response(response.status_code)
            self.end_headers()
            self.wfile.write(response.content)
            
            # 2. Log Metrics in background
            self.log_metrics(body.decode(), response.text)
        except Exception as e:
            print(f"Forwarding Error: {e}")

    def log_metrics(self, request_body, response_body):
        try:
            req_data = json.loads(request_body)
            resp_data = json.loads(response_body)
            
            payload = {
                "hw_id": secure_hash(str(uuid.getnode())), # Pseudonymized HW ID
                "hostname": platform.node(),
                "mac_address": secure_hash("local-mac"),
                "ip_address": secure_hash("local-ip"),
                "model_name": req_data.get("model", "unknown"),
                "input_tokens": resp_data.get("usage", {}).get("prompt_tokens", 0),
                "output_tokens": resp_data.get("usage", {}).get("completion_tokens", 0),
                "status": "pending"
            }
            
            encrypted = public_key.encrypt(json.dumps(payload).encode(), 
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            
            requests.post(f"{SERVER_URL}/log-ai-usage", data=encrypted, headers={'Content-Type': 'application/octet-stream'})
        except Exception as e:
            print(f"Logging Error: {e}")

if __name__ == "__main__":
    with socketserver.ThreadingTCPServer(("", 8080), ProxyHandler) as httpd:
        print("Proxy operational. Configure system proxy to 127.0.0.1:8080")
        httpd.serve_forever()