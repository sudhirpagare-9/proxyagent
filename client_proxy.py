import http.server
import socketserver
import urllib.request
import json
import threading
import uuid
import platform
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# --- CONFIGURATION ---
LOCAL_PORT = 8080
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

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        headers = {k: v for k, v in self.headers.items() if k.lower() != 'host'}
        req = urllib.request.Request(TARGET_API, data=body, headers=headers, method='POST')
        
        try:
            with urllib.request.urlopen(req) as response:
                resp_body = response.read()
                self.send_response(response.status)
                self.end_headers()
                self.wfile.write(resp_body)
                threading.Thread(target=self.log_metrics, args=(body, resp_body)).start()
        except Exception as e:
            self.send_error(502, f"Proxy Error: {str(e)}")
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
            
            encrypted = public_key.encrypt(
                json.dumps(data).encode(),
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            
            req = urllib.request.Request(f"{SERVER_URL}/log-ai-usage", 
                data=encrypted, method='POST', headers={'Content-Type': 'application/octet-stream'})
            
            with urllib.request.urlopen(req) as response:
                print("Log successful")
                
        except Exception as e:
            # This is essential! It will now print the error in your terminal.
            print(f"FAILED TO SEND LOG: {e}")

if __name__ == "__main__":
    print(f"Proxy Agent active on port {LOCAL_PORT}")
    with socketserver.ThreadingTCPServer(("", LOCAL_PORT), ProxyHandler) as httpd:
        httpd.serve_forever()