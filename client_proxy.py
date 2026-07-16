import http.server, socketserver, urllib.request, json, uuid, platform
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# Configuration
SERVER_URL = "https://your-render-app-url.com" # Replace with your Render URL
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
import http.server, socketserver, urllib.request, json, uuid, platform, sys

# --- DEBUGGER: FLOW TRACER ---
def trace(step, message):
    print(f"\n[PROXY-TRACE] STEP {step}: {message}", file=sys.stderr)

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def do_CONNECT(self):
        trace(1, "CONNECT request received (HTTPS Tunnel).")
        self.send_response(200, 'Connection Established')
        self.end_headers()

    def do_POST(self):
        trace(2, "POST request detected. Forwarding...")
        # Simulate log capture
        self.log_metrics("GPT-4", 10, 20)
        self.send_response(200)
        self.end_headers()

    def log_metrics(self, model, input_t, output_t):
        trace(3, "Preparing to send log to server...")
        try:
            data = {"hw_id": str(uuid.getnode()), "model_name": model, "input_tokens": input_t, "output_tokens": output_t}
            trace(4, f"Payload: {data}")
            # Ensure your URL is correct
            req = urllib.request.Request("https://your-app.onrender.com/log-ai-usage", 
                                       data=json.dumps(data).encode(), 
                                       headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req) as response:
                trace(5, f"Server responded with: {response.status}")
        except Exception as e:
            trace(6, f"ERROR: Failed to send data: {e}")

if __name__ == "__main__":
    print("Proxy started on 8080. Traffic will show below:")
    with socketserver.ThreadingTCPServer(("", 8080), ProxyHandler) as httpd:
        httpd.serve_forever()