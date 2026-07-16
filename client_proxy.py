import http.server, socketserver, urllib.request, json, uuid, platform, hashlib, requests
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

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
    """Compliance: Pseudonymization of sensitive fields."""
    return hashlib.sha256(data.encode()).hexdigest()[:16]

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def log_metrics(self, request_body):
        try:
            # Gather & Mask Data
            mac = secure_hash(str(uuid.getnode()))
            ip = secure_hash(requests.get('https://api.ipify.org').text) # Approximate
            
            payload = {
                "hw_id": str(uuid.uuid4()), # Generated UUID, not real hardware ID
                "hostname": platform.node(),
                "mac_address": mac,
                "ip_address": ip,
                "status": "pending",
                "country": "US" # In production, use a GeoIP library
            }
            
            encrypted = public_key.encrypt(json.dumps(payload).encode(), 
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            
            urllib.request.urlopen(urllib.request.Request(f"{SERVER_URL}/log-ai-usage", 
                                  data=encrypted, method='POST'))
        except Exception as e: print(f"Compliance Log Error: {e}")