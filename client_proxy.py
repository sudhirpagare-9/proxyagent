import json, uuid, platform, urllib.request
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

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

def log_ai_usage(model_name, input_tokens, output_tokens):
    data = {
        "hw_id": str(uuid.getnode()),
        "model_name": model_name,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens
    }
    
    # Encrypt with Public Key
    encrypted_payload = public_key.encrypt(
        json.dumps(data).encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    # Send to Render
    req = urllib.request.Request("https://proxyagent-dashboard.onrender.com/log-ai-usage", data=encrypted_payload, method='POST')
    urllib.request.urlopen(req)