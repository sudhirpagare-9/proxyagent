# agent_client.py
import requests
import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# 1. Load Public Key
with open("public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# 2. Prepare Data
payload = {
    "hw_id": "CLIENT-001",
    "hostname": "test-machine-01",
    "model_name": "gpt-4o",
    "input_tokens": 150,
    "output_tokens": 450
}
json_data = json.dumps(payload).encode('utf-8')

# 3. Encrypt
encrypted_data = public_key.encrypt(
    json_data,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# 4. Send to your Render URL
url = "https://proxyagent-dashboard.onrender.com/log-ai-usage"
response = requests.post(url, data=encrypted_data)

print(f"Status Code: {response.status_code}")
print(f"Response: {response.text}")