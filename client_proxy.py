import sys, socket, json, platform, subprocess, time, keyring
from mitmproxy import http
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from urllib import request, error
import logging
logging.basicConfig(filename='agent.log', level=logging.INFO)

def start_agent():
    logging.info("Agent started successfully.")
    # ... your existing logic ...
# --- Configuration ---
GATEWAY_URL = "https://your-server.onrender.com"

# --- Hardware Identification ---
def get_hw_id():
    # Persistent ID logic for VMs and Cloud
    if platform.system() == "Windows":
        cmd = 'reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid'
        return subprocess.check_output(cmd, shell=True).decode().split("REG_SZ")[1].strip()
    return "/etc/machine-id"

MY_HW_ID = get_hw_id()

# --- Security: Asymmetric Identity ---
def get_or_create_keys():
    key_hex = keyring.get_password("ai_proxy", "priv_key")
    if not key_hex:
        priv = ed25519.Ed25519PrivateKey.generate()
        key_hex = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
        keyring.set_password("ai_proxy", "priv_key", key_hex)
        return priv
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_hex))

priv_key = get_or_create_keys()
pub_key = priv_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

# --- Status Management ---
is_approved = False

def check_status():
    global is_approved
    try:
        # Use standard library to avoid 'requests' dependency if desired
        url = f"{GATEWAY_URL}/status/{MY_HW_ID}"
        with request.urlopen(url, timeout=5) as res:
            data = json.loads(res.read())
            is_approved = (data.get("status") == "approved")
    except: is_approved = False

# --- Interception Logic ---
class AIInterceptor:
    def response(self, flow: http.HTTPFlow):
        # 1. Periodically check approval
        if time.time() % 300 < 5: check_status()
        if not is_approved: return

        # 2. Intercept OpenAI traffic
        if "api.openai.com" in flow.request.pretty_host:
            try:
                data = json.loads(flow.response.content)
                payload = {
                    "hw_id": MY_HW_ID,
                    "model": data.get("model", "unknown"),
                    "input": data.get("usage", {}).get("prompt_tokens", 0)
                }
                # 3. Sign the data
                sig = priv_key.sign(json.dumps(payload, sort_keys=True).encode()).hex()
                
                # 4. Secure Transmission
                req = request.Request(f"{GATEWAY_URL}/update-usage", 
                                      data=json.dumps({"data": payload, "sig": sig}).encode(),
                                      headers={'Content-Type': 'application/json'})
                request.urlopen(req, timeout=3)
            except: pass

addons = [AIInterceptor()]
# Add this at the very bottom of your client_proxy.py
if __name__ == "__main__":
    print("Agent is running...")
    # This prevents the script from closing immediately
    try:
        while True:
            # Your main logic here (e.g., checking for tasks)
            import time
            time.sleep(10) 
    except KeyboardInterrupt:
        print("Agent stopped by user.")