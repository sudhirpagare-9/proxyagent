import keyring, json, requests, socket, uuid, os
from mitmproxy import http
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

GATEWAY_URL = os.environ.get("GATEWAY_URL", "https://your-render-url.onrender.com")
MY_HW_ID = str(uuid.getnode())

# Secure Identity Management
def get_identity():
    # Load or Create Private Key securely in OS Vault
    key_hex = keyring.get_password("ai_proxy", "priv_key")
    if not key_hex:
        priv = ed25519.Ed25519PrivateKey.generate()
        key_hex = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
        keyring.set_password("ai_proxy", "priv_key", key_hex)
        return priv
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_hex))

priv_key = get_identity()
pub_key_hex = priv_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

# Register on startup
def register():
    data = {"hw_id": MY_HW_ID, "hostname": socket.gethostname(), "public_key": pub_key_hex}
    requests.post(f"{GATEWAY_URL}/register", json=data)

register()

class AIInterceptor:
    def response(self, flow: http.HTTPFlow):
        if "api.openai.com" in flow.request.pretty_host:
            try:
                data = json.loads(flow.response.content)
                usage = data.get("usage", {})
                payload = {
                    "hw_id": MY_HW_ID,
                    "model_name": data.get("model", "unknown"),
                    "input_tokens": usage.get("prompt_tokens", 0),
                    "output_tokens": usage.get("completion_tokens", 0)
                }
                # Sign the payload
                sig = priv_key.sign(json.dumps(payload, sort_keys=True).encode()).hex()
                # Send
                requests.post(f"{GATEWAY_URL}/update-usage", json={"data": payload, "sig": sig})
            except: pass

addons = [AIInterceptor()]