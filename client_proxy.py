import threading, socket, uuid, requests, time, json, os, sys
from mitmproxy import http

# Load config file if it exists, otherwise fallback to env
def load_config():
    if os.path.exists("config.json"):
        with open("config.json") as f: return json.load(f)
    return {"GATEWAY_URL": os.getenv("GATEWAY_URL"), "SHARED_SECRET": os.getenv("SHARED_SECRET")}

config = load_config()
GATEWAY_URL = config.get("GATEWAY_URL")
SHARED_SECRET = config.get("SHARED_SECRET")

# ... (Existing imports)

def get_client_metadata():
    try:
        ip = requests.get('https://api.ipify.org', timeout=5).text
        # Simple geo lookup
        geo = requests.get(f'https://ipapi.co/{ip}/json/', timeout=5).json()
        return {
            "ip_address": ip,
            "hostname": socket.gethostname(),
            "country": geo.get("country_name", "Unknown"),
            "geo_location": f"{geo.get('city', '')}, {geo.get('region', '')}"
        }
    except:
        return {"ip_address": "0.0.0.0", "hostname": "unknown", "country": "unknown", "geo_location": "unknown"}

class AIInterceptor:
    # ... (Existing init)
    def register_device(self):
        meta = get_client_metadata()
        data = {
            "hw_id": MY_HW_ID, 
            "hostname": meta["hostname"], 
            "ip_address": meta["ip_address"],
            "country": meta["country"],
            "geo_location": meta["geo_location"],
            "status": "pending"
        }
        requests.post(f"{GATEWAY_URL}/register", headers={"api-key": SHARED_SECRET}, json=data)

    def response(self, flow: http.HTTPFlow):
        if self.is_approved and "api.openai.com" in flow.request.pretty_host:
            try:
                data = json.loads(flow.response.content)
                usage = data.get("usage", {})
                # Capture comprehensive metrics
                payload = {
                    "hw_id": MY_HW_ID,
                    "model_name": data.get("model", "unknown"),
                    "input_tokens": usage.get("prompt_tokens", 0),
                    "output_tokens": usage.get("completion_tokens", 0),
                    "model_type": "chat" # or identify from response
                }
                requests.post(f"{GATEWAY_URL}/update-usage", headers={"api-key": SHARED_SECRET}, json=payload)
            except: pass