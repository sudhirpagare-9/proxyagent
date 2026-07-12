import time
import requests
import logging
import platform
import uuid

# Configuration
SERVER_URL = "https://proxyagent-dashboard.onrender.com"
PUBLIC_KEY = "NA" 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def get_mac_address():
    return ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 2)][::-1])

def get_network_info():
    try:
        public_ip = requests.get('https://api.ipify.org', timeout=5).text
        geo_data = requests.get(f'https://ipapi.co/{public_ip}/json/', timeout=5).json()
        return {"ip": public_ip, "country": geo_data.get("country_name", "Unknown"), "city": geo_data.get("city", "Unknown")}
    except: return {"ip": "Unknown", "country": "Unknown", "city": "Unknown"}

def register_agent():
    net_info = get_network_info()
    payload = {
        "hw_id": str(uuid.getnode()),
        "hostname": platform.node(),
        "public_key": PUBLIC_KEY,
        "ip_address": net_info['ip'],
        "mac_address": get_mac_address(),
        "country": net_info['country'],
        "geo_location": net_info['city']
    }
    try: requests.post(f"{SERVER_URL}/register", json=payload, timeout=10)
    except Exception as e: logging.error(f"Registration failed: {e}")

def log_ai_usage(model_name, version, model_type, input_tokens, output_tokens, balance=0):
    data = {
        "hw_id": str(uuid.getnode()),
        "model_name": model_name,
        "version": version,
        "model_type": model_type,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "balance_tokens": balance
    }
    try: requests.post(f"{SERVER_URL}/log-ai-usage", json=data, timeout=5)
    except Exception as e: logging.error(f"Failed to log: {e}")

if __name__ == "__main__":
    register_agent()
    # Main Loop - Add your proxy/interception logic here
    while True:
        time.sleep(60)