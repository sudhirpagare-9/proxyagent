import time
import requests
import logging
import platform
import uuid
import sys

# Configuration
SERVER_URL = "https://proxyagent-dashboard.onrender.com"
PUBLIC_KEY = "NA" 

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def get_mac_address():
    """Returns the MAC address as a string."""
    try:
        return ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                        for elements in range(0, 2 * 6, 2)][::-1])
    except:
        return "Unknown"

def get_network_info():
    """Fetches IP and basic geolocation."""
    try:
        public_ip = requests.get('https://api.ipify.org', timeout=5).text
        geo_data = requests.get(f'https://ipapi.co/{public_ip}/json/', timeout=5).json()
        return {
            "ip": public_ip,
            "country": geo_data.get("country_name", "Unknown"),
            "city": geo_data.get("city", "Unknown")
        }
    except Exception as e:
        logging.error(f"Could not fetch network info: {e}")
        return {"ip": "0.0.0.0", "country": "Unknown", "city": "Unknown"}

def register_agent():
    """Registers the agent with the server."""
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
    try:
        response = requests.post(f"{SERVER_URL}/register", json=payload, timeout=10)
        return response.status_code == 200
    except Exception as e:
        logging.error(f"Registration failed: {e}")
        return False

def log_ai_usage(model_name, version, model_type, input_tokens, output_tokens):
    """Sends AI traffic logs to the backend."""
    data = {
        "hw_id": str(uuid.getnode()),
        "model_name": model_name,
        "version": version,
        "model_type": model_type,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens
    }
    try:
        requests.post(f"{SERVER_URL}/log-ai-usage", json=data, timeout=5)
    except Exception as e:
        logging.error(f"Failed to log AI usage: {e}")

if __name__ == "__main__":
    logging.info("Agent starting...")
    if register_agent():
        logging.info("Agent registered successfully.")
    
    # --- PROXY INTERCEPTION LOOP ---
    try:
        while True:
            # Add your interception logic here
            # When you intercept data, call: log_ai_usage("model_name", "v1", "type", 10, 20)
            time.sleep(60) 
    except KeyboardInterrupt:
        logging.info("Stopping agent...")