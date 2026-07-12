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
logging.basicConfig(
    filename='agent.log', 
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_mac_address():
    try:
        return ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                         for elements in range(0, 2 * 6, 2)][::-1])
    except:
        return "Unknown"

def get_network_info():
    try:
        public_ip = requests.get('https://api.ipify.org', timeout=5).text
        geo_data = requests.get(f'https://ipapi.co/{public_ip}/json/', timeout=5).json()
        return {
            "ip": public_ip,
            "country": geo_data.get("country_name", "Unknown"),
            "city": geo_data.get("city", "Unknown")
        }
    except:
        return {"ip": "Unknown", "country": "Unknown", "city": "Unknown"}

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
    
    try:
        response = requests.post(f"{SERVER_URL}/register", json=payload, timeout=10)
        return response.status_code == 200
    except Exception as e:
        logging.error(f"Registration connection error: {e}")
        return False

def main():
    logging.info("Agent process initialized.")
    if register_agent():
        print("Registration successful.")
    else:
        print("Registration failed.")

    while True:
        try:
            # Add proxy/logic here
            time.sleep(60)
        except KeyboardInterrupt:
            logging.info("Agent stopped by user.")
            sys.exit(0)

if __name__ == "__main__":
    main()