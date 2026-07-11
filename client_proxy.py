import time
import requests
import logging
import platform
import uuid

# Configure Logging
logging.basicConfig(
    filename='agent.log', 
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

SERVER_URL = "https://proxyagent-dashboard.onrender.com"

def get_hw_id():
    return str(uuid.getnode())

def register_agent():
    """Sends registration data to the backend."""
    data = {
        "hw_id": get_hw_id(),
        "hostname": platform.node(),
        "public_key": "NA" # Update this later with real crypto keys
    }
    try:
        response = requests.post(f"{SERVER_URL}/register", json=data)
        if response.status_code == 200:
            logging.info("Successfully registered with backend.")
            return True
    except Exception as e:
        logging.error(f"Registration failed: {e}")
    return False

def main():
    print("Agent starting...")
    # Perform registration once on startup
    register_agent()
    
    while True:
        try:
            print(f"Agent active. HWID: {get_hw_id()}")
            time.sleep(60) 
        except KeyboardInterrupt:
            break
        except Exception as e:
            logging.error(f"Error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    main()