import os
import platform
import uuid
import time
import json
import requests
import logging

# 1. Setup Logging: This creates a log file so you can debug why it crashes
logging.basicConfig(
    filename='agent.log', 
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 2. Dependency Check: Handles missing modules gracefully
try:
    import keyring
except ImportError:
    logging.error("Missing module: keyring. Run: pip install keyring")
    print("Error: Missing module 'keyring'. Please run: pip install keyring mitmproxy cryptography requests")
    exit(1)

# Configuration
SERVER_URL = "https://proxyagent-dashboard.onrender.com" # Your Render URL

def get_hw_id():
    """Generates a unique ID for the computer."""
    return str(uuid.getnode())

def register_agent():
    """Registers the agent with the server if not already done."""
    hw_id = get_hw_id()
    data = {
        "hw_id": hw_id,
        "hostname": platform.node(),
        "public_key": "dummy_key_for_now" # Replace with actual key logic
    }
    try:
        response = requests.post(f"{SERVER_URL}/register", json=data)
        if response.status_code == 200:
            logging.info("Registration successful.")
            return True
    except Exception as e:
        logging.error(f"Registration failed: {e}")
    return False

def check_status():
    """Polls the server for approval status."""
    hw_id = get_hw_id()
    try:
        response = requests.get(f"{SERVER_URL}/status/{hw_id}")
        if response.status_code == 200:
            status = response.json().get("status")
            logging.info(f"Current status: {status}")
            return status
    except Exception as e:
        logging.error(f"Status check failed: {e}")
    return "unknown"

def main():
    logging.info("Agent started.")
    print("Agent is running. Check agent.log for details.")
    
    # Registration Loop
    registered = register_agent()
    
    # Main Execution Loop (Prevents script from closing)
    while True:
        try:
            status = check_status()
            
            if status == "approved":
                # --- YOUR LOGIC HERE ---
                # This is where your proxy/task logic goes
                logging.info("Agent is approved and running active tasks.")
            else:
                logging.warning(f"Agent status is: {status}. Waiting for approval...")
            
            # Sleep for 60 seconds to prevent hammering the server
            time.sleep(60)
            
        except KeyboardInterrupt:
            logging.info("Agent stopped by user.")
            break
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    main()