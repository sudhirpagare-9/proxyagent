import time
import requests
import logging
import platform
import uuid
import sys
import uuid


# --- Configuration ---
# Ensure this matches your live Render deployment URL
SERVER_URL = "https://proxyagent-dashboard.onrender.com" 

# --- Logging ---
# Logs will be saved to 'agent.log' in the same directory
logging.basicConfig(
    filename='agent.log', 
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_hw_id():
    """Generates a unique ID based on the hardware's MAC address."""
    return str(uuid.getnode())

def register_agent():
    """Registers this client with the backend server."""
    data = {
        "hw_id": get_hw_id(),
        "hostname": platform.node(),
        "public_key": "NA"  # Placeholder for future security implementation
    }
    try:
        logging.info(f"Attempting to register with {SERVER_URL}/register")
        response = requests.post(f"{SERVER_URL}/register", json=data, timeout=10)
        
        if response.status_code == 200:
            logging.info("Registration successful.")
            print("Successfully registered with backend.")
            return True
        else:
            logging.error(f"Registration failed with status {response.status_code}: {response.text}")
            return False
    except Exception as e:
        logging.error(f"Connection error during registration: {e}")
        return False

def main():
    print(f"Agent started. HWID: {get_hw_id()}")
    logging.info("Agent process initialized.")
    
    # Perform registration before starting the main loop
    if not register_agent():
        print("Initial registration failed. The agent will retry in the background.")

    # Main persistent loop
    while True:
        try:
            # --- AGENT LOGIC ---
            # Place your proxy/task logic here.
            # Example: Keep the connection alive or perform health checks
            
            # Wait 60 seconds between checks to minimize CPU/Network usage
            time.sleep(60) 
            
        except KeyboardInterrupt:
            print("\nStopping agent...")
            logging.info("Agent stopped by user.")
            sys.exit(0)
        except Exception as e:
            logging.error(f"Error during runtime: {e}")
            time.sleep(30) # Wait 30 seconds before retrying if an error occurs
# ... existing code ...

def log_ai_usage(model_name, version, model_type, input_tok, output_tok, balance=0):
    """Sends AI usage data to the backend logging endpoint."""
    payload = {
        "hw_id": str(uuid.getnode()),
        "model_name": model_name,
        "version": version,
        "model_type": model_type,
        "input_tokens": input_tok,
        "output_tokens": output_tok,
        "balance_tokens": balance
    }
    try:
        response = requests.post(f"{SERVER_URL}/log-ai-usage", json=payload, timeout=10)
        if response.status_code == 200:
            print("Usage log synced.")
        else:
            print(f"Failed to sync usage log: {response.text}")
    except Exception as e:
        print(f"Error logging usage: {e}")
if __name__ == "__main__":
    main()