import time
import requests
import logging
import uuid
import platform

# Setup Logging
logging.basicConfig(
    filename='agent.log', 
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

SERVER_URL = "https://proxyagent-dashboard.onrender.com" 

def main():
    print("Agent started. Check 'agent.log' for activity.")
    logging.info("Agent process started.")
    
    # Infinite loop to keep the script alive
    while True:
        try:
            # --- YOUR PROXY LOGIC ---
            # This is where your code executes repeatedly
            # Example:
            # print("Checking status...")
            
            # Sleep prevents CPU overuse
            time.sleep(30) 
            
        except KeyboardInterrupt:
            logging.info("Agent stopped by user.")
            break
        except Exception as e:
            logging.error(f"Error: {e}")
            time.sleep(10) # Wait 10 seconds before retrying if there is an error

if __name__ == "__main__":
    main()