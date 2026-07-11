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

SERVER_URL = "https://proxyagent-dashboard.onrender.com" # Change if your URL is different

def get_hw_id():
    return str(uuid.getnode())

def main():
    print("Agent started. Press Ctrl+C to stop.")
    logging.info("Agent process initialized.")
    
    # This loop keeps the script running indefinitely
    while True:
        try:
            # --- AGENT LOGIC ---
            # Replace print() with your actual task logic
            print(f"Agent active. HWID: {get_hw_id()}")
            
            # The script will wait 30 seconds before running the next cycle
            # This keeps the CPU usage low and prevents flooding your backend
            time.sleep(30) 
            
        except KeyboardInterrupt:
            print("Stopping agent...")
            logging.info("Agent stopped by user.")
            break
        except Exception as e:
            print(f"Error occurred: {e}")
            logging.error(f"Error: {e}")
            time.sleep(10) # Wait 10 seconds before retrying

if __name__ == "__main__":
    main()