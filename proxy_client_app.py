import tkinter as tk
import threading, time, requests, os, sys, socket, subprocess
from tkinter import messagebox

class ProxyClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AI Agent Client")
        self.root.geometry("300x150")
        
        self.label = tk.Label(root, text="Checking Status...")
        self.label.pack(pady=20)
        
        # Start Security Heartbeat
        threading.Thread(target=self.security_heartbeat, daemon=True).start()
        # Start Proxy
        threading.Thread(target=self.run_proxy_process, daemon=True).start()

    def security_heartbeat(self):
        """Kills the app if status is BLOCKED."""
        while True:
            try:
                # Replace with your actual deployed backend URL
                url = "https://YOUR-APP-NAME.onrender.com/api/admin/devices" 
                # (You should add a specific status endpoint for this)
                response = requests.get(url, timeout=5)
                # Logic to parse if current HW_ID is in the list as BLOCKED
                # ...
            except: pass
            time.sleep(30)

    def run_proxy_process(self):
        """Runs the proxy script and captures the dynamic port."""
        # This calls the start_proxy.py file as a subprocess
        process = subprocess.Popen(
            [sys.executable, "start_proxy.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        for line in process.stdout:
            if "RUNNING_ON_PORT:" in line:
                port = line.split(":")[1].strip()
                self.label.config(text=f"Proxy Active on Port: {port}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ProxyClientApp(root)
    root.mainloop()