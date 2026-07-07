import threading
import tkinter as tk
import asyncio
import mitmproxy.tools.dump as dump
from mitmproxy.options import Options

# --- CONFIG ---
# Use the URL of the API you just deployed above
API_ENDPOINT = "https://your-api-domain.onrender.com/api/ingest"

class ProxyClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure AI Proxy")
        self.root.geometry("300x150")
        
        self.btn = tk.Button(root, text="Start Encrypted Proxy", command=self.run_proxy)
        self.btn.pack(pady=40)

    def run_proxy(self):
        # Use threading, NOT subprocess.Popen
        threading.Thread(target=self._start_mitm, daemon=True).start()
        self.btn.config(text="Proxy Active", state="disabled")

    def _start_mitm(self):
        options = Options(listen_host='127.0.0.1', listen_port=8080, ssl_insecure=False)
        master = dump.DumpMaster(options)
        # Load your interceptor logic here
        asyncio.run(master.run())

if __name__ == "__main__":
    root = tk.Tk()
    app = ProxyClientApp(root)
    root.mainloop()