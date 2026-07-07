# client_proxy.py
import threading
import tkinter as tk
import asyncio
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options

# This replaces your old 'start_proxy.py'
def run_proxy_thread():
    options = Options(listen_host='127.0.0.1', listen_port=8080, ssl_insecure=True)
    master = DumpMaster(options)
    asyncio.run(master.run())

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure AI Proxy")
        self.btn = tk.Button(root, text="Start Proxy", command=self.start_proxy)
        self.btn.pack(pady=20)

    def start_proxy(self):
        # Use Threading, NOT subprocess, to prevent loops
        threading.Thread(target=run_proxy_thread, daemon=True).start()
        self.btn.config(text="Proxy Active", state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()