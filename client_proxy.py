import os
import threading
import tkinter as tk
import asyncio
import uuid
import json
import time
import socket
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
from mitmproxy import http
from supabase import create_client

# --- CONFIG ---
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None

def get_hw_id():
    return str(uuid.getnode())

MY_HW_ID = get_hw_id()

# --- PROXY ADDON ---
class AIInterceptor:
    def __init__(self):
        self.is_approved = False
        # Register once on startup
        self.register_device()
        # Start polling loop
        threading.Thread(target=self.poll_status, daemon=True).start()

    def register_device(self):
        if not supabase: return
        try:
            # Check if device exists
            res = supabase.table("clients_registry").select("hw_id").eq("hw_id", MY_HW_ID).execute()
            if not res.data:
                # Insert only if not found (don't overwrite existing status)
                supabase.table("clients_registry").insert({
                    "hw_id": MY_HW_ID,
                    "status": "pending",
                    "client_name": "My Client Machine",
                    "hostname": socket.gethostname(),
                    "ip_address": "127.0.0.1",
                    "mac_address": MY_HW_ID
                }).execute()
        except Exception as e:
            print(f"[ERROR] Registration failed: {e}")

  def poll_status(self):
    while True:
        if supabase:
            try:
                # SELECT ONLY: Do not update status here!
                res = supabase.table("clients_registry").select("status").eq("hw_id", MY_HW_ID).single().execute()
                self.is_approved = (res.data.get("status") == "approved")
            except: 
                self.is_approved = False
        time.sleep(30)

    def request(self, flow: http.HTTPFlow):
        if not self.is_approved and "supabase" not in flow.request.pretty_host:
            flow.kill()

  def response(self, flow: http.HTTPFlow):
        # 1. Print the host to the console so you can see what traffic is passing through
        print(f"[DEBUG] Traffic detected: {flow.request.pretty_host}")

        # 2. Broaden the check (Remove specific 'api.openai.com' constraint for testing)
        # Change this to match the host you are actually using, or leave it broad to see data
        if self.is_approved:
            try:
                # Print the content to confirm we are getting data
                data = json.loads(flow.response.content)
                print(f"[DEBUG] Intercepted data: {data}")
                
                usage = data.get("usage", {})
                
                # Push to Supabase
                supabase.table("clients_registry").update({
                    "model_used": data.get("model", "unknown"),
                    "input_tokens": usage.get("prompt_tokens", 0),
                    "output_tokens": usage.get("completion_tokens", 0)
                }).eq("hw_id", MY_HW_ID).execute()
                print("[SUCCESS] Metrics updated in DB")
            except Exception as e:
                # Remove 'pass' so you can see errors in the console!
                print(f"[ERROR] Failed to process traffic: {e}")

# --- RUNNER ---
async def start_proxy():
    options = Options(listen_host='127.0.0.1', listen_port=8080)
    master = DumpMaster(options, with_termlog=False, with_dumper=False)
    master.addons.add(AIInterceptor())
    await master.run()

def run_proxy_in_thread():
    # Properly define the event loop for this thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    options = Options(listen_host='127.0.0.1', listen_port=8080)
    master = DumpMaster(options, with_termlog=False, with_dumper=False)
    master.addons.add(AIInterceptor())
    
    # Run the loop
    loop.run_until_complete(master.run())
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure AI Proxy")
        self.btn = tk.Button(root, text="Start Proxy", command=self.start_proxy)
        self.btn.pack(pady=50)

    def start_proxy(self):
        threading.Thread(target=run_proxy_in_thread, daemon=True).start()
        self.btn.config(text="Proxy Active", state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()