import os
import threading
import tkinter as tk
import asyncio
import uuid
import json
import socket
import time
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
        self.register_device()
        threading.Thread(target=self.poll_status, daemon=True).start()

    def register_device(self):
        """Register device with required fields to prevent null constraints."""
        if supabase:
            try:
                # Use upsert to handle registration gracefully
                supabase.table("clients_registry").upsert({
                    "hw_id": MY_HW_ID,
                    "status": "pending",
                    "hostname": socket.gethostname(), # FIX: Provides hostname
                    "ip_address": "127.0.0.1",       # FIX: Provides IP
                    "client_name": "My Client Machine"
                }).execute()
            except Exception as e:
                print(f"[ERROR] Failed to register: {e}")

    def poll_status(self):
        """Continuously check DB for approval."""
        while True:
            if supabase:
                try:
                    res = supabase.table("clients_registry").select("status").eq("hw_id", MY_HW_ID).single().execute()
                    self.is_approved = (res.data.get("status") == "approved")
                except: 
                    self.is_approved = False
            time.sleep(10)

    def response(self, flow: http.HTTPFlow):
        """Log token usage only if approved."""
        if self.is_approved and "api.openai.com" in flow.request.pretty_host:
            try:
                data = json.loads(flow.response.content)
                usage = data.get("usage", {})
                supabase.table("clients_registry").update({
                    "model_used": data.get("model", "unknown"),
                    "input_tokens": usage.get("prompt_tokens", 0),
                    "output_tokens": usage.get("completion_tokens", 0)
                }).eq("hw_id", MY_HW_ID).execute()
            except: pass

# --- RUNNER ---
async def start_proxy():
    options = Options(listen_host='127.0.0.1', listen_port=8080)
    master = DumpMaster(options, with_termlog=False, with_dumper=False)
    master.addons.add(AIInterceptor())
    await master.run()

def run_proxy_in_thread():
    try:
        asyncio.run(start_proxy())
    except Exception as e:
        print(f"Proxy error: {e}")

# ... (Include your existing GUI Class/App code here) ...