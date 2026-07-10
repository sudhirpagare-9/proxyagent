import threading, socket, uuid, requests, time, json, tkinter as tk, asyncio, os, sys
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
from mitmproxy import http

# Load config from System Environment Variables
GATEWAY_URL = os.getenv("GATEWAY_URL")
SHARED_SECRET = os.getenv("SHARED_SECRET")

if not GATEWAY_URL or not SHARED_SECRET:
    print("ERROR: GATEWAY_URL or SHARED_SECRET environment variables not set.")
    sys.exit(1)

MY_HW_ID = str(uuid.getnode())

class AIInterceptor:
    def __init__(self):
        self.is_approved = False
        self.register_device()
        threading.Thread(target=self.poll_status, daemon=True).start()

    def register_device(self):
        try:
            requests.post(f"{GATEWAY_URL}/register", headers={"api-key": SHARED_SECRET}, json={
                "hw_id": MY_HW_ID, "hostname": socket.gethostname(), "status": "pending"
            })
        except: pass

    def poll_status(self):
        while True:
            try:
                res = requests.get(f"{GATEWAY_URL}/clients", headers={"api-key": SHARED_SECRET})
                data = res.json()
                client = next((c for c in data.get("data", []) if c["hw_id"] == MY_HW_ID), None)
                self.is_approved = (client and client.get("status") == "approved")
            except: self.is_approved = False
            time.sleep(30)

    def response(self, flow: http.HTTPFlow):
        if self.is_approved and "api.openai.com" in flow.request.pretty_host:
            try:
                data = json.loads(flow.response.content)
                usage = data.get("usage", {})
                requests.post(f"{GATEWAY_URL}/update-usage", headers={"api-key": SHARED_SECRET}, json={
                    "hw_id": MY_HW_ID,
                    "model_used": data.get("model", "unknown"),
                    "input_tokens": usage.get("prompt_tokens", 0),
                    "output_tokens": usage.get("completion_tokens", 0)
                })
            except: pass

async def start_proxy():
    master = DumpMaster(Options(listen_host='127.0.0.1', listen_port=8080))
    master.addons.add(AIInterceptor())
    await master.run()

if __name__ == "__main__":
    threading.Thread(target=lambda: asyncio.run(start_proxy()), daemon=True).start()
    tk.Tk().mainloop()