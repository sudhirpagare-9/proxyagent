import threading, socket, uuid, requests, json, asyncio, tkinter as tk
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
from mitmproxy import http

# CONFIGURATION
GATEWAY_URL = "https://your-api-url.onrender.com" # Your deployed backend URL
SHARED_SECRET = "my_secure_random_key_123"        # Must match the one in Backend Env Vars

MY_HW_ID = str(uuid.getnode())

class AIInterceptor:
    def __init__(self):
        self.is_approved = False
        self.register_device()
        
    def register_device(self):
        try:
            requests.post(f"{GATEWAY_URL}/register", headers={"api-key": SHARED_SECRET}, json={
                "hw_id": MY_HW_ID, "hostname": socket.gethostname(), "status": "pending"
            })
        except Exception as e: print(f"Reg Error: {e}")

    def response(self, flow: http.HTTPFlow):
        if "api.openai.com" in flow.request.pretty_host:
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