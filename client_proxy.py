import os
import json
import hashlib
import platform
import subprocess
import time
import uuid
import socket
from fastapi import FastAPI, Request, HTTPException
import httpx
import uvicorn

app = FastAPI(title="Multi-Platform AI Interceptor Proxy Daemon")

CONFIG_FILE = os.path.expanduser("~/.enterprise_hw_config.json")

def get_real_hardware_id() -> str:
    # 1. Check if a persistent HW ID is already stored locally for this device/VM
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                data = json.load(f)
                if data.get("hw_id"):
                    return data["hw_id"]
        except Exception:
            pass

    hw_factors = []
    system = platform.system()
    
    try:
        if system == "Windows":
            # Virtual & Physical PC Motherboard / Product UUID
            res = subprocess.run(
                ["powershell", "(Get-CimInstance Win32_ComputerSystemProduct).UUID"],
                capture_output=True, text=True, timeout=3
            )
            if res.returncode == 0 and res.stdout.strip():
                hw_factors.append(res.stdout.strip())

            # BIOS Serial Number
            res2 = subprocess.run(
                ["wmic", "bios", "get", "serialnumber"],
                capture_output=True, text=True, timeout=3
            )
            if res2.returncode == 0:
                lines = [line.strip() for line in res2.stdout.splitlines() if line.strip()]
                if len(lines) > 1 and lines[1].lower() not in ["to be filled by o.e.m.", "default", "none", "system serial number"]:
                    hw_factors.append(lines[1])

            # Baseboard Serial
            res3 = subprocess.run(
                ["wmic", "baseboard", "get", "serialnumber"],
                capture_output=True, text=True, timeout=3
            )
            if res3.returncode == 0:
                lines = [line.strip() for line in res3.stdout.splitlines() if line.strip()]
                if len(lines) > 1 and lines[1].lower() not in ["to be filled by o.e.m.", "default", "none"]:
                    hw_factors.append(lines[1])

        elif system == "Linux":
            # Check for DMI product UUID (works on KVM, VirtualBox, VMware, AWS, GCP, Azure)
            for path in ["/sys/class/dmi/id/product_uuid", "/etc/machine-id"]:
                try:
                    with open(path, "r") as f:
                        val = f.read().strip()
                        if val:
                            hw_factors.append(val)
                except:
                    pass
    except Exception:
        pass

    # Fallback to MAC address and node name if BIOS/VMware UUID is unreadable
    mac_node = str(uuid.getnode())
    node_name = platform.node()
    hw_factors.append(mac_node)
    hw_factors.append(node_name)

    # Filter out empty or placeholder strings and combine into a secure hash
    valid_factors = [f.strip() for f in hw_factors if f and f.lower() not in ["to be filled by o.e.m.", "default", "none", "system serial number"]]
    
    combined_string = "-".join(valid_factors)
    hasher = hashlib.sha256(combined_string.encode())
    unique_hash = hasher.hexdigest()[:16].upper()

    prefix = "HW-MOBILE-TERMUX" if system == "Linux" and "android" in platform.release().lower() else "HW-VIRTUAL-PC"
    hw_id = f"{prefix}-{unique_hash}"

    # Save to local config so it remains permanent across restarts
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump({"hw_id": hw_id, "created_at": time.time()}, f)
    except Exception:
        pass

    return hw_id

HW_ID = get_real_hardware_id()
CLOUD_GATEWAY_URL = "https://proxyagent-dashboard.onrender.com"

print(f"[*] Initialized Proxy Daemon | Unique Hardware ID: {HW_ID}")

@app.post("/v1/chat/completions")
async def intercept_ai_traffic(request: Request):
    body = await request.json()
    messages = body.get("messages", [])
    prompt = messages[-1].get("content", "AI Query") if messages else "AI Query"
    model = body.get("model", "gemini-2.5-flash")

    print(f"[+] Intercepted AI Prompt: {prompt[:50]}...")

    start_time = time.time()
    response_text = f"Secure Multi-Platform Gateway routed response for: {prompt[:30]}"
    latency = int((time.time() - start_time) * 1000) + 40

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{CLOUD_GATEWAY_URL}/log-traffic",
                json={
                    "hw_id": HW_ID,
                    "provider": "Multi-Platform Proxy Interceptor",
                    "model": model,
                    "prompt_tokens": len(prompt.split()) * 2,
                    "completion_tokens": 45,
                    "latency_ms": latency,
                    "payload": prompt
                },
                timeout=5.0
            )
            if resp.status_code == 403:
                raise HTTPException(status_code=403, detail="Client node is pending approval, denied, or deleted by administrator.")
            print(f"[+] Telemetry successfully synced to Cloud Gateway.")
    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"[-] Gateway sync error: {e}")

    return {
        "id": f"chatcmpl-{int(time.time())}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": response_text}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": len(prompt.split()) * 2, "completion_tokens": 45, "total_tokens": len(prompt.split()) * 2 + 45}
    }

def find_available_port(start_port=8080, max_attempts=15):
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("0.0.0.0", port))
                return port
            except OSError:
                continue
    return 8095

if __name__ == "__main__":
    target_port = find_available_port(8080)
    print(f"[*] Starting proxy daemon on port {target_port} (bound to 0.0.0.0 for PC & Mobile access)...")
    uvicorn.run(app, host="0.0.0.0", port=target_port)