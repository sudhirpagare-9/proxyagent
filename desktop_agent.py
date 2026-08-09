import platform
import socket
import uuid
import subprocess
import time
import requests
import json
import logging
import os
import hashlib
import random

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [AI-TRAFFIC-AGENT] %(message)s",
)
logger = logging.getLogger("NativeAIClientAgent")

BACKEND_URL = os.environ.get("BACKEND_URL", "https://proxyagent-dashboard.onrender.com")

AI_WORKLOAD_PROMPTS = [
    "Write a Python FastAPI endpoint implementing JWT authentication and rate limiting.",
    "Analyze PostgreSQL query execution plan for indexing optimization on large tables.",
    "Generate a secure Dockerfile following NIST SP 800-53 container hardening guidelines.",
    "Implement an asynchronous Three.js 3D mesh rendering loop with WebGL shaders.",
    "Review data privacy compliance requirements for GDPR article 32 data encryption.",
    "Create a Python script using cryptography.fernet for secure payload encryption.",
    "Design a modular network security packet filter for real-time threat detection."
]

def get_dynamic_bios_serial() -> str:
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("wmic bios get serialnumber", shell=True, text=True, timeout=3)
            lines = [line.strip() for line in output.split('\n') if line.strip()]
            if len(lines) > 1 and lines[1].lower() not in ["to be filled by o.e.m.", "system serial number", "default string"]:
                return lines[1]
        elif platform.system() == "Linux":
            if os.path.exists("/sys/class/dmi/id/product_serial"):
                with open("/sys/class/dmi/id/product_serial", "r") as f:
                    val = f.read().strip()
                    if val:
                        return val
    except Exception:
        pass
    return f"SYS-{platform.machine()}-{abs(hash(platform.node()))}"

def get_dynamic_mac_address() -> str:
    mac_num = uuid.getnode()
    mac_str = ':'.join(['{:02x}'.format((mac_num >> elements) & 0xff) for elements in range(40, -1, -8)])
    return mac_str.upper()

def get_dynamic_ip_address() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())

def collect_real_system_hardware() -> dict:
    hostname = socket.gethostname()
    mac_address = get_dynamic_mac_address()
    ip_address = get_dynamic_ip_address()
    bios_sn = get_dynamic_bios_serial()
    
    unique_seed = f"{hostname}-{mac_address}-{bios_sn}"
    hash_hex = hashlib.sha256(unique_seed.encode()).hexdigest()[:12].upper()
    hw_id = f"HW-{platform.system().upper()}-{hash_hex}"

    os_name = platform.system()
    os_release = platform.release()
    processor = platform.processor() or platform.machine()

    return {
        "hw_id": hw_id,
        "hostname": hostname,
        "mac_address": mac_address,
        "ip_address": ip_address,
        "bios_sn": bios_sn,
        "os": f"{os_name} {os_release}",
        "device_type": f"{os_name} Workstation ({platform.machine()})",
        "processor": processor,
        "compliance": "GDPR, NIST SP 800-53 & DPDP Act Active"
    }

def run_agent():
    logger.info("Initializing AI Traffic Client Agent...")
    hw_specs = collect_real_system_hardware()
    
    logger.info("Discovered Client Node:")
    logger.info(f" -> Hostname: {hw_specs['hostname']}")
    logger.info(f" -> IP Address: {hw_specs['ip_address']}")
    logger.info(f" -> Hardware ID: {hw_specs['hw_id']}")

    api_key = None

    try:
        reg_response = requests.post(f"{BACKEND_URL}/api/register", json=hw_specs, timeout=10)
        if reg_response.status_code == 200:
            data = reg_response.json()
            api_key = data.get("api_key")
            logger.info("Successfully registered client node with gateway.")
        else:
            logger.error(f"Registration failed with code: {reg_response.status_code}")
    except Exception as e:
        logger.error(f"Registration connection error: {e}")

    logger.info("Starting live AI traffic transmission stream...")
    headers = {'Content-Type': 'application/json', 'X-HW-ID': hw_specs['hw_id']}
    if api_key:
        headers['Authorization'] = f"Bearer {api_key}"

    while True:
        try:
            selected_prompt = random.choice(AI_WORKLOAD_PROMPTS)
            payload = {
                "payload": selected_prompt,
                "model": "gemini-2.5-pro",
                "provider": "Native Desktop AI Agent",
                "hostname": hw_specs['hostname'],
                "mac_address": hw_specs['mac_address'],
                "ip_address": hw_specs['ip_address'],
                "bios_sn": hw_specs['bios_sn'],
                "os": hw_specs['os'],
                "device_type": hw_specs['device_type']
            }
            res = requests.post(f"{BACKEND_URL}/v1/chat/completions", json=payload, headers=headers, timeout=10)
            if res.status_code == 200:
                logger.info(f"AI Traffic captured & logged! Prompt: '{selected_prompt[:35]}...'")
            else:
                logger.warning(f"Traffic transmission returned code: {res.status_code}")
        except Exception as ex:
            logger.error(f"Transmission failure: {ex}")

        time.sleep(8)

if __name__ == "__main__":
    run_agent()