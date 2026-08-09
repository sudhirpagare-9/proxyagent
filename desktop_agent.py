import platform
import socket
import uuid
import subprocess
import time
import requests
import json
import logging
import os

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [DYNAMIC-AGENT] %(message)s",
)
logger = logging.getLogger("NativeClientAgent")

BACKEND_URL = os.environ.get("BACKEND_URL", "https://proxyagent-dashboard.onrender.com")

def get_dynamic_bios_serial() -> str:
    """Dynamically queries system BIOS serial number from operating system."""
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
    """Extracts true physical MAC address."""
    mac_num = uuid.getnode()
    mac_str = ':'.join(['{:02x}'.format((mac_num >> elements) & 0xff) for elements in range(40, -1, -8)])
    return mac_str.upper()

def get_dynamic_ip_address() -> str:
    """Discovers active local IP address dynamically."""
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
    
    # Unique ID bound strictly to actual hardware attributes
    hw_id = f"HW-{platform.system().upper()}-{abs(hash(hostname + mac_address))}"

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
    logger.info("Initializing Dynamic Hardware Telemetry Agent...")
    hw_specs = collect_real_system_hardware()
    
    logger.info("Discovered System Hardware:")
    logger.info(f" -> Hostname: {hw_specs['hostname']}")
    logger.info(f" -> IP Address: {hw_specs['ip_address']}")
    logger.info(f" -> MAC Address: {hw_specs['mac_address']}")
    logger.info(f" -> Hardware ID: {hw_specs['hw_id']}")
    logger.info(f" -> BIOS Serial: {hw_specs['bios_sn']}")

    api_key = None

    # Step 1: Register dynamic node with backend
    try:
        reg_response = requests.post(f"{BACKEND_URL}/api/register", json=hw_specs, timeout=10)
        if reg_response.status_code == 200:
            data = reg_response.json()
            api_key = data.get("api_key")
            logger.info("Successfully registered dynamic node with gateway.")
        else:
            logger.error(f"Registration failed with code: {reg_response.status_code}")
    except Exception as e:
        logger.error(f"Registration connection error: {e}")

    # Step 2: Continuous live telemetry stream loop
    logger.info("Starting live telemetry stream...")
    headers = {'Content-Type': 'application/json', 'X-HW-ID': hw_specs['hw_id']}
    if api_key:
        headers['Authorization'] = f"Bearer {api_key}"

    while True:
        try:
            payload = {
                "payload": f"Dynamic Telemetry Heartbeat from {hw_specs['hostname']} [IP: {hw_specs['ip_address']}]",
                "model": "gemini-2.5-pro",
                "provider": "Native Python Agent",
                "hostname": hw_specs['hostname'],
                "mac_address": hw_specs['mac_address'],
                "ip_address": hw_specs['ip_address'],
                "bios_sn": hw_specs['bios_sn'],
                "os": hw_specs['os'],
                "device_type": hw_specs['device_type']
            }
            res = requests.post(f"{BACKEND_URL}/v1/chat/completions", json=payload, headers=headers, timeout=10)
            if res.status_code == 200:
                logger.info(f"Telemetry pushed successfully. Host: {hw_specs['hostname']} | IP: {hw_specs['ip_address']}")
            else:
                logger.warning(f"Telemetry push returned code: {res.status_code}")
        except Exception as ex:
            logger.error(f"Transmission failure: {ex}")

        time.sleep(5)

if __name__ == "__main__":
    run_agent()