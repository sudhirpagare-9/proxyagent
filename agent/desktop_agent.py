#!/usr/bin/env python3
"""
Zero-Dependency Desktop Agent (Windows / Linux / macOS)
Extracts hardware BIOS serial numbers & UUID for uniqueness.
Streams RSA-OAEP encrypted telemetry and auto-reregisters if deleted.
"""

import os
import sys
import json
import socket
import uuid
import time
import secrets
import platform
import subprocess
import hashlib
import base64
import urllib.request
import urllib.error
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

DASHBOARD_URL = "https://proxyagent-dashboard.onrender.com"
HEADERS = {"Content-Type": "application/json"}

def get_real_mac_address() -> str:
    """Gets formatted local hardware MAC address."""
    node = uuid.getnode()
    mac_hex = f"{node:012x}"
    return ":".join(mac_hex[i:i+2] for i in range(0, 12, 2))

def get_hardware_uuid() -> str:
    """Extracts BIOS Serial Number and Hardware UUID for uniqueness."""
    sys_type = platform.system()
    bios_serial = ""
    system_uuid = ""

    def clean_val(val: str) -> str:
        if not val:
            return ""
        v = val.strip().strip('"').strip("'")
        invalid = ["to be filled", "default string", "none", "00000000", "unknown"]
        if any(inv in v.lower() for inv in invalid):
            return ""
        return v

    try:
        if sys_type == "Windows":
            cmd_bios = 'powershell -NoProfile -Command "(Get-CimInstance Win32_Bios).SerialNumber"'
            bios_serial = clean_val(subprocess.check_output(cmd_bios, shell=True, stderr=subprocess.DEVNULL).decode())

            cmd_uuid = 'powershell -NoProfile -Command "(Get-CimInstance Win32_ComputerSystemProduct).UUID"'
            system_uuid = clean_val(subprocess.check_output(cmd_uuid, shell=True, stderr=subprocess.DEVNULL).decode())

        elif sys_type == "Linux":
            if os.path.exists("/sys/class/dmi/id/product_uuid"):
                with open("/sys/class/dmi/id/product_uuid", "r") as f:
                    system_uuid = clean_val(f.read())
            if os.path.exists("/sys/class/dmi/id/bios_serial"):
                with open("/sys/class/dmi/id/bios_serial", "r") as f:
                    bios_serial = clean_val(f.read())
            if not system_uuid and os.path.exists("/etc/machine-id"):
                with open("/etc/machine-id", "r") as f:
                    system_uuid = clean_val(f.read())

        elif sys_type == "Darwin":
            cmd = "ioreg -l | grep IOPlatformSerialNumber"
            raw = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode()
            if "=" in raw:
                bios_serial = clean_val(raw.split("=")[-1])
    except Exception:
        pass

    raw_combined = f"{bios_serial}:{system_uuid}"
    if not bios_serial and not system_uuid:
        raw_combined = f"{socket.gethostname()}:{get_real_mac_address()}"

    hashed = hashlib.sha256(raw_combined.encode('utf-8')).hexdigest()[:12].upper()
    prefix = "SUPLAPTOP" if "laptop" in socket.gethostname().lower() or sys_type == "Windows" else sys_type[:3].upper()
    return f"{prefix}-{hashed}"

AGENT_ID = get_hardware_uuid()
cached_public_key = None

def get_server_public_key():
    global cached_public_key
    if cached_public_key:
        return cached_public_key

    try:
        req = urllib.request.Request(f"{DASHBOARD_URL}/public-key")
        with urllib.request.urlopen(req, timeout=10) as resp:
            pem_bytes = resp.read()
            cached_public_key = serialization.load_pem_public_key(pem_bytes)
            return cached_public_key
    except Exception as e:
        print(f"[-] Failed to fetch public key from server: {e}")
        return None

def register() -> bool:
    payload = {
        "hw_id": AGENT_ID,
        "hostname": socket.gethostname(),
        "mac_address": get_real_mac_address(),
        "ip_address": "127.0.0.1",
        "client_name": f"DesktopAgent-{platform.system()}",
        "model_name": "Sonar 2 Pro",
        "model_version": "v2.5",
        "think_level": "High",
        "subscription_status": "ACTIVE",
        "country": "IND",
        "geo_location": "Maharashtra"
    }
    req = urllib.request.Request(f"{DASHBOARD_URL}/register", data=json.dumps(payload).encode('utf-8'), headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"[+] Device Registered Successfully [{AGENT_ID}]: {resp.read().decode('utf-8')}")
            return True
    except urllib.error.HTTPError as http_err:
        try:
            err_body = http_err.read().decode('utf-8')
            print(f"[-] Registration Error [HTTP {http_err.code}]: {err_body}")
        except Exception:
            print(f"[-] Registration Error: {http_err}")
    except Exception as e:
        print(f"[-] Registration Error: {e}")
    return False

def send_telemetry():
    pub_key = get_server_public_key()
    if not pub_key:
        print("[-] Skipping transmission: Server public key unavailable.")
        return

    payload = {
        "m": "Sonar 2 Pro",
        "v": "v2.5",
        "t": platform.system(),
        "l": "High",
        "i": secrets.randbelow(300) + 100,
        "o": secrets.randbelow(600) + 200,
        "b": 8500,
        "s": "ACTIVE"
    }
    
    raw_payload_bytes = json.dumps(payload).encode('utf-8')
    try:
        encrypted_bytes = pub_key.encrypt(
            raw_payload_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')
    except Exception as enc_err:
        print(f"[-] Encryption Error: {enc_err}")
        return

    body = json.dumps({
        "hw_id": AGENT_ID,
        "encrypted_payload": encrypted_b64
    }).encode('utf-8')

    req = urllib.request.Request(f"{DASHBOARD_URL}/log-traffic", data=body, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"[+] E2EE Telemetry Sent [{platform.system()}]: {resp.read().decode('utf-8')}")
    except urllib.error.HTTPError as http_err:
        if http_err.code == 404:
            print(f"[!] Server returned 404 (Client record deleted/unregistered). Triggering re-registration...")
            register()
        else:
            try:
                err_body = http_err.read().decode('utf-8')
                print(f"[-] Transmission Error [HTTP {http_err.code}]: {err_body}")
            except Exception:
                print(f"[-] Transmission Error: {http_err}")
    except Exception as e:
        print(f"[-] Transmission Error: {e}")

if __name__ == "__main__":
    print(f"[*] Starting Desktop Agent [{AGENT_ID}]...")
    register()
    while True:
        send_telemetry()
        time.sleep(8)