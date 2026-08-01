#!/usr/bin/env python3
"""
Zero-Dependency Desktop Agent (Windows / Linux / macOS)
Extracts hardware serial numbers and streams RSA-OAEP encrypted telemetry.
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
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

DASHBOARD_URL = "https://proxyagent-dashboard.onrender.com"
HEADERS = {"Content-Type": "application/json"}

def get_hardware_uuid() -> str:
    sys_type = platform.system()
    raw_id = ""

    try:
        if sys_type == "Windows":
            cmd = 'powershell -NoProfile -Command "(Get-CimInstance Win32_ComputerSystemProduct).UUID"'
            raw_id = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
        elif sys_type == "Linux":
            if os.path.exists("/etc/machine-id"):
                with open("/etc/machine-id", "r") as f:
                    raw_id = f.read().strip()
        elif sys_type == "Darwin":
            cmd = "system_profiler SPHardwareDataType | grep 'Serial Number'"
            raw_id = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().split()[-1]
    except Exception:
        pass

    if not raw_id:
        raw_id = f"{socket.gethostname()}-{uuid.getnode()}"

    hashed = hashlib.sha256(raw_id.encode('utf-8')).hexdigest()[:12].upper()
    return f"{sys_type[:3].upper()}-{hashed}"

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

def register():
    payload = {
        "hw_id": AGENT_ID,
        "hostname": socket.gethostname(),
        "mac_address": "00:00:00:00:00:00",
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
            print(f"[+] Device Registered: {resp.read().decode('utf-8')}")
    except Exception as e:
        print(f"[-] Registration Error: {e}")

def send_telemetry():
    pub_key = get_server_public_key()
    if not pub_key:
        print("[-] Skipping transmission: Public key uninitialized.")
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
    
    # Encrypt payload using RSA-OAEP SHA-256
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
    except Exception as e:
        print(f"[-] Transmission Error: {e}")

if __name__ == "__main__":
    print(f"[*] Starting Desktop Agent [{AGENT_ID}]...")
    register()
    while True:
        send_telemetry()
        time.sleep(8)