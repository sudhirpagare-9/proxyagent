import os
import json
import socket
import uuid
import asyncio
import requests
from mitmproxy import http

# Route traffic metrics directly through the centralized app pipeline
INGEST_URL = "https://proxyagent-dashboard.onrender.com/api/ingest"
TARGET_DOMAINS = ["chatgpt.com", "openai.com", "claude.ai", "anthropic.com", "perplexity.ai", "gemini.google.com", "google.com"][cite: 5]

def get_system_identifiers():
    try:
        hostname = socket.gethostname()
        mac_int = uuid.getnode()
        mac_str = ':'.join(['{:02x}'.format((mac_int >> i) & 0xff) for i in range(0, 8*6, 8)][::-1])[cite: 3]
        hw_id = f"HW-{hostname.upper()}-{mac_int}"[cite: 3]
        return hw_id, hostname, mac_str
    except Exception:
        return "HW-UNKNOWN", "Unknown-Host", "00:00:00:00:00:00"[cite: 3]

# Read hardware fingerprint locally 
HW_ID, HOSTNAME, MAC_ADDRESS = get_system_identifiers()

def parse_application_name(user_agent_string):
    if not user_agent_string:
        return "Generic HTTP App"
    
    ua = user_agent_string.lower()
    if "cursor" in ua:
        return "VS Code (Cursor)"
    elif "code" in ua or "vscode" in ua:
        return "VS Code Editor"
    elif "chrome" in ua and "chromium" not in ua:
        return "Chrome Browser"
    elif "safari" in ua and "chrome" not in ua:
        return "Safari Browser"
    elif "edge" in ua:
        return "Edge Browser"
    elif "firefox" in ua:
        return "Firefox Browser"
    elif "postman" in ua:
        return "Postman Client"
    elif "python-requests" in ua:
        return "Python Requests"
    return user_agent_string[:24] # Fallback to shortened raw User-Agent

def _forward_to_ingest_pipeline(payload):
    try:
        # Offload network payload delivery to the central system registry
        response = requests.post(INGEST_URL, json=payload, timeout=5)[cite: 3]
        print(f"[Proxy Matrix Sync] Ingest Node Status Code Response: {response.status_code}")
    except Exception as err:
        print(f"[Proxy Outbound Sync Error]: {err}")

async def request(flow: http.HTTPFlow) -> None:
    if any(domain in flow.request.pretty_url for domain in TARGET_DOMAINS):[cite: 5]
        print(f"[Proxy Intercept Outbound] Target traffic spotted: {flow.request.pretty_url}")[cite: 5]

async def response(flow: http.HTTPFlow) -> None:
    if any(domain in flow.request.pretty_url for domain in TARGET_DOMAINS):[cite: 5]
        if flow.request.method == "OPTIONS":[cite: 5]
            return[cite: 5]
            
        try:
            url_host = flow.request.pretty_host.lower()[cite: 5]
            print(f"[Proxy Intercept Activity] Processing traffic stream from: {url_host}")
            
            # Match baseline structures
            model_name, version, thinking_level = "AI Model Session", "Stable", "Standard"[cite: 5]
            input_tokens, output_tokens, balance_tokens = 520, 340, 88400[cite: 5]
            subscription_details = "Pro Tier"[cite: 5]

            if "claude" in url_host or "anthropic" in url_host:[cite: 5]
                model_name, version, thinking_level = "Claude", "3.5 Sonnet", "High"[cite: 5]
            elif "perplexity" in url_host:[cite: 5]
                model_name, version, thinking_level = "Perplexity", "Sonar Online", "Deep Research"[cite: 5]
            elif "gemini" in url_host or "google" in url_host:[cite: 5]
                model_name, version, thinking_level = "Gemini", "1.5 Pro", "Adaptive"[cite: 5]
            elif "chatgpt" in url_host or "openai" in url_host:[cite: 5]
                model_name, version, thinking_level = "GPT", "4o", "Dynamic"[cite: 5]

            # Intercept payload metadata if available
            body_text = flow.request.get_text() or ""[cite: 5]
            if body_text:
                try:
                    parsed = json.loads(body_text)[cite: 5]
                    if isinstance(parsed, dict):[cite: 5]
                        if "model" in parsed:[cite: 5]
                            version = str(parsed["model"])[cite: 5]
                        if "usage" in parsed and isinstance(parsed["usage"], dict):[cite: 5]
                            input_tokens = parsed["usage"].get("prompt_tokens", input_tokens)[cite: 5]
                            output_tokens = parsed["usage"].get("completion_tokens", output_tokens)[cite: 5]
                except Exception:
                    pass

            # Extract source browser identity from the actual live request headers
            user_agent = flow.request.headers.get("User-Agent", "Generic HTTP App")
            detected_app = parse_application_name(user_agent)

            # Package telemetry payload
            log_payload = {
                "hw_id": HW_ID,
                "hostname": HOSTNAME,
                "mac_address": MAC_ADDRESS,
                "model_name": model_name,[cite: 5]
                "version": version,[cite: 5]
                "thinking_level": thinking_level,[cite: 5]
                "input_tokens": int(input_tokens),[cite: 5]
                "output_tokens": int(output_tokens),[cite: 5]
                "balance_tokens": int(balance_tokens),[cite: 5]
                "subscription_details": subscription_details,[cite: 5]
                "app_name": detected_app
            }
            
            # Execute worker thread safely to keep your browsing latency near zero
            loop = asyncio.get_running_loop()[cite: 5]
            loop.run_in_executor(None, _forward_to_ingest_pipeline, log_payload)

        except Exception as err:
            print(f"[Proxy Processing Error]: {err}")[cite: 5]

async def error(flow: http.HTTPFlow) -> None:
    if any(domain in flow.request.pretty_url for domain in TARGET_DOMAINS):[cite: 5]
        print(f"[Proxy TLS Error] Connection dropped for {flow.request.pretty_url}. Error: {flow.error}")[cite: 5]