import json
import requests
from mitmproxy import http

# Catch the exact API backend pathways modern browsers use for AI interfaces
# TARGET_DOMAINS = [
    # "chatgpt.com",
    # "openai.com",
    # "claude.ai",
    # "anthropic.com",
    # "perplexity.ai",
    # "gemini.google.com"
# ]

# def request(flow: http.HTTPFlow) -> None:
    # if any(domain in flow.request.pretty_url for domain in TARGET_DOMAINS):
        # Log request sighting immediately to the terminal console
        # print(f"[Proxy Detected Request] -> Host: {flow.request.pretty_host} | Path: {flow.request.path}")

# def response(flow: http.HTTPFlow) -> None:
    # if any(domain in flow.request.pretty_url for domain in TARGET_DOMAINS):
        # try:
            # url_host = flow.request.pretty_host
            # detected_model = "ChatGPT-User-Session"
            # tokens_status = "Streaming content capture active"

            # 1. Match the AI Web service interface being browsed
            # if "claude" in url_host or "anthropic" in url_host:
                # detected_model = "Claude-3.5-Sonnet"
            # elif "chatgpt" in url_host or "openai" in url_host:
                # detected_model = "GPT-5.5"  # Automatically adapted based on active interface session
            # elif "perplexity" in url_host:
                # detected_model = "Perplexity-Sonar"
            # elif "gemini" in url_host:
                # detected_model = "Gemini-1.5-Pro"

            # 2. Extract content text securely from streaming text fields if readable
            # body_text = flow.request.get_text(as_bytes=False) or ""
            # if body_text and '"model"' in body_text:
                # try:
                    # parsed_json = json.loads(body_text)
                    # if "model" in parsed_json:
                        # detected_model = str(parsed_json["model"])
                # except Exception:
                    # pass # Fallback to mapped default if format is nested text

            # 3. Create the robust telemetry bundle payload 
            # live_payload = {
                # "model": detected_model,
                # "prompt_score": "Verified Secure",
                # "reasoning": "Active",
                # "client": flow.client_conn.peername[0] if flow.client_conn.peername else "127.0.0.1",
                # "tokens": "Token exchange captured successfully"
            # }
            
            # print(f"[Proxy Sync] Relaying dynamic metrics payload to local dashboard...")
            
            # Post metrics directly over to our listening analytics hub endpoint
            # resp = requests.post(
                # "http://127.0.0.1:5050/api/ingest-event", 
                # json=live_payload, 
                # timeout=2.0
            # )
            # print(f"[Proxy Sync Success] Dashboard Route Response Status Code: {resp.status_code}")
            
        # except Exception as err:
            # print(f"[Proxy Pipeline Exception Error]: {err}")
            
            
            
            
            
            
            
import requests
import datetime

SUPABASE_URL = "https://qwsnkbpsumqobrqkqpht.supabase.co/rest/v1/network_logs"
SUPABASE_KEY = "sb_publishable_IPKGvB9I6G7Ix0q2kkpucw_8JdGDaHh"

def response(flow):
    # Extract the traffic info
    log_data = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "url": flow.request.pretty_url,
        "method": flow.request.method,
        "status_code": flow.response.status_code,
        "user_id": "unique_user_id_here"  # Helps differentiate traffic inside the cloud dashboard
    }
    
    # Send securely to your Supabase cloud database
    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        requests.post(SUPABASE_URL, json=log_data, headers=headers, timeout=2)
    except requests.exceptions.RequestException:
        pass # Fail silently if network drops to preserve proxy performance