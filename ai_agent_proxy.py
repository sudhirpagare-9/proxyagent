import os
import json
from mitmproxy import http
from supabase import create_client, Client

SUPABASE_URL = os.environ.get("SUPABASE_URL") or "https://your-actual-project-id.supabase.co"
SUPABASE_KEY = os.environ.get("SUPABASE_KEY") or "your-actual-anon-key-here"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
TARGET_DOMAINS = ["chatgpt.com", "openai.com", "claude.ai", "anthropic.com", "perplexity.ai", "gemini.google.com"]

# Operational Diagnostic: Confirm visibility of outbound target requests
def request(flow: http.HTTPFlow) -> None:
    if any(domain in flow.request.pretty_url for domain in TARGET_DOMAINS):
        print(f"[Proxy Intercept Outbound] Target traffic spotted: {flow.request.pretty_url}")

def response(flow: http.HTTPFlow) -> None:
    if any(domain in flow.request.pretty_url for domain in TARGET_DOMAINS):
        try:
            url_host = flow.request.pretty_host
            print(f"[Proxy Intercept Activity] Caught streaming response from: {url_host}")
            
            # Default fallback mappings
            model_name, version, thinking_level = "AI Model Session", "Stable", "Standard"
            input_tokens, output_tokens, balance_tokens = 520, 340, 88400
            subscription_details = "Pro Tier"

            if "claude" in url_host:
                model_name, version, thinking_level = "Claude", "3.5 Sonnet", "High"
            elif "chatgpt" in url_host or "openai" in url_host:
                model_name, version, thinking_level = "GPT", "4o", "Dynamic"
            elif "gemini" in url_host:
                model_name, version, thinking_level = "Gemini", "1.5 Pro", "Adaptive"
            elif "perplexity" in url_host:
                model_name, version, thinking_level = "Perplexity", "Sonar Online", "Deep Research"

            # Parse dynamic model properties if available safely
            body_text = flow.request.get_text() or ""
            if body_text and '"model"' in body_text:
                try:
                    parsed = json.loads(body_text)
                    if "model" in parsed:
                        version = str(parsed["model"])
                except Exception:
                    pass

            log_payload = {
                "model_name": model_name,
                "version": version,
                "thinking_level": thinking_level,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "balance_tokens": balance_tokens,
                "subscription_details": subscription_details
            }
            
            # Fire data stream directly into Supabase
            res = supabase.table("network_logs").insert(log_payload).execute()
            print(f"[Proxy Matrix Sync] Success! Stored row in DB for {model_name}.")
        except Exception as err:
            print(f"[Proxy Insertion Error]: {err}")

# Error tracking hook to capture dropped TLS connection handshakes
def error(flow: http.HTTPFlow) -> None:
    if any(domain in flow.request.pretty_url for domain in TARGET_DOMAINS):
        print(f"[Proxy TLS Error] Connection dropped for {flow.request.pretty_url}. Error: {flow.error}")