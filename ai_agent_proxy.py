import os
import json
import asyncio
from mitmproxy import http
from supabase import create_client, Client

SUPABASE_URL = os.environ.get("SUPABASE_URL") or "https://qwsnkbpsumqobrqkqpht.supabase.co"
SUPABASE_KEY = os.environ.get("SUPABASE_KEY") or "sb_publishable_IPKGvB9I6G7Ix0q2kkpucw_8JdGDaHh"

# Keep the client initialization global
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
TARGET_DOMAINS = ["chatgpt.com", "openai.com", "claude.ai", "anthropic.com", "perplexity.ai", "gemini.google.com", "google.com"]

# A helper function to safely process the blocking Supabase I/O in a background thread
def _sync_db_insert(payload):
    try:
        supabase.table("network_logs").insert(payload).execute()
        print(f"[Proxy Matrix Sync] Success! Stored stream event row for {payload.get('model_name')}.")
    except Exception as err:
        print(f"[Proxy Insertion Error]: {err}")

async def request(flow: http.HTTPFlow) -> None:
    if any(domain in flow.request.pretty_url for domain in TARGET_DOMAINS):
        print(f"[Proxy Intercept Outbound] Target traffic spotted: {flow.request.pretty_url}")

async def response(flow: http.HTTPFlow) -> None:
    if any(domain in flow.request.pretty_url for domain in TARGET_DOMAINS):
        if flow.request.method == "OPTIONS":
            return
            
        try:
            url_host = flow.request.pretty_host.lower()
            print(f"[Proxy Intercept Activity] Processing traffic stream from: {url_host} (Status: {flow.response.status_code})")
            
            # Default values (Preserved)
            model_name, version, thinking_level = "AI Model Session", "Stable", "Standard"
            input_tokens, output_tokens, balance_tokens = 520, 340, 88400
            subscription_details = "Pro Tier"

            if "claude" in url_host or "anthropic" in url_host:
                model_name, version, thinking_level = "Claude", "3.5 Sonnet", "High"
            elif "perplexity" in url_host:
                model_name, version, thinking_level = "Perplexity", "Sonar Online", "Deep Research"
            elif "gemini" in url_host or "google" in url_host:
                model_name, version, thinking_level = "Gemini", "1.5 Pro", "Adaptive"
            elif "chatgpt" in url_host or "openai" in url_host:
                model_name, version, thinking_level = "GPT", "4o", "Dynamic"

            body_text = flow.request.get_text() or ""
            if body_text:
                try:
                    parsed = json.loads(body_text)
                    if isinstance(parsed, dict):
                        if "model" in parsed:
                            version = str(parsed["model"])
                        if "usage" in parsed and isinstance(parsed["usage"], dict):
                            input_tokens = parsed["usage"].get("prompt_tokens", input_tokens)
                            output_tokens = parsed["usage"].get("completion_tokens", output_tokens)
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
            
            # CRITICAL FIX: Run the database insertion completely asynchronously in a separate worker thread.
            # This allows mitmproxy to immediately return the network payload to the browser/client without waiting for the DB.
            loop = asyncio.get_running_loop()
            loop.run_in_executor(None, _sync_db_insert, log_payload)

        except Exception as err:
            print(f"[Proxy Processing Error]: {err}")

async def error(flow: http.HTTPFlow) -> None:
    if any(domain in flow.request.pretty_url for domain in TARGET_DOMAINS):
        print(f"[Proxy TLS Error] Connection dropped for {flow.request.pretty_url}. Error: {flow.error}")