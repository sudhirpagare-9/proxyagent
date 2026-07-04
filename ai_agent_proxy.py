import json
from mitmproxy import http
from supabase import create_client, Client

SUPABASE_URL = "https://your-project-id.supabase.co"
SUPABASE_KEY = "your-supabase-anon-key-here"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

TARGET_DOMAINS = ["chatgpt.com", "openai.com", "claude.ai", "anthropic.com", "perplexity.ai", "gemini.google.com"]

def response(flow: http.HTTPFlow) -> None:
    if any(domain in flow.request.pretty_url for domain in TARGET_DOMAINS):
        try:
            url_host = flow.request.pretty_host
            
            # Default fallback initial tracking assignments
            model_name = "AI Model Session"
            version = "Stable"
            thinking_level = "Standard"
            input_tokens = 450
            output_tokens = 280
            balance_tokens = 94500
            subscription_details = "Pro Tier"

            if "claude" in url_host:
                model_name = "Claude"
                version = "3.5 Sonnet"
                thinking_level = "High"
            elif "chatgpt" in url_host or "openai" in url_host:
                model_name = "GPT"
                version = "4o"
                thinking_level = "Dynamic"
            elif "gemini" in url_host:
                model_name = "Gemini"
                version = "1.5 Pro"
                thinking_level = "Adaptive"

            # Parse structural JSON if body contents allow
            body_text = flow.request.get_text(as_bytes=False) or ""
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
            
            supabase.table("network_logs").insert(log_payload).execute()
            print(f"[Proxy Matrix Sync] Log entry generated for {model_name} ({version})")
        except Exception as err:
            print(f"[Proxy Error]: {err}")