import json
from mitmproxy import http
from supabase import create_client, Client

# Update these with your absolute project dashboard database credentials
SUPABASE_URL = "https://your-project-id.supabase.co"
SUPABASE_KEY = "your-supabase-anon-key-here"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

TARGET_DOMAINS = [
    "chatgpt.com",
    "openai.com",
    "claude.ai",
    "anthropic.com",
    "perplexity.ai",
    "gemini.google.com"
]

def response(flow: http.HTTPFlow) -> None:
    if any(domain in flow.request.pretty_url for domain in TARGET_DOMAINS):
        try:
            url_host = flow.request.pretty_host
            detected_model = "AI Web Session"

            if "claude" in url_host:
                detected_model = "Claude-3.5-Sonnet"
            elif "chatgpt" in url_host or "openai" in url_host:
                detected_model = "GPT-5.5"
            elif "perplexity" in url_host:
                detected_model = "Perplexity-Sonar"
            elif "gemini" in url_host:
                detected_model = "Gemini-1.5-Pro"

            body_text = flow.request.get_text(as_bytes=False) or ""
            if body_text and '"model"' in body_text:
                try:
                    parsed = json.loads(body_text)
                    if "model" in parsed:
                        detected_model = str(parsed["model"])
                except Exception:
                    pass

            log_payload = {
                "model": detected_model,
                "tokens": "Token transaction event intercepted successfully"
            }
            
            print(f"[Proxy Sync] Streaming interception to Supabase cloud storage...")
            supabase.table("network_logs").insert(log_payload).execute()
            print("[Proxy Sync Success] Transaction row written to cloud database.")

        except Exception as err:
            print(f"[Proxy Sync Error]: {err}")