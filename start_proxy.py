import sys
import os
from mitmproxy.tools.main import mitmdump

if __name__ == "__main__":
    # Ensure mitmproxy can locate your installed site-packages
    sys.path.append(os.path.dirname(sys.executable))
    
    sys.argv = [
        "mitmdump", 
        "-p", "8085",                  
        "-s", "ai_agent_proxy.py", 
        "--set", "upstream_cert=false",
        "--set", "ssl_verify_upstream_trusted=false"
    ]
    
    print("[Proxy Matrix Sync] Initializing interceptor network interface on port 8085...")
    try:
        mitmdump()
    except Exception as e:
        print(f"[Proxy Error] Failed to execute mitmdump: {e}", file=sys.stderr)