import sys
import os
import asyncio
import errno
import importlib.util
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

async def start_proxy():
    options = Options(
        listen_host='0.0.0.0',
        listen_port=8080,
        upstream_cert=False,
        ssl_insecure=True, 
        # Expanded telemetry ignore patterns to drop background asset tracker requests
        ignore_hosts=[
            r".*supabase\.co(: \d+)?",
            r".*onrender\.com(: \d+)?",
            r".*linkedin\.com(: \d+)?",
            r".*render\.com(: \d+)?",
            r".*intercom\.io(: \d+)?",
            r".*whatsapp\.com(: \d+)?",
            r".*github\.com(: \d+)?",
            r".*clients6\.google\.com(: \d+)?",
            r".*stripe\.com(: \d+)?",
            r".*bing\.com(: \d+)?",
            r".*google\.com\/log.*",
            r".*microsoft\.com(: \d+)?",
        ]
    )

    master = DumpMaster(options)
    script_path = os.path.abspath("ai_agent_proxy.py")
    
    if not os.path.exists(script_path):
        print(f"[Proxy Error] Interceptor script not found at target directory: {script_path}", file=sys.stderr)
        return

    try:
        spec = importlib.util.spec_from_file_location("ai_agent_proxy", script_path)
        ai_agent_proxy_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ai_agent_proxy_module)
        
        master.addons.add(ai_agent_proxy_module)
        print("[Proxy Matrix Sync] Interceptor script 'ai_agent_proxy.py' successfully attached.")
    except Exception as script_err:
        print(f"[Proxy Error] Failed to compile and load interceptor logic: {script_err}", file=sys.stderr)
        return

    print("[Proxy Matrix Sync] Initializing network interface on port 8080...")

    try:
        await master.run()
    except OSError as os_err:
        if getattr(os_err, 'winerror', None) == 64 or os_err.errno == errno.WSAENETRESET:
            print("[Proxy Warning] Network socket connection dropped by host OS or client. Continuing loop...", file=sys.stderr)
        else:
            print(f"[Proxy Network Error] OS Network Exception encountered: {os_err}", file=sys.stderr)
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        print("[Proxy Matrix Sync] Shutting down master...")
        try:
            master.shutdown()
        except Exception:
            pass

if __name__ == "__main__":
    try:
        asyncio.run(start_proxy())
    except (KeyboardInterrupt, SystemExit):
        print("\n[Proxy Matrix Sync] Interceptor shut down successfully.")