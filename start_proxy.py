import sys
import os
import asyncio
import importlib.util
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

# Use absolute path relative to the file location
def get_resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

async def start_proxy_async():
    # Dynamic port 0 = OS assigns free port
    options = Options(listen_host='127.0.0.1', listen_port=0, ssl_insecure=True)
    master = DumpMaster(options)
    
    script_path = get_resource_path("ai_agent_proxy.py")
    
    spec = importlib.util.spec_from_file_location("ai_agent_proxy", script_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    master.addons.add(module)
    
    await master.run()

if __name__ == "__main__":
    asyncio.run(start_proxy_async())