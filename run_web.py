#!/usr/bin/env python
# run_web.py -- Launcher for Sentinels Web Cockpit
import sys
import os
import webbrowser
from pathlib import Path

# Add src/ to python path
src_dir = Path(__file__).resolve().parent / "src"
sys.path.insert(0, str(src_dir))

def main():
    print("""
   ____             _   _            _
  / ___|  ___ _ __ | |_(_)_ __   ___| |___
  \___ \ / _ \ '_ \| __| | '_ \ / _ \ / __|
   ___) |  __/ | | | |_| | | | |  __/ \__ \
  |____/ \___|_| |_|\__|_|_| |_|\___|_|___/
  
  🛡️  Sentinels Web Cockpit — Stitch Design System
  Enterprise Multi-Agent Security Audit Dashboard
  """)

    import uvicorn
    from dotenv import load_dotenv
    load_dotenv()

    host = "127.0.0.1"
    port = int(os.getenv("PORT", "8000"))

    url = f"http://{host}:{port}"
    print(f"  ► Launching UI at: {url}")
    print(f"  ► Press Ctrl+C to terminate the web server.\n")

    try:
        uvicorn.run("sentinels.web.server:app", host=host, port=port, log_level="info")
    except KeyboardInterrupt:
        print("\n  Web cockpit shutdown safely.")

if __name__ == "__main__":
    main()
