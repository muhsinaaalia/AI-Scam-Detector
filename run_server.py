import sys
import webbrowser
import threading
import time
import uvicorn

def open_browser(url: str):
    time.sleep(1.2)
    try:
        webbrowser.open(url)
    except Exception:
        pass

if __name__ == "__main__":
    port = 8000
    url = f"http://localhost:{port}"
    print(f"=====================================================")
    print(f"  SCAMSHIELD: AI-Powered Scam & Phishing Analyzer   ")
    print(f"  Tagline: 'Think before you click.'                ")
    print(f"  Launching server at {url}...                     ")
    print(f"=====================================================")
    
    # Launch browser automatically
    threading.Thread(target=open_browser, args=(url,), daemon=True).start()
    
    uvicorn.run("server:app", host="127.0.0.1", port=port, reload=False)
