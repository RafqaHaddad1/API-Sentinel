import threading
import time

import uvicorn

from backend.api import app as proxy_app
from backend.backend_simulator import app as backend_app
from dashboard.app import app as dashboard_app


def run_dummy_backend():
    uvicorn.run(backend_app, host="127.0.0.1", port=8001, log_level="warning")


def run_proxy():
    uvicorn.run(proxy_app, host="127.0.0.1", port=8000, log_level="info")


def run_dashboard():
    dashboard_app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)


if __name__ == "__main__":
    threading.Thread(target=run_dummy_backend, daemon=True).start()
    threading.Thread(target=run_proxy, daemon=True).start()
    threading.Thread(target=run_dashboard, daemon=True).start()

    print("✅ API Sentinel system is running")
    print("Dashboard: http://127.0.0.1:5000")
    print("Proxy/API Security Layer: http://127.0.0.1:8000")
    print("Dummy Backend: http://127.0.0.1:8001")
    print("Press CTRL+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped.")
