import os
import sys
import threading
import time

import pytest
import requests

os.environ.setdefault("VULNERABLE_MODE", "true")

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
TARGET_API_DIR = os.path.join(REPO_ROOT, "target_api")
sys.path.insert(0, os.path.abspath(REPO_ROOT))       # so `import scanner...` works
sys.path.insert(0, os.path.abspath(TARGET_API_DIR))  # so `import app` (target_api/app.py) works


@pytest.fixture(scope="session")
def vulnerable_target():
    """Runs target_api/app.py (VULNERABLE_MODE=true) in a background
    thread on port 5050 for the duration of the test session."""
    import app as target_app  # target_api/app.py

    thread = threading.Thread(
        target=lambda: target_app.app.run(host="127.0.0.1", port=5050, use_reloader=False, threaded=True),
        daemon=True,
    )
    thread.start()

    base_url = "http://127.0.0.1:5050"
    for _ in range(30):
        try:
            requests.get(f"{base_url}/health", timeout=1)
            return base_url
        except requests.exceptions.ConnectionError:
            time.sleep(0.3)
    raise RuntimeError("target API did not start in time")
