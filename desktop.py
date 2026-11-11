
import sys
import time
import socket
import threading
from pathlib import Path

import webview
from streamlit.web import cli as stcli


PORT = 8501

if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys._MEIPASS)
else:
    BASE_DIR = Path(__file__).resolve().parent

APP_PATH = BASE_DIR / "app.py"


def run_streamlit():
    sys.argv = [
        "streamlit",
        "run",
        str(APP_PATH),
        "--server.headless=true",
        f"--server.port={PORT}",
        "--server.address=127.0.0.1"
    ]

    stcli.main()


def wait_for_server():
    for _ in range(60):
        try:
            with socket.create_connection(
                ("127.0.0.1", PORT), timeout=1
            ):
                return True
        except OSError:
            time.sleep(1)

    return False


def main():
    server_thread = threading.Thread(
        target=run_streamlit,
        daemon=True
    )
    server_thread.start()

    if not wait_for_server():
        raise RuntimeError("USB Guardian AI failed to start.")

    webview.create_window(
        "USB Guardian AI",
        f"http://127.0.0.1:{PORT}",
        width=1200,
        height=800
    )

    webview.start()


if __name__ == "__main__":
    main()
