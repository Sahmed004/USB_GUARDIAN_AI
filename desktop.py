
import sys
import time
import socket
import multiprocessing
from pathlib import Path

import webview
from streamlit.web import cli as stcli


PORT = 8501
HOST = "127.0.0.1"


# Locate the application files
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
        "--global.developmentMode=false",
        "--server.headless=true",
        f"--server.port={PORT}",
        f"--server.address={HOST}",
        "--browser.gatherUsageStats=false"
    ]

    stcli.main()


def wait_for_server(process):

    for _ in range(60):

        if not process.is_alive():
            return False

        try:
            with socket.create_connection(
                (HOST, PORT),
                timeout=1
            ):
                return True

        except OSError:
            time.sleep(1)

    return False


def main():

    if not APP_PATH.exists():
        raise FileNotFoundError(
            f"Could not find app.py: {APP_PATH}"
        )

    # Start Streamlit in a separate process
    streamlit_process = multiprocessing.Process(
        target=run_streamlit,
        name="USB Guardian AI Streamlit"
    )

    streamlit_process.start()

    try:

        if not wait_for_server(streamlit_process):
            raise RuntimeError(
                "USB Guardian AI failed to start. "
                "Check the terminal for errors."
            )

        # Open the desktop application
        webview.create_window(
            title="USB Guardian AI",
            url=f"http://{HOST}:{PORT}",
            width=1200,
            height=800,
            min_size=(900, 600)
        )

        webview.start()

    finally:

        # Stop Streamlit when the desktop window closes
        if streamlit_process.is_alive():
            streamlit_process.terminate()
            streamlit_process.join(timeout=5)

        if streamlit_process.is_alive():
            streamlit_process.kill()
            streamlit_process.join()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
