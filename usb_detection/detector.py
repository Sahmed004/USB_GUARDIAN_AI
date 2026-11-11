
import platform

from usb_detection.macos import detect_usb_devices


def detect_connected_usb():

    operating_system = platform.system()

    if operating_system == "Darwin":
        return detect_usb_devices()

    elif operating_system == "Windows":
        from usb_detection.windows import detect_usb_devices as detect_windows_usb
        return detect_windows_usb()

    else:
        raise OSError("Operating system not supported.")
