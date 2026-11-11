
import subprocess
import plistlib
import psutil


def detect_usb_devices():

    detected_devices = []

    try:
        result = subprocess.run(
            ["diskutil", "list", "-plist", "external", "physical"],
            capture_output=True,
            check=True,
            timeout=30
        )

        disk_data = plistlib.loads(result.stdout)

        for disk_id in disk_data.get("WholeDisks", []):

            info_result = subprocess.run(
                ["diskutil", "info", "-plist", f"/dev/{disk_id}"],
                capture_output=True,
                check=True,
                timeout=30
            )

            info = plistlib.loads(info_result.stdout)

            if (
                info.get("BusProtocol") == "USB"
                and info.get("Internal") is False
                and info.get("RemovableMedia") is True
                and info.get("VirtualOrPhysical") == "Physical"
            ):

                for disk in disk_data.get("AllDisksAndPartitions", []):

                    if disk.get("DeviceIdentifier") != disk_id:
                        continue

                    for partition in disk.get("Partitions", []):

                        mount_point = partition.get("MountPoint")

                        if not mount_point:
                            continue

                        try:
                            usage = psutil.disk_usage(mount_point)
                        except OSError:
                            usage = None

                        device = {
                            "device": disk_id,
                            "name": info.get("MediaName", "Unknown"),
                            "protocol": info.get("BusProtocol", "Unknown"),
                            "capacity_gb": round(
                                info.get("TotalSize", 0) / (1024 ** 3), 2
                            ),
                            "volume_name": partition.get(
                                "VolumeName", "Unknown"
                            ),
                            "mount_point": mount_point,
                            "file_system": partition.get(
                                "Content", "Unknown"
                            ),
                            "free_gb": round(
                                usage.free / (1024 ** 3), 2
                            ) if usage else None
                        }

                        detected_devices.append(device)

        return detected_devices

    except subprocess.CalledProcessError as error:
        print(f"Could not retrieve USB information: {error}")
        return []

    except subprocess.TimeoutExpired:
        print("USB detection timed out.")
        return []

    except Exception as error:
        print(f"An error occurred: {error}")
        return []


if __name__ == "__main__":

    devices = detect_usb_devices()

    if devices:
        for device in devices:
            print("\nUSB DEVICE DETECTED")
            print("------------------------------")
            print(f"Name: {device['name']}")
            print(f"Volume: {device['volume_name']}")
            print(f"Mount point: {device['mount_point']}")
            print(f"Capacity: {device['capacity_gb']} GB")
            print(f"File system: {device['file_system']}")
    else:
        print("No mounted USB storage devices detected.")
