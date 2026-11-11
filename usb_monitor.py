
import subprocess
import plistlib
import psutil


def get_external_usb_devices():

    print("\n================================")
    print("       USB GUARDIAN AI")
    print("================================")

    print("\nSearching for external USB devices...\n")

    try:
        result = subprocess.run(
            ["diskutil", "list", "-plist", "external", "physical"],
            capture_output=True,
            check=True
        )

        disk_data = plistlib.loads(result.stdout)

        detected_devices = []

        for disk_id in disk_data.get("WholeDisks", []):

            info_result = subprocess.run(
                ["diskutil", "info", "-plist", f"/dev/{disk_id}"],
                capture_output=True,
                check=True
            )

            info = plistlib.loads(info_result.stdout)

            # Check whether the disk is a removable USB device
            if (
                info.get("BusProtocol") == "USB"
                and info.get("Internal") is False
                and info.get("RemovableMedia") is True
                and info.get("VirtualOrPhysical") == "Physical"
            ):
                detected_devices.append((disk_id, info))

        if not detected_devices:
            print("No external USB storage devices found.")
            return

        for disk_id, info in detected_devices:

            print("--------------------------------")
            print("USB DEVICE DETECTED")

            print(f"Device: {disk_id}")
            print(f"Name: {info.get('MediaName', 'Unknown')}")
            print(f"Protocol: {info.get('BusProtocol', 'Unknown')}")
            print(f"Removable: {info.get('RemovableMedia', 'Unknown')}")

            size = info.get("TotalSize", 0)

            print(f"Capacity: {size / (1024 ** 3):.2f} GB")

            # Find the mounted partition belonging to this USB
            for disk in disk_data.get("AllDisksAndPartitions", []):

                if disk.get("DeviceIdentifier") != disk_id:
                    continue

                for partition in disk.get("Partitions", []):

                    mount_point = partition.get("MountPoint")

                    if not mount_point:
                        continue

                    print(f"Volume Name: {partition.get('VolumeName', 'Unknown')}")
                    print(f"Mount Point: {mount_point}")
                    print(f"File System: {partition.get('Content', 'Unknown')}")

                    try:
                        usage = psutil.disk_usage(mount_point)

                        print(f"Used: {usage.used / (1024 ** 3):.2f} GB")
                        print(f"Free: {usage.free / (1024 ** 3):.2f} GB")

                    except OSError:
                        print("Storage usage unavailable.")

        print("\nUSB check completed.")

    except subprocess.CalledProcessError:
        print("Could not retrieve disk information.")

    except Exception as error:
        print(f"An error occurred: {error}")


if __name__ == "__main__":
    get_external_usb_devices()
