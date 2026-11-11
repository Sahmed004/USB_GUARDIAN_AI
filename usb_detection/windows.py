
import subprocess
import json


def detect_usb_devices():

    powershell_script = r"""
    Get-Disk |
    Where-Object { $_.BusType -eq 'USB' } |
    ForEach-Object {
        $disk = $_

        Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue |
        Get-Volume -ErrorAction SilentlyContinue |
        ForEach-Object {
            [PSCustomObject]@{
                Device = $disk.FriendlyName
                DiskNumber = $disk.Number
                Protocol = $disk.BusType.ToString()
                CapacityGB = [math]::Round($disk.Size / 1GB, 2)
                VolumeName = $_.FileSystemLabel
                DriveLetter = $_.DriveLetter
                FileSystem = $_.FileSystem
                FreeGB = [math]::Round($_.SizeRemaining / 1GB, 2)
            }
        }
    } | ConvertTo-Json -Compress
    """

    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                powershell_script
            ],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            print("Windows USB detection failed:")
            print(result.stderr)
            return []

        if not result.stdout.strip():
            return []

        devices = json.loads(result.stdout)

        if isinstance(devices, dict):
            devices = [devices]

        return devices

    except subprocess.TimeoutExpired:
        print("USB detection timed out.")
        return []

    except json.JSONDecodeError:
        print("Could not read the Windows USB information.")
        return []

    except FileNotFoundError:
        print("PowerShell was not found.")
        return []


if __name__ == "__main__":

    usb_devices = detect_usb_devices()

    if usb_devices:
        print("\nUSB DEVICES DETECTED\n")

        for device in usb_devices:
            print(f"Device: {device['Device']}")
            print(f"Disk number: {device['DiskNumber']}")
            print(f"Protocol: {device['Protocol']}")
            print(f"Capacity: {device['CapacityGB']} GB")
            print(f"Volume name: {device['VolumeName']}")
            print(f"Drive letter: {device['DriveLetter']}")
            print(f"File system: {device['FileSystem']}")
            print(f"Free space: {device['FreeGB']} GB")
            print("-" * 35)

    else:
        print("No mounted USB volumes detected.")
