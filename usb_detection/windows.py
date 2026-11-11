
import subprocess
import json


def detect_usb_devices():

    powershell_script = r"""
    $ErrorActionPreference = 'Stop'

    Get-Disk |
    Where-Object { $_.BusType -eq 'USB' } |
    ForEach-Object {
        $disk = $_

        Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue |
        ForEach-Object {
            $partition = $_

            $volume = Get-Volume -Partition $partition -ErrorAction SilentlyContinue

            if ($volume -and $volume.DriveLetter) {
                [PSCustomObject]@{
                    name = $disk.FriendlyName
                    mount_point = "$($volume.DriveLetter):\"
                    volume_name = $volume.FileSystemLabel
                    capacity_gb = [math]::Round($disk.Size / 1GB, 2)
                    file_system = $volume.FileSystem
                    free_gb = [math]::Round($volume.SizeRemaining / 1GB, 2)
                }
            }
        }
    } | ConvertTo-Json -Compress
    """

    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
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
            print(f"Device: {device['name']}")
            print(f"Location: {device['mount_point']}")
            print(f"Capacity: {device['capacity_gb']} GB")
            print(f"Volume name: {device['volume_name']}")
            print(f"File system: {device['file_system']}")
            print(f"Free space: {device['free_gb']} GB")
            print("-" * 35)

    else:
        print("No mounted USB volumes detected.")
