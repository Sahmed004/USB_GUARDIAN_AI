
import os
import hashlib
import subprocess
import shutil
import platform

from datetime import datetime
from collections import defaultdict
from xml.sax.saxutils import escape

from usb_detection.detector import detect_connected_usb

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)


# File extensions that may need manual review.
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1",
    ".vbs", ".js", ".scr", ".msi"
}


# File categories.
FILE_CATEGORIES = {
    "Documents": [
        ".pdf", ".doc", ".docx", ".odt", ".txt", ".rtf"
    ],
    "Spreadsheets": [
        ".xls", ".xlsx", ".csv", ".ods"
    ],
    "Images": [
        ".jpg", ".jpeg", ".png", ".gif", ".bmp"
    ],
    "Videos": [
        ".mp4", ".avi", ".mov", ".mkv"
    ],
    "Audio": [
        ".mp3", ".wav", ".aac", ".flac"
    ],
    "Archives": [
        ".zip", ".rar", ".7z", ".tar", ".gz"
    ],
    "Executables and scripts": [
        ".exe", ".bat", ".cmd", ".ps1",
        ".vbs", ".js", ".scr", ".msi"
    ],
    "Virtual machine files": [
        ".ovf", ".vmdk", ".vdi"
    ]
}


def find_clamav():
    """Find the ClamAV executable."""

    clamav_path = shutil.which("clamscan")

    if clamav_path:
        return clamav_path

    possible_paths = [
        "/opt/homebrew/bin/clamscan",
        "/usr/local/bin/clamscan"
    ]

    for path in possible_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    return None


def calculate_sha256(file_path):
    """Calculate the SHA-256 hash of a file."""

    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            for chunk in iter(
                lambda: file.read(1024 * 1024),
                b""
            ):
                sha256.update(chunk)

        return sha256.hexdigest()

    except OSError:
        return "Could not calculate"


def classify_file(extension):
    """Classify a file using its extension."""

    for category, extensions in FILE_CATEGORIES.items():
        if extension in extensions:
            return category

    return "Other / Unknown"


def get_excluded_directory_names():
    """Return operating system folders excluded from inspection."""

    system = platform.system()

    if system == "Darwin":
        return {
            ".Spotlight-V100",
            ".Trashes",
            ".fseventsd"
        }

    elif system == "Windows":
        return {
            "$RECYCLE.BIN",
            "System Volume Information"
        }

    return set()


def get_clamav_exclusions():
    """Return ClamAV exclusion patterns for system folders."""

    system = platform.system()

    if system == "Darwin":
        patterns = [
            r"(^|/)\.Spotlight-V100(/|$)",
            r"(^|/)\.Trashes(/|$)",
            r"(^|/)\.fseventsd(/|$)"
        ]

    elif system == "Windows":
        patterns = [
            r"(^|[\\/])\$RECYCLE\.BIN([\\/]|$)",
            r"(^|[\\/])System Volume Information([\\/]|$)"
        ]

    else:
        patterns = []

    return [
        f"--exclude-dir={pattern}"
        for pattern in patterns
    ]


def scan_with_clamav(usb_path):
    """Run a read-only ClamAV scan on the USB drive."""

    print("\nStarting ClamAV malware scan...")
    print("This may take some time.")

    clamav_path = find_clamav()

    if not clamav_path:
        message = "ClamAV executable was not found."

        print(message)

        return {
            "status": "ClamAV not found",
            "infected_files": [],
            "output": message,
            "returncode": -1
        }

    if not os.path.isdir(usb_path):
        message = f"USB location is unavailable: {usb_path}"

        print(message)

        return {
            "status": "Invalid USB location",
            "infected_files": [],
            "output": message,
            "returncode": -1
        }

    command = [
        clamav_path,
        "--recursive",
        "--infected",
        "--verbose"
    ]

    command.extend(get_clamav_exclusions())
    command.append(usb_path)

    print(f"ClamAV executable: {clamav_path}")
    print("Excluding operating system metadata folders.")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=1800
        )

        output = "\n".join(
            part for part in [
                result.stdout,
                result.stderr
            ] if part
        )

        infected_files = []

        for line in output.splitlines():
            if line.rstrip().endswith(" FOUND"):
                infected_files.append(
                    line.rsplit(": ", 1)[0]
                )

        if result.returncode == 0:
            status = "No known threats detected"

        elif result.returncode == 1:
            status = "Threats detected"

        else:
            status = "Scan error"

        print(f"\nClamAV return code: {result.returncode}")
        print(f"ClamAV status: {status}")
        print(f"Files flagged by ClamAV: {len(infected_files)}")

        if result.returncode not in (0, 1):
            print("\nClamAV diagnostic output:")
            print(
                output
                if output
                else "No diagnostic information available."
            )

        return {
            "status": status,
            "infected_files": infected_files,
            "output": output,
            "returncode": result.returncode
        }

    except subprocess.TimeoutExpired:
        message = "ClamAV scan exceeded the 30-minute time limit."

        print(message)

        return {
            "status": "Scan timed out",
            "infected_files": [],
            "output": message,
            "returncode": -1
        }

    except Exception as error:
        message = f"ClamAV error: {error}"

        print(message)

        return {
            "status": "Scan error",
            "infected_files": [],
            "output": message,
            "returncode": -1
        }


def scan_usb(usb_path):
    """Inspect USB files, run ClamAV and return scan results."""

    print("\n================================")
    print("          USB GUARDIAN AI")
    print("================================")

    print(f"Scanning location: {usb_path}")

    if not os.path.isdir(usb_path):
        print("USB location is unavailable.")
        return None

    results = []
    errors = []

    excluded_folders = get_excluded_directory_names()

    print("\nCollecting file information...")

    def record_walk_error(error):
        errors.append(str(error))

    for root, directories, files in os.walk(
        usb_path,
        onerror=record_walk_error
    ):

        # Skip operating system metadata folders.
        directories[:] = [
            directory
            for directory in directories
            if directory not in excluded_folders
            and not os.path.islink(
                os.path.join(root, directory)
            )
        ]

        for filename in files:

            file_path = os.path.join(root, filename)

            # Skip symbolic links.
            if os.path.islink(file_path):
                errors.append(
                    f"{filename}: Symbolic link skipped."
                )
                continue

            extension = os.path.splitext(
                filename
            )[1].lower()

            try:
                file_size = os.path.getsize(file_path)
                file_hash = calculate_sha256(file_path)

                if file_hash == "Could not calculate":
                    errors.append(
                        f"{filename}: SHA-256 calculation failed."
                    )

                if extension in SUSPICIOUS_EXTENSIONS:
                    finding = "Review required"
                else:
                    finding = "No extension warning"

                results.append({
                    "name": os.path.relpath(
                        file_path,
                        usb_path
                    ),
                    "extension": extension or "No extension",
                    "category": classify_file(extension),
                    "size": file_size,
                    "hash": file_hash,
                    "finding": finding
                })

            except OSError as error:
                errors.append(
                    f"{filename}: {error}"
                )

    print(f"\nFiles inspected: {len(results)}")
    print(f"Inspection errors: {len(errors)}")

    # Run ClamAV.
    clamav_result = scan_with_clamav(usb_path)

    print("\nCLAMAV RESULTS")
    print("--------------------------------")
    print(f"Status: {clamav_result['status']}")
    print(
        f"Threats detected: "
        f"{len(clamav_result['infected_files'])}"
    )

    # Create the PDF report.
    report_path = create_pdf_report(
        usb_path,
        results,
        errors,
        clamav_result
    )

    # Return data to the Streamlit dashboard.
    return {
        "usb_path": usb_path,
        "files": results,
        "errors": errors,
        "clamav": clamav_result,
        "report_path": report_path
    }


def create_pdf_report(
    usb_path,
    results,
    errors,
    clamav_result
):
    """Generate a PDF report containing scan results."""

    timestamp = datetime.now()

    report_name = (
        f"USB_Security_Report_"
        f"{timestamp:%Y%m%d_%H%M%S}.pdf"
    )

    project_folder = os.path.dirname(
        os.path.abspath(__file__)
    )

    report_path = os.path.join(
        project_folder,
        report_name
    )

    document = SimpleDocTemplate(
        report_path,
        pagesize=landscape(A4),
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm
    )

    styles = getSampleStyleSheet()
    story = []

    small_style = ParagraphStyle(
        "SmallText",
        parent=styles["BodyText"],
        fontSize=6,
        leading=8,
        wordWrap="CJK"
    )

    # Report heading.
    story.append(
        Paragraph("USB GUARDIAN AI", styles["Title"])
    )

    story.append(
        Paragraph(
            "USB Security Scan Report",
            styles["Heading2"]
        )
    )

    story.append(Spacer(1, 8))

    # Basic scan information.
    story.append(Paragraph(
        f"<b>Scan date:</b> "
        f"{timestamp.strftime('%d %B %Y, %H:%M:%S')}",
        styles["BodyText"]
    ))

    story.append(Paragraph(
        f"<b>USB location:</b> {escape(usb_path)}",
        styles["BodyText"]
    ))

    story.append(Paragraph(
        f"<b>Total files inspected:</b> {len(results)}",
        styles["BodyText"]
    ))

    story.append(Paragraph(
        f"<b>Files with inspection errors:</b> {len(errors)}",
        styles["BodyText"]
    ))

    flagged = [
        item for item in results
        if item["finding"] == "Review required"
    ]

    story.append(Paragraph(
        f"<b>Files flagged for extension review:</b> "
        f"{len(flagged)}",
        styles["BodyText"]
    ))

    # Identify duplicate files using SHA-256.
    hash_groups = defaultdict(list)

    for item in results:
        if item["hash"] != "Could not calculate":
            hash_groups[item["hash"]].append(
                item["name"]
            )

    duplicates = {
        file_hash: names
        for file_hash, names in hash_groups.items()
        if len(names) > 1
    }

    story.append(Paragraph(
        f"<b>Groups of duplicate files:</b> "
        f"{len(duplicates)}",
        styles["BodyText"]
    ))

    # Security assessment.
    story.append(Spacer(1, 12))

    story.append(
        Paragraph(
            "Security assessment",
            styles["Heading2"]
        )
    )

    infected_files = clamav_result["infected_files"]
    return_code = clamav_result["returncode"]
    clamav_status = clamav_result["status"]

    if return_code == 0:
        assessment = (
            "No known threats detected by ClamAV."
        )

    elif return_code == 1:
        assessment = (
            "ClamAV detected potential malware."
        )

    else:
        assessment = (
            "INCOMPLETE - ClamAV scan did not "
            "complete successfully."
        )

    story.append(Paragraph(
        f"<b>ClamAV status:</b> {escape(clamav_status)}",
        styles["BodyText"]
    ))

    story.append(Paragraph(
        f"<b>Assessment:</b> {escape(assessment)}",
        styles["BodyText"]
    ))

    story.append(Paragraph(
        f"<b>Files flagged by ClamAV:</b> "
        f"{len(infected_files)}",
        styles["BodyText"]
    ))

    story.append(Spacer(1, 6))

    story.append(Paragraph(
        "This report records file information, file extensions, "
        "file sizes and SHA-256 hashes. Selected extensions are "
        "flagged for manual review. ClamAV checks files against "
        "its available malware definitions. No detection does "
        "not prove that a file is safe. Do not open or run "
        "suspicious files.",
        styles["BodyText"]
    ))

    # List files flagged by ClamAV.
    if infected_files:

        story.append(Spacer(1, 8))

        story.append(
            Paragraph(
                "Files flagged by ClamAV",
                styles["Heading3"]
            )
        )

        for infected_file in infected_files:
            story.append(
                Paragraph(
                    escape(infected_file),
                    small_style
                )
            )

    # Diagnostic information.
    if return_code not in (0, 1):

        story.append(Spacer(1, 8))

        story.append(
            Paragraph(
                "ClamAV diagnostic information",
                styles["Heading3"]
            )
        )

        diagnostic = (
            clamav_result["output"]
            or "No diagnostic output available."
        )

        story.append(
            Paragraph(
                escape(diagnostic).replace(
                    "\n",
                    "<br/>"
                ),
                small_style
            )
        )

    # Inspected files table.
    story.append(Spacer(1, 12))

    story.append(
        Paragraph(
            "Inspected files",
            styles["Heading2"]
        )
    )

    table_data = [[
        "File name",
        "Type",
        "Category",
        "Size (bytes)",
        "Finding",
        "SHA-256"
    ]]

    for item in results:

        table_data.append([
            Paragraph(
                escape(item["name"]),
                small_style
            ),
            Paragraph(
                escape(item["extension"]),
                small_style
            ),
            Paragraph(
                escape(item["category"]),
                small_style
            ),
            f"{item['size']:,}",
            Paragraph(
                escape(item["finding"]),
                small_style
            ),
            Paragraph(
                escape(item["hash"]),
                small_style
            )
        ])

    file_table = Table(
        table_data,
        colWidths=[160, 55, 100, 70, 100, 230],
        repeatRows=1
    )

    file_table.setStyle(TableStyle([
        (
            "BACKGROUND",
            (0, 0),
            (-1, 0),
            colors.HexColor("#26364A")
        ),
        (
            "TEXTCOLOR",
            (0, 0),
            (-1, 0),
            colors.white
        ),
        (
            "FONTNAME",
            (0, 0),
            (-1, 0),
            "Helvetica-Bold"
        ),
        (
            "FONTSIZE",
            (0, 0),
            (-1, 0),
            7
        ),
        (
            "FONTSIZE",
            (0, 1),
            (-1, -1),
            6
        ),
        (
            "GRID",
            (0, 0),
            (-1, -1),
            0.25,
            colors.grey
        ),
        (
            "VALIGN",
            (0, 0),
            (-1, -1),
            "TOP"
        ),
        (
            "ROWBACKGROUNDS",
            (0, 1),
            (-1, -1),
            [
                colors.white,
                colors.HexColor("#F1F4F7")
            ]
        ),
        (
            "LEFTPADDING",
            (0, 0),
            (-1, -1),
            4
        ),
        (
            "RIGHTPADDING",
            (0, 0),
            (-1, -1),
            4
        ),
        (
            "TOPPADDING",
            (0, 0),
            (-1, -1),
            4
        ),
        (
            "BOTTOMPADDING",
            (0, 0),
            (-1, -1),
            4
        )
    ]))

    story.append(file_table)

    # Duplicate files section.
    if duplicates:

        story.append(PageBreak())

        story.append(
            Paragraph(
                "Duplicate files",
                styles["Heading2"]
            )
        )

        for file_hash, names in duplicates.items():

            story.append(Paragraph(
                f"<b>SHA-256:</b> {escape(file_hash)}",
                styles["BodyText"]
            ))

            for name in names:
                story.append(
                    Paragraph(
                        f"• {escape(name)}",
                        styles["BodyText"]
                    )
                )

            story.append(Spacer(1, 8))

    # Files that could not be inspected.
    if errors:

        story.append(PageBreak())

        story.append(
            Paragraph(
                "Files with inspection errors",
                styles["Heading2"]
            )
        )

        for error in errors:
            story.append(
                Paragraph(
                    escape(error),
                    small_style
                )
            )

    document.build(story)

    print("\n================================")
    print("          PDF REPORT CREATED")
    print("================================")
    print(f"Report saved as: {report_path}")

    # Return the PDF location to the dashboard.
    return report_path


if __name__ == "__main__":

    print("\n================================")
    print("          USB GUARDIAN AI")
    print("================================")

    print("\nSearching for connected USB devices...")

    try:
        devices = detect_connected_usb()

    except Exception as error:
        print(f"\nUSB detection error: {error}")
        devices = []

    if not devices:
        print("\nNo supported USB storage devices detected.")

    else:
        for device in devices:

            usb_path = device.get("mount_point")

            if not usb_path:
                print(
                    f"\nSkipping {device.get('name', 'Unknown')}: "
                    "no mount point available."
                )
                continue

            print("\nUSB DEVICE DETECTED")
            print("--------------------------------")
            print(
                f"Name: {device.get('name', 'Unknown')}"
            )
            print(f"Location: {usb_path}")

            scan_usb(usb_path)
