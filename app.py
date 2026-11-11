
import os
import streamlit as st

from usb_detection.detector import detect_connected_usb
from file_scanner import scan_usb


# Dashboard configuration.
st.set_page_config(
    page_title="USB Guardian AI",
    page_icon="🛡️",
    layout="wide"
)


# Store scan results during the current session.
if "scan_results" not in st.session_state:
    st.session_state.scan_results = None

if "selected_usb" not in st.session_state:
    st.session_state.selected_usb = None


# Dashboard heading.
st.title("🛡️ USB Guardian AI")

st.write(
    "USB storage inspection and endpoint security dashboard."
)

st.caption(
    "A read-only security tool for inspecting USB storage devices."
)

st.divider()


# USB detection.
st.header("Connected USB devices")

if st.button("Refresh USB devices"):
    st.session_state.scan_results = None
    st.session_state.selected_usb = None

try:
    devices = detect_connected_usb()

except Exception as error:
    devices = []
    st.error(f"USB detection failed: {error}")


if not devices:

    st.warning("No supported USB storage devices detected.")

else:

    device_options = {}

    for device in devices:

        mount_point = device.get("mount_point")

        if mount_point:

            device_name = device.get(
                "name",
                "Unknown USB"
            )

            label = f"{device_name} — {mount_point}"

            device_options[label] = device

    if not device_options:

        st.warning(
            "USB devices were detected, but none have an available mount point."
        )

    else:

        selected_label = st.selectbox(
            "Select a USB device",
            list(device_options.keys())
        )

        selected_device = device_options[selected_label]

        usb_path = selected_device["mount_point"]

        st.session_state.selected_usb = usb_path

        # Device information.
        st.subheader("Device information")

        col1, col2, col3 = st.columns(3)

        with col1:

            st.metric(
                "Device name",
                selected_device.get("name", "Unknown")
            )

        with col2:

            capacity = selected_device.get(
                "capacity_gb",
                "Unknown"
            )

            st.metric(
                "Capacity",
                f"{capacity} GB"
            )

        with col3:

            st.metric(
                "File system",
                selected_device.get(
                    "file_system",
                    "Unknown"
                )
            )

        st.write(f"**Mount location:** `{usb_path}`")

        if "free_gb" in selected_device:

            st.write(
                f"**Free space:** {selected_device['free_gb']} GB"
            )

        st.divider()

        # Start scan.
        st.header("USB security scan")

        st.warning(
            "Scanning is read-only. USB files will not be opened, "
            "executed, deleted or modified."
        )

        if st.button(
            "Start security scan",
            type="primary"
        ):

            with st.spinner(
                "Inspecting files and running ClamAV. Please wait..."
            ):

                try:

                    scan_result = scan_usb(usb_path)

                    st.session_state.scan_results = scan_result

                    if scan_result is None:

                        st.error(
                            "The scan could not be completed."
                        )

                except Exception as error:

                    st.session_state.scan_results = None

                    st.error(
                        f"An error occurred during scanning: {error}"
                    )


# Display scan results.
scan_result = st.session_state.scan_results

if scan_result:

    st.divider()

    st.header("Scan results")

    files = scan_result["files"]

    errors = scan_result["errors"]

    clamav = scan_result["clamav"]

    infected_files = clamav["infected_files"]

    flagged_files = [
        item for item in files
        if item["finding"] == "Review required"
    ]

    # Summary metrics.
    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "Files inspected",
            len(files)
        )

    with col2:

        st.metric(
            "Threats detected",
            len(infected_files)
        )

    with col3:

        st.metric(
            "Files flagged for review",
            len(flagged_files)
        )

    with col4:

        st.metric(
            "Inspection errors",
            len(errors)
        )

    # ClamAV assessment.
    st.subheader("ClamAV assessment")

    if clamav["returncode"] == 0:

        st.success(
            "No known threats detected by ClamAV."
        )

    elif clamav["returncode"] == 1:

        st.error(
            "ClamAV detected potential malware."
        )

    else:

        st.warning(
            "The ClamAV scan did not complete successfully. "
            "The security assessment is incomplete."
        )

    st.write(
        f"**Status:** {clamav['status']}"
    )

    # Threat details.
    if infected_files:

        st.subheader("Files flagged by ClamAV")

        for filename in infected_files:

            st.error(filename)

    # Extension warnings.
    st.subheader("Files requiring manual review")

    if flagged_files:

        flagged_data = [
            {
                "File": item["name"],
                "Extension": item["extension"],
                "Category": item["category"]
            }
            for item in flagged_files
        ]

        st.dataframe(
            flagged_data,
            use_container_width=True
        )

        st.info(
            "These extensions can be used by legitimate software "
            "as well as malicious files. They are flagged for review, "
            "not classified as malware."
        )

    else:

        st.write(
            "No files were flagged by their extensions."
        )

    # Complete file inventory.
    st.subheader("Inspected files")

    if files:

        file_data = [
            {
                "File": item["name"],
                "Extension": item["extension"],
                "Category": item["category"],
                "Size (bytes)": item["size"],
                "Finding": item["finding"],
                "SHA-256": item["hash"]
            }
            for item in files
        ]

        st.dataframe(
            file_data,
            use_container_width=True,
            height=400
        )

    # Inspection errors.
    if errors:

        with st.expander("View inspection errors"):

            for error in errors:

                st.write(error)

    # PDF report download.
    st.divider()

    st.subheader("Security report")

    report_path = scan_result.get("report_path")

    if report_path and os.path.isfile(report_path):

        with open(report_path, "rb") as report_file:

            report_bytes = report_file.read()

        st.download_button(
            label="Download PDF security report",
            data=report_bytes,
            file_name=os.path.basename(report_path),
            mime="application/pdf"
        )

    else:

        st.warning(
            "The PDF report could not be found."
        )
