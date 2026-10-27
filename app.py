
import json
from datetime import datetime
from pathlib import Path

import pandas as pd
import psutil
import streamlit as st


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="Keylogger Detection System",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)


# --------------------------------------------------
# DETECTION SETTINGS
# --------------------------------------------------

PROCESS_TERMS = [
    "keylogger",
    "keylog",
    "keystroke",
    "pynput",
    "pykeylogger",
]

FILE_TERMS = [
    "keylogger",
    "keylog",
    "keystroke",
    "stealer",
    "credential_dump",
]

SUSPICIOUS_EXTENSIONS = [".scr", ".pif"]


# --------------------------------------------------
# SESSION STATE
# --------------------------------------------------

if "main_navigation" not in st.session_state:
    st.session_state["main_navigation"] = "Dashboard"

if "process_results" not in st.session_state:
    st.session_state["process_results"] = None

if "folder_results" not in st.session_state:
    st.session_state["folder_results"] = None

if "report_history" not in st.session_state:
    st.session_state["report_history"] = []


# --------------------------------------------------
# CUSTOM DESIGN
# --------------------------------------------------

st.markdown(
    """
    <style>
    .stApp {
        background-color: #f4f7fb;
        color: #172b4d;
    }

    [data-testid="stSidebar"] {
        background-color: #10243a;
    }

    [data-testid="stSidebar"] * {
        color: #ffffff;
    }

    .main-title {
        font-size: 34px;
        font-weight: 800;
        color: #163a63;
        margin-bottom: 5px;
    }

    .subtitle {
        font-size: 16px;
        color: #52677e;
        margin-bottom: 22px;
    }

    .section-heading {
        font-size: 27px;
        font-weight: 750;
        color: #163a63;
        margin-bottom: 10px;
    }

    .metric-card {
        background: #ffffff;
        padding: 17px;
        border-radius: 12px;
        border: 1px solid #dce5ef;
        margin-bottom: 10px;
    }

    .metric-label {
        color: #61758a;
        font-size: 14px;
    }

    .metric-value {
        color: #163a63;
        font-size: 28px;
        font-weight: 800;
    }

    div.stButton > button[kind="primary"] {
        background: #1677e8;
        color: white;
        border: 0;
        border-radius: 8px;
        min-height: 44px;
        font-weight: 700;
    }

    .footer {
        text-align: center;
        color: #718096;
        padding-top: 25px;
        font-size: 13px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def navigate_to(page_name):
    """Navigate from the dashboard using a button callback."""
    st.session_state["main_navigation"] = page_name


def metric(label, value):
    """Display a dashboard metric card."""
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def flagged_count(df):
    """Count rows classified for review."""
    if (
        df is None
        or df.empty
        or "Risk Classification" not in df.columns
    ):
        return 0

    return int(
        (df["Risk Classification"] == "Review").sum()
    )


def record_report(df, report_type):
    """Record a report in the current session."""
    st.session_state["report_history"].append(
        {
            "Report Type": report_type,
            "Created": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "Rows": len(df),
        }
    )


def downloads(df, report_type):
    """Provide CSV and JSON downloads."""
    if df is None:
        st.info("Run a scan to generate a report.")
        return

    if df.empty:
        st.info("There are no results to download.")
        return

    csv_data = df.to_csv(index=False).encode("utf-8")

    json_data = df.to_json(
        orient="records",
        indent=2,
        force_ascii=False,
    ).encode("utf-8")

    col1, col2 = st.columns(2)

    with col1:
        st.download_button(
            "⬇️ Download CSV Report",
            data=csv_data,
            file_name=f"{report_type}_report.csv",
            mime="text/csv",
            use_container_width=True,
            key=f"{report_type}_csv_download",
        )

    with col2:
        st.download_button(
            "⬇️ Download JSON Report",
            data=json_data,
            file_name=f"{report_type}_report.json",
            mime="application/json",
            use_container_width=True,
            key=f"{report_type}_json_download",
        )


# --------------------------------------------------
# PROCESS SCANNER
# --------------------------------------------------

def scan_processes():
    """
    Inspect processes visible to the Python process.
    On Streamlit Cloud, these are server-side processes,
    not processes running on a visitor's laptop.
    """
    rows = []

    for proc in psutil.process_iter(
        ["pid", "name", "exe", "username", "cmdline", "status"]
    ):
        try:
            info = proc.info

            name = str(info.get("name") or "Unknown")
            exe = str(info.get("exe") or "Unavailable")
            username = str(info.get("username") or "Unavailable")

            command = info.get("cmdline") or []

            if isinstance(command, list):
                command = " ".join(
                    str(part) for part in command
                )

            searchable_text = (
                f"{name} {exe} {command}"
            ).lower()

            indicators = [
                f"Configured keyword match: {term}"
                for term in PROCESS_TERMS
                if term in searchable_text
            ]

            normalized_path = exe.lower().replace("\\", "/")

            suspicious_locations = [
                "/appdata/local/temp/",
                "/windows/temp/",
                "/users/public/",
            ]

            if any(
                location in normalized_path
                for location in suspicious_locations
            ):
                indicators.append(
                    "Executable in a temporary/public-writable location"
                )

            rows.append(
                {
                    "Process ID": info.get("pid"),
                    "Process Name": name,
                    "Executable Path": exe,
                    "User Account": username,
                    "Status": info.get("status") or "Unknown",
                    "Detection Indicators": (
                        "; ".join(indicators)
                        if indicators
                        else "None detected"
                    ),
                    "Risk Classification": (
                        "Review"
                        if indicators
                        else "No indicator found"
                    ),
                }
            )

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            continue

        except Exception:
            continue

    columns = [
        "Process ID",
        "Process Name",
        "Executable Path",
        "User Account",
        "Status",
        "Detection Indicators",
        "Risk Classification",
    ]

    result = pd.DataFrame(rows, columns=columns)

    if not result.empty:
        result = result.sort_values(
            ["Risk Classification", "Process Name"]
        ).reset_index(drop=True)

    return result


# --------------------------------------------------
# HOSTED FILE / FOLDER SCANNER
# --------------------------------------------------

def inspect_uploaded_files(uploaded_files):
    """
    Inspect uploaded file names and extensions.

    This function does not execute uploaded files and
    does not claim to determine whether file contents
    contain malware.
    """
    rows = []

    for uploaded_file in uploaded_files:
        # Streamlit may supply a relative folder path.
        relative_path = uploaded_file.name.replace("\\", "/")
        filename = relative_path.split("/")[-1]
        searchable_name = filename.lower()

        indicators = [
            f"Filename keyword match: {term}"
            for term in FILE_TERMS
            if term in searchable_name
        ]

        extension = Path(filename).suffix.lower()

        if extension in SUSPICIOUS_EXTENSIONS:
            indicators.append(
                f"Extension for review: {extension}"
            )

        rows.append(
            {
                "File Name": filename,
                "File Path": relative_path,
                "Extension": extension or "No extension",
                "Size (Bytes)": uploaded_file.size,
                "Detection Indicators": (
                    "; ".join(indicators)
                    if indicators
                    else "None detected"
                ),
                "Risk Classification": (
                    "Review"
                    if indicators
                    else "No indicator found"
                ),
            }
        )

    columns = [
        "File Name",
        "File Path",
        "Extension",
        "Size (Bytes)",
        "Detection Indicators",
        "Risk Classification",
    ]

    return pd.DataFrame(rows, columns=columns)


# --------------------------------------------------
# SIDEBAR NAVIGATION
# --------------------------------------------------

with st.sidebar:
    st.markdown("## 🛡️ Security Center")
    st.write("Keylogger Detection System")
    st.divider()

    page = st.radio(
        "Navigation",
        [
            "Dashboard",
            "Process Scanner",
            "Folder Scanner",
            "Reports",
            "About",
        ],
        key="main_navigation",
    )

    st.divider()
    st.caption("Python Cybersecurity Project")
    st.caption("Educational use only")


# --------------------------------------------------
# MAIN HEADER
# --------------------------------------------------

st.markdown(
    '<div class="main-title">🔐 Keylogger Detection System</div>',
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="subtitle">
        A Python cybersecurity dashboard for reviewing process
        metadata and suspicious filenames.
    </div>
    """,
    unsafe_allow_html=True,
)

st.warning(
    "Educational tool: a flagged item is not proof of malware. "
    "No flagged items does not guarantee that a device is safe."
)


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

if page == "Dashboard":

    st.markdown(
        '<div class="section-heading">📊 Security Dashboard</div>',
        unsafe_allow_html=True,
    )

    process_data = st.session_state["process_results"]
    folder_data = st.session_state["folder_results"]

    cols = st.columns(4)

    dashboard_metrics = [
        (
            "Processes Scanned",
            len(process_data) if process_data is not None else 0,
        ),
        ("Processes to Review", flagged_count(process_data)),
        (
            "Files Inspected",
            len(folder_data) if folder_data is not None else 0,
        ),
        ("Files to Review", flagged_count(folder_data)),
    ]

    for col, (label, value) in zip(cols, dashboard_metrics):
        with col:
            metric(label, value)

    st.markdown("### Available Security Tools")

    left, right = st.columns(2)

    with left:
        st.markdown("#### 🖥️ Process Scanner")
        st.write(
            "Review running-process metadata visible to the app."
        )
        st.markdown(
            "- Process name inspection\n"
            "- Detection indicators\n"
            "- CSV and JSON reports"
        )
        st.button(
            "Open Process Scanner",
            type="primary",
            use_container_width=True,
            key="go_process",
            on_click=navigate_to,
            args=("Process Scanner",),
        )

    with right:
        st.markdown("#### 📁 Folder Scanner")
        st.write(
            "Upload files or select a folder to review filenames."
        )
        st.markdown(
            "- Filename inspection\n"
            "- Suspicious extension checks\n"
            "- CSV and JSON reports"
        )
        st.button(
            "Open Folder Scanner",
            type="primary",
            use_container_width=True,
            key="go_folder",
            on_click=navigate_to,
            args=("Folder Scanner",),
        )

    st.markdown("### Recent Process Results")

    if process_data is not None and not process_data.empty:
        st.dataframe(
            process_data.head(10),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info(
            "No process scan has been performed during this session."
        )


# --------------------------------------------------
# PROCESS SCANNER PAGE
# --------------------------------------------------

elif page == "Process Scanner":

    st.markdown(
        '<div class="section-heading">🖥️ Running Process Scanner</div>',
        unsafe_allow_html=True,
    )

    st.write(
        "Inspect process names, executable paths, and available "
        "account metadata for configured indicators."
    )

    st.info(
        "On the hosted website, this scans processes visible on "
        "the Streamlit server, not processes on your personal laptop."
    )

    if st.button(
        "▶ Start Process Scan",
        type="primary",
        use_container_width=True,
        key="start_process_scan",
    ):
        try:
            with st.spinner("Scanning visible processes..."):
                result = scan_processes()

            st.session_state["process_results"] = result

            if not result.empty:
                record_report(result, "Process Scan")

            st.success(
                f"Scan completed: {len(result)} processes inspected."
            )

        except Exception as exc:
            st.error(f"Process scan failed: {exc}")

    result = st.session_state["process_results"]

    if result is not None:
        st.markdown("### Process Scan Results")

        if result.empty:
            st.info("No process information could be collected.")
        else:
            a, b, c = st.columns(3)

            with a:
                metric("Processes", len(result))

            with b:
                metric("Flagged for Review", flagged_count(result))

            with c:
                metric(
                    "No Indicator Found",
                    len(result) - flagged_count(result),
                )

            choice = st.selectbox(
                "Filter results",
                [
                    "All Processes",
                    "Review Only",
                    "No Indicator Found",
                ],
                key="process_filter",
            )

            shown = result

            if choice == "Review Only":
                shown = result[
                    result["Risk Classification"] == "Review"
                ]
            elif choice == "No Indicator Found":
                shown = result[
                    result["Risk Classification"]
                    == "No indicator found"
                ]

            st.dataframe(
                shown,
                use_container_width=True,
                hide_index=True,
            )

            downloads(result, "process_scan")

        st.caption(
            "Detection indicators are heuristic signals, not "
            "confirmed malware findings."
        )


# --------------------------------------------------
# FOLDER SCANNER PAGE - HOSTED VERSION
# --------------------------------------------------

elif page == "Folder Scanner":

    st.markdown(
        '<div class="section-heading">📁 Folder Scanner</div>',
        unsafe_allow_html=True,
    )

    st.write(
        "Upload files or select a folder from your computer "
        "to inspect filenames for suspicious indicators."
    )

    st.info(
        "This hosted scanner checks filenames and extensions only. "
        "It does not execute files or inspect their contents."
    )

    st.warning(
        "Files selected here are uploaded to the hosted application. "
        "Only upload files you are authorised to share."
    )

    st.markdown("### Option 1: Upload individual files")

    uploaded_files = st.file_uploader(
        "Choose one or more files",
        accept_multiple_files=True,
        key="individual_file_upload",
    )

    st.markdown("### Option 2: Select a folder")

    uploaded_folder_files = st.file_uploader(
        "Choose a folder to upload",
        accept_multiple_files="directory",
        key="directory_upload",
    )

    files_to_scan = list(uploaded_files or [])
    files_to_scan.extend(list(uploaded_folder_files or []))

    # Remove duplicate entries when the same file was
    # selected in both upload areas.
    unique_files = {}
    for uploaded_file in files_to_scan:
        unique_files[uploaded_file.name] = uploaded_file

    files_to_scan = list(unique_files.values())

    st.caption(f"Files selected: {len(files_to_scan)}")

    if st.button(
        "▶ Scan Uploaded Files",
        type="primary",
        use_container_width=True,
        key="start_uploaded_folder_scan",
    ):

        if not files_to_scan:
            st.warning(
                "Please upload files or select a folder first."
            )

        else:
            try:
                with st.spinner("Inspecting uploaded filenames..."):
                    result = inspect_uploaded_files(files_to_scan)

                st.session_state["folder_results"] = result

                if not result.empty:
                    record_report(result, "Folder Scan")

                st.success(
                    f"Scan completed: {len(result)} files inspected."
                )

            except Exception as exc:
                st.error(f"Folder scan failed: {exc}")

    result = st.session_state["folder_results"]

    if result is not None:
        st.markdown("### Folder Scan Results")

        if result.empty:
            st.info("No files were available to inspect.")

        else:
            a, b, c = st.columns(3)

            with a:
                metric("Files Inspected", len(result))

            with b:
                metric("Flagged for Review", flagged_count(result))

            with c:
                metric(
                    "No Indicator Found",
                    len(result) - flagged_count(result),
                )

            choice = st.selectbox(
                "Filter files",
                [
                    "All Files",
                    "Review Only",
                    "No Indicator Found",
                ],
                key="folder_filter",
            )

            shown = result

            if choice == "Review Only":
                shown = result[
                    result["Risk Classification"] == "Review"
                ]
            elif choice == "No Indicator Found":
                shown = result[
                    result["Risk Classification"]
                    == "No indicator found"
                ]

            st.dataframe(
                shown,
                use_container_width=True,
                hide_index=True,
            )

            downloads(result, "folder_scan")

            st.caption(
                "A filename match indicates that a file needs review; "
                "it does not establish that the file is malicious."
            )


# --------------------------------------------------
# REPORTS PAGE
# --------------------------------------------------

elif page == "Reports":

    st.markdown(
        '<div class="section-heading">📄 Security Reports</div>',
        unsafe_allow_html=True,
    )

    tab1, tab2, tab3 = st.tabs(
        ["Process Report", "Folder Report", "Report History"]
    )

    with tab1:
        data = st.session_state["process_results"]

        if data is None:
            st.info("Run a process scan to create this report.")
        else:
            st.dataframe(
                data,
                use_container_width=True,
                hide_index=True,
            )
            downloads(data, "process_scan")

    with tab2:
        data = st.session_state["folder_results"]

        if data is None:
            st.info(
                "Upload and scan files to create a folder report."
            )
        else:
            st.dataframe(
                data,
                use_container_width=True,
                hide_index=True,
            )
            downloads(data, "folder_scan")

    with tab3:
        history = st.session_state["report_history"]

        if history:
            st.dataframe(
                pd.DataFrame(history),
                use_container_width=True,
                hide_index=True,
            )
            st.caption(
                "Report history is kept in the current app session. "
                "Download reports to keep a copy."
            )
        else:
            st.info(
                "No reports have been generated during this session."
            )


# --------------------------------------------------
# ABOUT PAGE
# --------------------------------------------------

elif page == "About":

    st.markdown(
        '<div class="section-heading">ℹ️ About This Project</div>',
        unsafe_allow_html=True,
    )

    st.write(
        "Keylogger Detection System is an educational Python "
        "cybersecurity dashboard that flags selected indicators "
        "for further review."
    )

    st.markdown(
        """
        **Main modules**

        - **Dashboard:** Summarises scan results.
        - **Process Scanner:** Reviews visible process metadata.
        - **Folder Scanner:** Checks uploaded filenames and extensions.
        - **Reports:** Provides CSV and JSON downloads.
        """
    )

    st.markdown(
        """
        **Technologies used**

        - Python
        - Streamlit
        - Pandas
        - psutil
        """
    )

    st.warning(
        "This project is not a full antivirus product. It does not "
        "record keystrokes, inspect all file contents, or guarantee "
        "malware detection."
    )

    st.info(
        "Only inspect systems and files you own or are authorised "
        "to examine."
    )

    st.markdown(
        """
        **Project repository**

        https://github.com/Alfiy123/keylogger_detection_system
        """
    )


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.markdown(
    """
    <div class="footer">
        🔐 Keylogger Detection System | Built with Python and Streamlit
    </div>
    """,
    unsafe_allow_html=True,
)
