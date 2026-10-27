import json
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

from detector import scan_processes, scan_folder


# ==========================================================
# 1. PAGE CONFIGURATION
# ==========================================================

st.set_page_config(
    page_title="Keylogger Detection System",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ==========================================================
# 2. PROJECT PATHS
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"

# Create the reports folder safely.
if REPORT_DIR.exists() and not REPORT_DIR.is_dir():
    st.error(
        "The path named 'reports' is a file, not a folder. "
        "Rename that file and restart the application."
    )
    st.stop()

REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ==========================================================
# 3. CUSTOM CSS
# ==========================================================

st.markdown(
    """
    <style>

    /* Main application background */
    .stApp {
        background-color: #F3F6FB;
        color: #172033;
    }

    /* Headings */
    h1, h2, h3 {
        color: #14213D !important;
        font-weight: 700 !important;
    }

    /* Main text */
    .stApp p,
    .stApp label,
    .stApp li {
        color: #263449;
    }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #14213D;
    }

    section[data-testid="stSidebar"] h1,
    section[data-testid="stSidebar"] h2,
    section[data-testid="stSidebar"] h3,
    section[data-testid="stSidebar"] p,
    section[data-testid="stSidebar"] label,
    section[data-testid="stSidebar"] span {
        color: #FFFFFF !important;
    }

    /* Metric cards */
    div[data-testid="stMetric"] {
        background-color: #FFFFFF;
        border: 1px solid #DCE3EE;
        border-radius: 12px;
        padding: 18px;
        box-shadow: 0 2px 8px rgba(20, 33, 61, 0.05);
    }

    div[data-testid="stMetricLabel"] {
        color: #334155 !important;
    }

    div[data-testid="stMetricValue"] {
        color: #14213D !important;
    }

    /* Buttons */
    .stButton button,
    .stDownloadButton button {
        border-radius: 8px;
        font-weight: 600;
        min-height: 42px;
    }

    /* Tables */
    div[data-testid="stDataFrame"] {
        background-color: #FFFFFF;
        border-radius: 10px;
    }

    /* Footer */
    .footer-text {
        text-align: center;
        color: #64748B;
        font-size: 13px;
        padding: 12px;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ==========================================================
# 4. HELPER FUNCTIONS
# ==========================================================

def save_report(report_type, results):
    """Save scan results as a JSON file."""

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    report_path = REPORT_DIR / (
        f"{report_type}_{timestamp}.json"
    )

    report_data = {
        "project": "Keylogger Detection System",
        "report_type": report_type,
        "created_at": datetime.now().isoformat(
            timespec="seconds"
        ),
        "total_items": len(results),
        "results": results,
    }

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(
            report_data,
            file,
            indent=4,
            default=str,
        )

    return report_path


def show_scan_results(results, report_name):
    """Display results and provide CSV and JSON downloads."""

    if results is None:
        st.warning("The scanner did not return any results.")
        return

    # Convert results into a list of dictionaries.
    if isinstance(results, pd.DataFrame):
        df = results.copy()

    elif isinstance(results, list):
        df = pd.DataFrame(results)

    elif isinstance(results, dict):
        df = pd.DataFrame(results)

    else:
        st.error(
            "The scanner returned an unsupported result format."
        )
        return

    if df.empty:
        st.info("No results were returned by the scanner.")
        return

    st.success("Scan completed successfully!")

    # Display metrics.
    risk_column = next(
        (
            col for col in
            ["risk_level", "risk", "severity", "status"]
            if col in df.columns
        ),
        None,
    )

    if risk_column:
        risk_values = (
            df[risk_column]
            .fillna("")
            .astype(str)
            .str.lower()
        )

        flagged_count = int(
            risk_values.isin(
                ["high", "critical", "review", "suspicious"]
            ).sum()
        )
    else:
        flagged_count = 0

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Items Inspected",
        len(df),
    )

    col2.metric(
        "Items Flagged",
        flagged_count,
    )

    col3.metric(
        "Not Flagged",
        len(df) - flagged_count,
    )

    st.subheader("Scan Results")

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
    )

    if flagged_count:
        st.warning(
            "Some items matched the configured detection rules. "
            "Investigate them before deciding whether they are "
            "malicious. A match is not proof of malware."
        )
    else:
        st.info(
            "No items matched the supported risk categories. "
            "This does not guarantee that the device is safe."
        )

    # Prepare JSON-safe records.
    json_records = json.loads(
        df.to_json(
            orient="records",
            date_format="iso",
        )
    )

    st.subheader("Download Reports")

    col1, col2 = st.columns(2)

    with col1:
        st.download_button(
            label="⬇ Download CSV",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name=f"{report_name}.csv",
            mime="text/csv",
            use_container_width=True,
        )

    with col2:
        st.download_button(
            label="⬇ Download JSON",
            data=json.dumps(
                json_records,
                indent=4,
            ),
            file_name=f"{report_name}.json",
            mime="application/json",
            use_container_width=True,
        )

    # Save a copy to the local reports directory.
    try:
        report_path = save_report(
            report_name,
            json_records,
        )

        st.caption(
            f"Local report saved: {report_path.name}"
        )

    except OSError as error:
        st.warning(
            f"Could not save a local report: {error}"
        )


# ==========================================================
# 5. SIDEBAR NAVIGATION
# ==========================================================

st.sidebar.markdown(
    """
    <h2>🛡️ Security Center</h2>
    <p>Keylogger Detection System</p>
    """,
    unsafe_allow_html=True,
)

st.sidebar.divider()

# Use one radio control as the source of navigation.
page = st.sidebar.radio(
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

st.sidebar.divider()

st.sidebar.caption("Python Cybersecurity Project")


# ==========================================================
# 6. APPLICATION HEADER
# ==========================================================

st.markdown(
    """
    <h1>🔐 Keylogger Detection System</h1>
    <p style="font-size:17px;">
        A Python-based cybersecurity dashboard for inspecting
        running process metadata and reviewing suspicious
        filename indicators.
    </p>
    """,
    unsafe_allow_html=True,
)

st.warning(
    "Educational security tool. Detection rules are limited: "
    "a flagged item is not proof of malware, and an unflagged "
    "item does not guarantee that a device is safe."
)


# ==========================================================
# 7. DASHBOARD PAGE
# ==========================================================

if page == "Dashboard":

    st.subheader("Security Overview")

    st.write(
        "Use the navigation menu on the left to inspect "
        "running processes, review folder contents, and "
        "generate security reports."
    )

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Detection Modules",
        "2",
    )

    col2.metric(
        "Keyboard Recording",
        "Disabled",
    )

    col3.metric(
        "Report Formats",
        "CSV / JSON",
    )

    st.divider()

    st.subheader("Available Security Tools")

    card1, card2 = st.columns(2)

    with card1:
        st.markdown(
            """
            ### 🖥️ Process Scanner

            Inspect running process metadata for configured
            suspicious indicators.

            **Features**
            - Process name inspection
            - Process metadata results
            - CSV and JSON report downloads
            """
        )

    with card2:
        st.markdown(
            """
            ### 📁 Folder Scanner

            Inspect filenames in a folder you are authorized
            to access.

            **Features**
            - Filename inspection
            - Configured indicator checks
            - CSV report downloads
            """
        )

    st.info(
        "Select Process Scanner or Folder Scanner in the "
        "left sidebar to begin."
    )


# ==========================================================
# 8. PROCESS SCANNER PAGE
# ==========================================================

elif page == "Process Scanner":

    st.subheader("🖥️ Running Process Scanner")

    st.write(
        "Inspect running process metadata for configured "
        "name-based indicators."
    )

    st.info(
        "This scanner does not record keystrokes, capture "
        "typed text, or collect passwords."
    )

    if st.button(
        "▶ Start Process Scan",
        type="primary",
        use_container_width=True,
        key="start_process_scan",
    ):

        try:
            with st.spinner(
                "Inspecting running processes..."
            ):
                results = scan_processes()

            st.session_state["process_scan_results"] = results

        except Exception as error:
            st.error(
                f"Process scan failed: {error}"
            )

    # Keep results visible after Streamlit reruns.
    if "process_scan_results" in st.session_state:
        st.divider()

        show_scan_results(
            st.session_state["process_scan_results"],
            "process_scan",
        )


# ==========================================================
# 9. FOLDER SCANNER PAGE
# ==========================================================

elif page == "Folder Scanner":

    st.subheader("📁 Folder Scanner")

    st.write(
        "Inspect filenames inside a folder you are authorized "
        "to access."
    )

    st.warning(
        "Filename-based detection is limited. A file extension "
        "or filename alone cannot prove that a file is malicious."
    )

    default_folder = str(
        Path.home() / "Downloads"
    )

    folder_path = st.text_input(
        "Enter the folder path",
        value=default_folder,
        placeholder="C:\\Users\\YourName\\Downloads",
    )

    if st.button(
        "▶ Scan Folder",
        type="primary",
        use_container_width=True,
        key="start_folder_scan",
    ):

        if not folder_path.strip():
            st.error("Please enter a folder path.")

        elif not Path(folder_path).expanduser().is_dir():
            st.error(
                "The specified folder does not exist. "
                "Check the path and try again."
            )

        else:
            try:
                with st.spinner(
                    "Inspecting folder filenames..."
                ):
                    results = scan_folder(
                        folder_path.strip()
                    )

                st.session_state["folder_scan_results"] = results

            except Exception as error:
                st.error(
                    f"Folder scan failed: {error}"
                )

    if "folder_scan_results" in st.session_state:
        st.divider()

        show_scan_results(
            st.session_state["folder_scan_results"],
            "folder_scan",
        )


# ==========================================================
# 10. REPORTS PAGE
# ==========================================================

elif page == "Reports":

    st.subheader("📊 Saved Security Reports")

    st.write(
        "Review and download JSON reports created by previous "
        "scans in this local project."
    )

    report_files = sorted(
        REPORT_DIR.glob("*.json"),
        key=lambda file: file.stat().st_mtime,
        reverse=True,
    )

    if not report_files:
        st.info(
            "No saved reports are available yet. "
            "Run a scan to create your first report."
        )

    else:
        st.metric(
            "Saved Reports",
            len(report_files),
        )

        for report_file in report_files:

            with st.expander(report_file.name):

                try:
                    report_text = report_file.read_text(
                        encoding="utf-8"
                    )

                    report_data = json.loads(report_text)

                    st.write(
                        "**Report type:**",
                        report_data.get(
                            "report_type",
                            "Unknown",
                        ),
                    )

                    st.write(
                        "**Created at:**",
                        report_data.get(
                            "created_at",
                            "Unknown",
                        ),
                    )

                    st.write(
                        "**Items:**",
                        report_data.get(
                            "total_items",
                            0,
                        ),
                    )

                    st.download_button(
                        "⬇ Download Report",
                        data=report_text,
                        file_name=report_file.name,
                        mime="application/json",
                        key=f"download_{report_file.name}",
                    )

                except (
                    OSError,
                    json.JSONDecodeError,
                ) as error:
                    st.error(
                        f"Could not read this report: {error}"
                    )


# ==========================================================
# 11. ABOUT PAGE
# ==========================================================

elif page == "About":

    st.subheader("ℹ️ About the Project")

    st.markdown(
        """
        ### Keylogger Detection System Using Python

        **Objective**

        Demonstrate basic cybersecurity monitoring using
        Python and a Streamlit dashboard.

        **Main features**

        - Inspect running process metadata.
        - Review configured suspicious indicators.
        - Inspect filenames in selected folders.
        - Display scan results in tables.
        - Download CSV and JSON reports.

        **Technologies used**

        - Python
        - Streamlit
        - Pandas
        - Psutil
        - JSON

        **Limitations**

        The project uses basic detection rules. It can produce
        false positives and may miss sophisticated threats.

        It does not capture keystrokes, collect passwords,
        or automatically terminate processes.

        It is an educational demonstration and not a replacement
        for professional endpoint security software.
        """
    )

    st.info(
        "Only inspect devices and files that you own or "
        "have permission to investigate."
    )


# ==========================================================
# 12. FOOTER
# ==========================================================

st.divider()

st.markdown(
    """
    <div class="footer-text">
        🔐 Keylogger Detection System |
        Built with Python and Streamlit
    </div>
    """,
    unsafe_allow_html=True,
)