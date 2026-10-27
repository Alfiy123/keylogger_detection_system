import os
from datetime import datetime
from pathlib import Path

import pandas as pd
import psutil
import streamlit as st

st.set_page_config(
    page_title="Keylogger Detection System",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

PROCESS_TERMS = ["keylogger", "keylog", "keystroke", "pynput", "pykeylogger"]
FILE_TERMS = ["keylogger", "keylog", "keystroke", "stealer", "credential_dump"]
SUSPICIOUS_EXTENSIONS = [".scr", ".pif"]

st.markdown("""
<style>
.stApp {background:#f4f7fb;color:#172b4d}
[data-testid="stSidebar"] {background:#10243a}
[data-testid="stSidebar"] * {color:white !important}
.main-title {font-size:34px;font-weight:800;color:#163a63}
.subtitle {font-size:16px;color:#52677e;margin-bottom:22px}
.section-heading {font-size:25px;font-weight:750;color:#163a63}
.metric-card {background:white;padding:16px;border-radius:12px;border:1px solid #dce5ef;margin-bottom:10px}
.metric-label {color:#61758a;font-size:14px}
.metric-value {color:#163a63;font-size:28px;font-weight:800}
div.stButton>button[kind="primary"] {background:#1677e8;color:white;border:0;border-radius:8px;min-height:44px;font-weight:700}
.footer {text-align:center;color:#718096;padding-top:20px;font-size:13px}
</style>
""", unsafe_allow_html=True)

# Initialise state before the navigation widget is created.
if "main_navigation" not in st.session_state:
    st.session_state["main_navigation"] = "Dashboard"
for key in ("process_results", "folder_results"):
    if key not in st.session_state:
        st.session_state[key] = None
if "report_history" not in st.session_state:
    st.session_state["report_history"] = []

def navigate_to(page_name):
    # This callback runs before the next render, so changing the radio key is safe.
    st.session_state["main_navigation"] = page_name

def metric(label, value):
    st.markdown(
        f'<div class="metric-card"><div class="metric-label">{label}</div>'
        f'<div class="metric-value">{value}</div></div>',
        unsafe_allow_html=True,
    )

def flagged_count(df):
    if df is None or df.empty or "Risk Classification" not in df.columns:
        return 0
    return int((df["Risk Classification"] == "Review").sum())

def scan_processes():
    rows = []
    for proc in psutil.process_iter(["pid", "name", "exe", "username", "cmdline", "status"]):
        try:
            info = proc.info
            name = str(info.get("name") or "Unknown")
            exe = str(info.get("exe") or "Unavailable")
            user = str(info.get("username") or "Unavailable")
            cmd = info.get("cmdline") or []
            if isinstance(cmd, list):
                cmd = " ".join(str(part) for part in cmd)
            text = f"{name} {exe} {cmd}".lower()
            indicators = [f"Configured keyword match: {term}" for term in PROCESS_TERMS if term in text]
            normal_path = exe.lower().replace("\\", "/")
            if any(p in normal_path for p in ("/appdata/local/temp/", "/windows/temp/", "/users/public/")):
                indicators.append("Executable in a temporary/public-writable location")
            rows.append({
                "Process ID": info.get("pid"),
                "Process Name": name,
                "Executable Path": exe,
                "User Account": user,
                "Status": info.get("status") or "Unknown",
                "Detection Indicators": "; ".join(indicators) if indicators else "None detected",
                "Risk Classification": "Review" if indicators else "No indicator found",
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue
    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values(["Risk Classification", "Process Name"]).reset_index(drop=True)
    return df

def scan_folder(folder_text):
    folder = Path(folder_text).expanduser()
    if not folder.exists():
        raise FileNotFoundError("The selected folder does not exist.")
    if not folder.is_dir():
        raise NotADirectoryError("The selected path is not a folder.")
    rows = []
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d.lower() not in {"$recycle.bin", "system volume information"}]
        for filename in files:
            path = Path(root) / filename
            low = filename.lower()
            indicators = [f"Filename keyword match: {term}" for term in FILE_TERMS if term in low]
            if path.suffix.lower() in SUSPICIOUS_EXTENSIONS:
                indicators.append(f"Extension for review: {path.suffix.lower()}")
            try:
                size = path.stat().st_size
            except (OSError, PermissionError):
                size = None
            rows.append({
                "File Name": filename,
                "File Path": str(path),
                "Extension": path.suffix.lower() or "No extension",
                "Size (Bytes)": size,
                "Detection Indicators": "; ".join(indicators) if indicators else "None detected",
                "Risk Classification": "Review" if indicators else "No indicator found",
            })
    return pd.DataFrame(rows)

def save_report(df, report_type):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = REPORT_DIR / f"{report_type}_{stamp}.csv"
    json_path = REPORT_DIR / f"{report_type}_{stamp}.json"
    df.to_csv(csv_path, index=False)
    json_path.write_text(df.to_json(orient="records", indent=2, force_ascii=False), encoding="utf-8")
    st.session_state["report_history"].append({
        "Report Type": report_type,
        "Created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "CSV File": csv_path.name,
        "JSON File": json_path.name,
        "Rows": len(df),
    })

def downloads(df, report_type):
    if df is None or df.empty:
        st.info("No results available to download yet.")
        return
    c1, c2 = st.columns(2)
    with c1:
        st.download_button("⬇️ Download CSV Report", df.to_csv(index=False).encode("utf-8"),
            f"{report_type}_report.csv", "text/csv", use_container_width=True, key=f"{report_type}_csv")
    with c2:
        st.download_button("⬇️ Download JSON Report",
            df.to_json(orient="records", indent=2, force_ascii=False).encode("utf-8"),
            f"{report_type}_report.json", "application/json", use_container_width=True, key=f"{report_type}_json")

# Sidebar navigation
with st.sidebar:
    st.markdown("## 🛡️ Security Center")
    st.write("Keylogger Detection System")
    st.divider()
    page = st.radio(
        "Navigation",
        ["Dashboard", "Process Scanner", "Folder Scanner", "Reports", "About"],
        key="main_navigation",
    )
    st.divider()
    st.caption("Python Cybersecurity Project")
    st.caption("Educational use only")

st.markdown('<div class="main-title">🔐 Keylogger Detection System</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">A Python cybersecurity dashboard for inspecting running process metadata and reviewing suspicious filenames.</div>', unsafe_allow_html=True)
st.warning("Educational tool: a flagged item is not proof of malware, and no flagged items does not guarantee that a device is safe.")

if page == "Dashboard":
    st.markdown('<div class="section-heading">📊 Security Dashboard</div>', unsafe_allow_html=True)
    p = st.session_state["process_results"]
    f = st.session_state["folder_results"]
    cols = st.columns(4)
    for col, (label, value) in zip(cols, [
        ("Processes Scanned", len(p) if p is not None else 0),
        ("Processes to Review", flagged_count(p)),
        ("Files Inspected", len(f) if f is not None else 0),
        ("Files to Review", flagged_count(f)),
    ]):
        with col:
            metric(label, value)
    st.markdown("### Available Security Tools")
    left, right = st.columns(2)
    with left:
        st.markdown("#### 🖥️ Process Scanner")
        st.write("Inspect running process names, executable paths, and available user metadata.")
        st.markdown("- Process name inspection\n- Metadata results\n- CSV and JSON report downloads")
        st.button("Open Process Scanner", type="primary", use_container_width=True,
                   key="go_process", on_click=navigate_to, args=("Process Scanner",))
    with right:
        st.markdown("#### 📁 Folder Scanner")
        st.write("Inspect filenames in a folder you are authorized to access.")
        st.markdown("- Filename inspection\n- Basic indicator checks\n- CSV and JSON report downloads")
        st.button("Open Folder Scanner", type="primary", use_container_width=True,
                   key="go_folder", on_click=navigate_to, args=("Folder Scanner",))
    st.markdown("### Recent Process Results")
    if p is not None and not p.empty:
        st.dataframe(p.head(10), use_container_width=True, hide_index=True)
    else:
        st.info("No scan has been performed yet. Choose Process Scanner in the sidebar.")

elif page == "Process Scanner":
    st.markdown('<div class="section-heading">🖥️ Running Process Scanner</div>', unsafe_allow_html=True)
    st.write("Inspect running process metadata for configured suspicious indicators.")
    st.info("This scanner checks process names, executable paths, and available account metadata. It does not record keystrokes or passwords.")
    if st.button("▶ Start Process Scan", type="primary", use_container_width=True, key="start_process_scan"):
        try:
            with st.spinner("Scanning running processes..."):
                result = scan_processes()
            st.session_state["process_results"] = result
            if not result.empty:
                save_report(result, "process_scan")
            st.success(f"Scan completed: {len(result)} processes inspected.")
        except Exception as exc:
            st.error(f"Process scan failed: {exc}")
    result = st.session_state["process_results"]
    if result is not None:
        st.markdown("### Process Scan Results")
        if result.empty:
            st.warning("No process information could be collected.")
        else:
            a, b, c = st.columns(3)
            with a: metric("Processes", len(result))
            with b: metric("Flagged for Review", flagged_count(result))
            with c: metric("No Indicator Found", len(result) - flagged_count(result))
            choice = st.selectbox("Filter results", ["All Processes", "Review Only", "No Indicator Found"], key="process_filter")
            shown = result
            if choice == "Review Only":
                shown = result[result["Risk Classification"] == "Review"]
            elif choice == "No Indicator Found":
                shown = result[result["Risk Classification"] == "No indicator found"]
            st.dataframe(shown, use_container_width=True, hide_index=True)
            downloads(result, "process_scan")
            st.caption("Detection indicators are heuristic signals, not confirmed malware findings.")

elif page == "Folder Scanner":
    st.markdown('<div class="section-heading">📁 Folder Scanner</div>', unsafe_allow_html=True)
    st.write("Inspect filenames in a folder you own or have permission to examine.")
    st.info("This scanner checks filenames and extensions only. It does not execute or modify files.")
    folder_path = st.text_input("Folder path", value=str(Path.home() / "Downloads"),
                                placeholder=r"C:\Users\YourName\Downloads", key="folder_path_input")
    if st.button("▶ Scan Folder", type="primary", use_container_width=True, key="start_folder_scan"):
        try:
            with st.spinner("Inspecting folder filenames..."):
                result = scan_folder(folder_path)
            st.session_state["folder_results"] = result
            if not result.empty:
                save_report(result, "folder_scan")
            st.success(f"Folder scan completed: {len(result)} files inspected.")
        except (FileNotFoundError, NotADirectoryError) as exc:
            st.error(str(exc))
        except PermissionError:
            st.error("Permission denied. Choose a folder you are authorized to inspect.")
        except Exception as exc:
            st.error(f"Folder scan failed: {exc}")
    result = st.session_state["folder_results"]
    if result is not None:
        st.markdown("### Folder Scan Results")
        if result.empty:
            st.info("No files were found in the selected folder.")
        else:
            a, b, c = st.columns(3)
            with a: metric("Files Inspected", len(result))
            with b: metric("Flagged for Review", flagged_count(result))
            with c: metric("No Indicator Found", len(result) - flagged_count(result))
            choice = st.selectbox("Filter files", ["All Files", "Review Only", "No Indicator Found"], key="folder_filter")
            shown = result
            if choice == "Review Only":
                shown = result[result["Risk Classification"] == "Review"]
            elif choice == "No Indicator Found":
                shown = result[result["Risk Classification"] == "No indicator found"]
            st.dataframe(shown, use_container_width=True, hide_index=True)
            downloads(result, "folder_scan")

elif page == "Reports":
    st.markdown('<div class="section-heading">📄 Security Reports</div>', unsafe_allow_html=True)
    tab1, tab2, tab3 = st.tabs(["Process Report", "Folder Report", "Saved Reports"])
    with tab1:
        data = st.session_state["process_results"]
        if data is None:
            st.info("Run a process scan to create this report.")
        else:
            st.dataframe(data, use_container_width=True, hide_index=True)
            downloads(data, "process_scan")
    with tab2:
        data = st.session_state["folder_results"]
        if data is None:
            st.info("Run a folder scan to create this report.")
        else:
            st.dataframe(data, use_container_width=True, hide_index=True)
            downloads(data, "folder_scan")
    with tab3:
        if st.session_state["report_history"]:
            st.dataframe(pd.DataFrame(st.session_state["report_history"]), use_container_width=True, hide_index=True)
            st.caption(f"Local reports folder: {REPORT_DIR}")
        else:
            st.info("No reports have been created during this session.")

elif page == "About":
    st.markdown('<div class="section-heading">ℹ️ About This Project</div>', unsafe_allow_html=True)
    st.write("Keylogger Detection System is an educational Python cybersecurity dashboard.")
    st.markdown("- **Process Scanner:** reviews running process metadata.\n- **Folder Scanner:** checks filenames for configured indicators.\n- **Reports:** exports CSV and JSON.\n- **Dashboard:** summarizes scan results.")
    st.write("Technologies: Python, Streamlit, Pandas, and psutil.")
    st.warning("This is not a full antivirus product. It does not capture keystrokes, inspect every file's contents, or guarantee malware detection.")
    st.info("Only inspect devices and folders you own or are authorized to examine.")

st.divider()
st.markdown('<div class="footer">🔐 Keylogger Detection System | Built with Python and Streamlit</div>', unsafe_allow_html=True)