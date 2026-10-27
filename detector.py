import psutil
import os
from datetime import datetime


# Names that may warrant further investigation.
# These are indicators, not proof of malicious activity.
SUSPICIOUS_NAME_INDICATORS = [
    "keylogger",
    "keylog",
    "keystroke",
    "keyboard_capture",
    "key_capture",
    "pynput",
]

# Potentially suspicious file extensions.
SUSPICIOUS_EXTENSIONS = [
    ".vbs",
    ".js",
    ".bat",
    ".ps1",
    ".scr",
]


def scan_processes():
    """
    Inspect running process metadata.

    This function does not read keyboard input or
    inspect the contents of other processes' memory.
    """

    results = []

    for process in psutil.process_iter(
        ["pid", "name", "exe", "username"]
    ):
        try:
            info = process.info

            process_name = (
                info.get("name") or "Unknown"
            )

            executable_path = (
                info.get("exe") or "Unavailable"
            )

            username = (
                info.get("username") or "Unknown"
            )

            indicators = []

            name_lower = process_name.lower()
            path_lower = executable_path.lower()

            # Check process name for suspicious indicators.
            for keyword in SUSPICIOUS_NAME_INDICATORS:
                if keyword in name_lower:
                    indicators.append(
                        f"Process name contains: {keyword}"
                    )

            # Check the executable path for suspicious names.
            for keyword in SUSPICIOUS_NAME_INDICATORS:
                if keyword in path_lower:
                    indicators.append(
                        f"Executable path contains: {keyword}"
                    )

            if indicators:
                risk_level = "High"
                status = "Needs investigation"
            else:
                risk_level = "Not flagged"
                status = "No matching indicator found"

            results.append(
                {
                    "timestamp": datetime.now().isoformat(
                        timespec="seconds"
                    ),
                    "pid": info.get("pid"),
                    "process_name": process_name,
                    "executable_path": executable_path,
                    "username": username,
                    "risk_level": risk_level,
                    "indicators": "; ".join(indicators),
                    "status": status,
                }
            )

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            # A process may exit during scanning,
            # or Windows may restrict access to its metadata.
            continue

    return results


def scan_folder(folder_path):
    """
    Inspect file names in a user-selected folder.

    This is a basic filename-based scan, not antivirus
    scanning or proof that a file is malicious.
    """

    results = []

    if not os.path.isdir(folder_path):
        raise ValueError(
            "Please select a valid folder."
        )

    for root, _, filenames in os.walk(folder_path):

        for filename in filenames:

            full_path = os.path.join(root, filename)

            extension = os.path.splitext(
                filename
            )[1].lower()

            indicators = []

            filename_lower = filename.lower()

            for keyword in SUSPICIOUS_NAME_INDICATORS:
                if keyword in filename_lower:
                    indicators.append(
                        f"Filename contains: {keyword}"
                    )

            if extension in SUSPICIOUS_EXTENSIONS:
                indicators.append(
                    f"File has potentially risky extension: "
                    f"{extension}"
                )

            if indicators:
                risk_level = "Review"
                status = "Potentially suspicious filename"
            else:
                risk_level = "Not flagged"
                status = "No matching filename indicator"

            results.append(
                {
                    "timestamp": datetime.now().isoformat(
                        timespec="seconds"
                    ),
                    "filename": filename,
                    "file_path": full_path,
                    "extension": extension,
                    "risk_level": risk_level,
                    "indicators": "; ".join(indicators),
                    "status": status,
                }
            )

    return results