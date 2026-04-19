import subprocess
from loguru import logger


ALLOWLISTED_PROCESSES = {
    "svchost.exe",
    "searchindexer.exe",
    "searchprotocolhost.exe",
    "tiworker.exe",
    "trustedinstaller.exe",
    "msiexec.exe",
    "wuauclt.exe",
    "backgroundtaskhost.exe",
    "runtimebroker.exe",
    "dllhost.exe",
    "wmiprvse.exe",
    "spoolsv.exe",
    "lsass.exe",
    "services.exe",
    "smss.exe",
    "csrss.exe",
    "winlogon.exe",
    "explorer.exe",
    "onedrive.exe",
    "dropbox.exe",
    "googledrivefs.exe",
    "msedge.exe",
    "chrome.exe",
    "firefox.exe",
    "brave.exe",
}

# System-owned paths that legitimate Windows processes rename files in
SYSTEM_OWNED_PATHS = [
    "\\appdata\\local\\microsoft\\",
    "\\appdata\\roaming\\microsoft\\",
    "\\appdata\\local\\packages\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\local\\comms\\",
    "\\appdata\\local\\connectedddevicesplatform\\",
    "\\appdata\\local\\d3dscrapcache\\",
]


def get_process_name(pid):
    """Get process name by PID using tasklist."""
    try:
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split(',')
            if parts and len(parts) > 1:
                name = parts[0].strip('"').lower()
                # tasklist returns "No tasks are running..." if not found
                if "no tasks" not in name:
                    return name
    except Exception:
        pass
    return ""


class TripwireEngine:

    def __init__(self, config):
        self.config = config["tripwires"]
        logger.info("TripwireEngine initialized")

    def _get_dominant_pid(self, events):
        """Find the PID responsible for most events in this window."""
        pid_counts = {}
        for event in events:
            try:
                pid = int(event.process_id)
                if pid > 4:
                    pid_counts[pid] = pid_counts.get(pid, 0) + 1
            except (ValueError, TypeError):
                continue
        if not pid_counts:
            return 0
        return max(pid_counts, key=pid_counts.get)

    def check(self, events):
        """
        Hard deterministic rules — fire immediately, no ML.
        Returns {"triggered": bool, "reason": str}
        """
        rename_count = 0
        dominant_pid = self._get_dominant_pid(events)

        # Skip system processes
        if dominant_pid <= 4:
            return {"triggered": False, "reason": ""}

        # Check process name against allowlist
        proc_name = get_process_name(dominant_pid)

        if proc_name in ALLOWLISTED_PROCESSES:
            logger.debug(
                f"Tripwire skipping allowlisted process: "
                f"{proc_name} (PID={dominant_pid})"
            )
            return {"triggered": False, "reason": ""}

        # Process already gone — likely a short-lived system service
        # Real ransomware stays alive during encryption
        if proc_name == "":
            logger.debug(
                f"Tripwire skipping — PID={dominant_pid} already gone "
                f"(likely short-lived system service)"
            )
            return {"triggered": False, "reason": ""}

        for event in events:
            file_lower = event.file_path.lower()
            op         = event.operation.upper()
            pid        = int(event.process_id) if event.process_id else 0

            # Skip system processes
            if pid <= 4:
                continue

            # Skip system drive paths
            if any(file_lower.startswith(p) for p in [
                "c:\\windows\\",
                "c:\\program files\\",
                "c:\\programdata\\",
                "c:\\users\\all users\\",
            ]):
                continue

            # Skip system-owned user profile paths
            if any(p in file_lower for p in SYSTEM_OWNED_PATHS):
                continue

            # VSS deletion — ransomware kills shadow copies
            if "vssadmin" in file_lower and "delete" in file_lower:
                return {
                    "triggered": True,
                    "reason":    "VSS shadow copy deletion detected"
                }

            # Boot recovery disable
            if "bcdedit" in file_lower:
                return {
                    "triggered": True,
                    "reason":    "Boot recovery modification detected"
                }

            # Ransom note filenames
            for pattern in self.config["ransom_note_patterns"]:
                if pattern.lower() in file_lower:
                    return {
                        "triggered": True,
                        "reason":    f"Ransom note detected: {pattern}"
                    }

            # Count renames of user files only
            if op == "RENAME":
                rename_count += 1

        # Rapid rename check
        threshold = self.config["rapid_rename_threshold"]
        if rename_count >= threshold:
            return {
                "triggered": True,
                "reason":    f"Rapid rename: {rename_count} files renamed in one window"
            }

        return {"triggered": False, "reason": ""}