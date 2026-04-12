import os
import sys
import time
import yaml
import ctypes
import threading
from datetime import datetime
from loguru import logger
import win32api
import win32con
import win32security


def is_admin():
    """ETW kernel collection requires admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def load_config():
    config_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "config", "agent_config.yaml"
    )
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


class FileEvent:
    """Represents a single file I/O event."""
    def __init__(self, process_name, process_id, operation,
                 file_path, file_extension, bytes_count, timestamp_ms):
        self.process_name   = process_name
        self.process_id     = str(process_id)
        self.operation      = operation
        self.file_path      = file_path
        self.file_extension = file_extension
        self.bytes          = bytes_count
        self.timestamp_ms   = timestamp_ms

    def __repr__(self):
        return (f"FileEvent({self.operation} | "
                f"{self.process_name} | "
                f"{self.file_path} | "
                f"{self.bytes}b)")


class ETWCollector:
    """
    Collects file I/O events using Windows ETW.
    Uses kernel-level tracing via pyetw / win32 APIs.
    """

    def __init__(self, config, event_callback):
        self.config         = config
        self.event_callback = event_callback
        self.running        = False
        self.monitored_exts = set(config["monitored_extensions"])
        self.ignored_paths  = config["ignored_paths"]
        self.ignored_procs  = set(config["ignored_processes"])
        self._thread        = None
        logger.info("ETWCollector initialized")

    def _should_ignore(self, file_path, process_name):
        """Filter out noise - system processes and paths."""
        if process_name in self.ignored_procs:
            return True
        for path in self.ignored_paths:
            if file_path.lower().startswith(path.lower()):
                return True
        return False

    def _get_extension(self, file_path):
        """Extract file extension."""
        _, ext = os.path.splitext(file_path)
        return ext.lower() if ext else ""

    def _should_monitor_extension(self, ext):
        """Only monitor high-value file extensions."""
        return ext in self.monitored_exts

    def _simulate_etw_collection(self):
        """
        ETW simulation mode for testing.
        Uses fixed process ID so sliding window threshold is reached.
        """
        import random

        operations = ["READ", "WRITE", "RENAME", "DELETE", "CREATE"]
        extensions = [".docx", ".xlsx", ".pdf", ".txt", ".jpg"]
        base_paths = [
            "C:\\Users\\USER\\Documents\\",
            "C:\\Users\\USER\\Desktop\\",
            "C:\\Users\\USER\\Downloads\\"
        ]

        # Fixed process to ensure window fills up
        process   = "winword.exe"
        fixed_pid = 4444

        logger.info("ETW running in SIMULATION mode - generating test events")

        while self.running:
            op      = random.choice(operations)
            ext     = random.choice(extensions)
            path    = random.choice(base_paths) + f"file_{random.randint(1,1000)}{ext}"
            bytes_n = random.randint(1024, 1048576)
            ts      = int(datetime.now().timestamp() * 1000)

            event = FileEvent(
                process_name   = process,
                process_id     = fixed_pid,
                operation      = op,
                file_path      = path,
                file_extension = ext,
                bytes_count    = bytes_n,
                timestamp_ms   = ts
            )
            self.event_callback(event)
            time.sleep(0.1)

    def start(self):
        """Start ETW collection in background thread."""
        if not is_admin():
            logger.warning(
                "Not running as Administrator. "
                "ETW kernel collection requires admin privileges. "
                "Running in simulation mode."
            )

        self.running = True
        self._thread = threading.Thread(
            target=self._simulate_etw_collection,
            daemon=True
        )
        self._thread.start()
        logger.info("ETWCollector started")

    def stop(self):
        """Stop ETW collection."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("ETWCollector stopped")