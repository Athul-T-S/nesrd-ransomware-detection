import os
import re
import subprocess
import threading
import time
from datetime import datetime
from loguru import logger


class WPRCollector:
    """
    Real ETW collector using Windows Performance Recorder (WPR).
    Collects kernel file I/O events and feeds them into the pipeline.
    Runs continuously - starts WPR, parses events, feeds pipeline.
    """

    # WPR profile path
    PROFILE_PATH = r"C:\traces\fileio.wprp"
    ETL_PATH     = r"C:\traces\live_trace.etl"
    CSV_PATH     = r"C:\traces\live_trace.csv"

    # Operation mapping for Microsoft-Windows-Kernel-File
    OP_MAP = {
        "10": "CREATE",
        "11": "CLEANUP",
        "12": "CLOSE",
        "13": "READ",
        "14": "WRITE",
        "15": "SET_INFO",
        "16": "DELETE",
        "17": "RENAME",
        "18": "DIR_ENUM",
        "19": "FLUSH",
        "20": "QUERY_INFO",
    }

    # Map task number to operation for Kernel-File provider
    TASK_MAP = {
        "10": "CREATE",
        "11": "CLOSE",
        "12": "READ",
        "13": "WRITE",
        "14": "SET_INFO",
        "15": "DELETE",
        "16": "RENAME",
        "17": "DIR_ENUM",
        "18": "FLUSH",
        "19": "QUERY_INFO",
        "20": "FSControl",
    }

    def __init__(self, config, event_callback):
        self.config         = config
        self.event_callback = event_callback
        self.running        = False
        self.monitored_exts = set(config["monitored_extensions"])
        self.ignored_paths  = config["ignored_paths"]
        self._thread        = None
        logger.info("WPRCollector initialized")

        # Create traces directory
        os.makedirs(r"C:\traces", exist_ok=True)

    def _should_ignore(self, file_path):
        for path in self.ignored_paths:
            if file_path.lower().startswith(path.lower()):
                return True
        return False

    def _get_operation(self, task, opcode):
        """Determine operation type from task and opcode fields."""
        op = self.TASK_MAP.get(task.strip(), None)
        if op:
            return op
        op = self.OP_MAP.get(opcode.strip(), None)
        if op:
            return op
        return "UNKNOWN"

    def _parse_csv(self, csv_path):
        """Parse tracerpt CSV into FileEvent objects."""
        from collector.etw_collector import FileEvent

        events = []

        try:
            with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"Error reading CSV: {e}")
            return events

        for line in lines:
            if 'Microsoft-Windows-Kernel-File' not in line:
                continue

            parts = line.split(',')
            if len(parts) < 20:
                continue

            try:
                task      = parts[7].strip() if len(parts) > 7 else "0"
                opcode    = parts[6].strip() if len(parts) > 6 else "0"
                pid_hex   = parts[9].strip() if len(parts) > 9 else "0"
                timestamp = parts[16].strip() if len(parts) > 16 else "0"
                user_data = ','.join(parts[20:]).strip() if len(parts) > 20 else ""

                # Extract file path from user data
                path_match = re.search(r'"(\\Device\\[^"]+)"', user_data)
                if not path_match:
                    continue

                raw_path  = path_match.group(1)
                file_path = raw_path.replace(
                    r'\Device\HarddiskVolume3', 'C:'
                ).replace('\\', '\\')

                if self._should_ignore(file_path):
                    continue

                # Get extension
                _, ext = os.path.splitext(file_path)
                ext = ext.lower()

                # Get operation
                operation = self._get_operation(task, opcode)
                if operation in ["UNKNOWN", "CLEANUP", "CLOSE",
                                  "DIR_ENUM", "FLUSH", "QUERY_INFO"]:
                    continue

                # Convert PID
                try:
                    pid = int(pid_hex, 16)
                except:
                    pid = 0

                # Convert timestamp
                try:
                    ts_ms = int(timestamp) // 10000
                except:
                    ts_ms = int(datetime.now().timestamp() * 1000)

                event = FileEvent(
                    process_name   = "unknown",
                    process_id     = pid,
                    operation      = operation,
                    file_path      = file_path,
                    file_extension = ext,
                    bytes_count    = 0,
                    timestamp_ms   = ts_ms
                )
                events.append(event)

            except Exception as e:
                continue

        return events

    def _collection_loop(self):
        """
        Main collection loop:
        1. Start WPR recording
        2. Wait for interval
        3. Stop and parse
        4. Feed events to pipeline
        5. Repeat
        """
        interval_sec = 10  # collect every 10 seconds

        logger.info("WPR collection loop starting")

        while self.running:
            try:
                # Start WPR
                logger.info("Starting WPR recording...")
                start_result = subprocess.run(
                    ["wpr", "-start", f"{self.PROFILE_PATH}!FileIO", "-filemode"],
                    capture_output=True, text=True, timeout=10
                )

                if start_result.returncode != 0:
                    logger.warning(f"WPR start warning: {start_result.stderr}")

                # Wait for events to accumulate
                time.sleep(interval_sec)

                if not self.running:
                    break

                # Stop WPR
                logger.info("Stopping WPR recording...")
                stop_result = subprocess.run(
                    ["wpr", "-stop", self.ETL_PATH],
                    capture_output=True, text=True, timeout=30
                )

                if stop_result.returncode != 0:
                    logger.warning(f"WPR stop warning: {stop_result.stderr}")
                    continue

                # Convert to CSV
                convert_result = subprocess.run(
                    ["tracerpt", self.ETL_PATH, "-o", self.CSV_PATH,
                     "-of", "CSV", "-y"],
                    capture_output=True, text=True, timeout=30
                )

                if convert_result.returncode != 0:
                    logger.warning(f"tracerpt warning: {convert_result.stderr}")
                    continue

                # Parse and feed events
                events = self._parse_csv(self.CSV_PATH)
                logger.info(f"Parsed {len(events)} real ETW events")

                for event in events:
                    if self.running:
                        self.event_callback(event)

                # Clean up
                for f in [self.ETL_PATH, self.CSV_PATH]:
                    if os.path.exists(f):
                        os.remove(f)

            except subprocess.TimeoutExpired:
                logger.warning("WPR operation timed out")
                subprocess.run(["wpr", "-cancel"],
                               capture_output=True, timeout=5)
            except Exception as e:
                logger.error(f"Collection loop error: {e}")
                time.sleep(5)

    def start(self):
        """Start real ETW collection."""
        self.running = True
        self._thread = threading.Thread(
            target=self._collection_loop,
            daemon=True,
            name="WPRCollector"
        )
        self._thread.start()
        logger.info("WPRCollector started — real kernel ETW collection active")

    def stop(self):
        """Stop collection."""
        self.running = False
        subprocess.run(["wpr", "-cancel"],
                       capture_output=True, timeout=5)
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("WPRCollector stopped")