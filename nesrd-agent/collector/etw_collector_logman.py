import os
import re
import subprocess
import threading
import time
from datetime import datetime
from loguru import logger

ETL_PATH     = r"C:\traces\nesrd_live.etl"
CSV_PATH     = r"C:\traces\nesrd_live.csv"
SESSION_NAME = "NESRD-logman-session"
# Correct GUID for this Windows 10 VM
PROVIDER_GUID = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"
INTERVAL_SEC  = 3


class LogmanCollector:
    """
    Near real-time ETW collector using Windows logman.
    Collects kernel file I/O events every INTERVAL_SEC seconds.
    """

    def __init__(self, config, event_callback):
        self.config         = config
        self.event_callback = event_callback
        self.running        = False
        self._thread        = None
        self.ignored_paths  = [
            p.lower() for p in config.get("ignored_paths", [])
        ]
        os.makedirs(r"C:\traces", exist_ok=True)
        logger.info("LogmanCollector initialized")

    def _should_ignore(self, path):
        lower = path.lower()
        ignore_prefixes = [
            "c:\\windows\\",
            "c:\\program files\\",
            "c:\\program files (x86)\\",
            "c:\\programdata\\",
        ]
        ignore_fragments = [
            "appdata\\local\\programs\\python",
            "appdata\\local\\temp",
            "nesrd-agent\\venv",
            "nesrd-etw",
            "pagefile.sys",
            "vmware",
        ]
        for prefix in ignore_prefixes:
            if lower.startswith(prefix):
                return True
        for fragment in ignore_fragments:
            if fragment in lower:
                return True
        return False

    def _stop_existing_session(self):
        subprocess.run(
            ["logman", "stop", SESSION_NAME, "-ets"],
            capture_output=True
        )
        subprocess.run(
            ["logman", "delete", SESSION_NAME, "-ets"],
            capture_output=True
        )

    def _start_logman(self):
        """Start logman ETW session."""
        self._stop_existing_session()

        # Remove old ETL file
        if os.path.exists(ETL_PATH):
            try:
                os.remove(ETL_PATH)
            except:
                pass

        result = subprocess.run([
            "logman", "start", SESSION_NAME,
            "-p", PROVIDER_GUID, "0xFFFFFFFFFFFFFFFF", "0xff",
            "-o", ETL_PATH,
            "-ets"
        ], capture_output=True, text=True)

        if result.returncode != 0:
            logger.error(f"logman start failed: {result.stderr}")
            return False

        logger.info("logman ETW session started")
        return True

    def _stop_logman(self):
        subprocess.run(
            ["logman", "stop", SESSION_NAME, "-ets"],
            capture_output=True
        )

    def _parse_csv(self, csv_path):
        """Parse tracerpt CSV into FileEvent objects."""
        from collector.etw_collector import FileEvent

        events = []
        op_map = {
            "10": "RENAME",
            "11": "RENAME",
            "12": "CREATE",
            "13": "READ",
            "14": "WRITE",
            "15": "SET_INFO",
            "16": "DELETE",
            "17": "RENAME",
            "30": "DELETE",
            "32": "WRITE",
            "34": "WRITE",
        }

        skip_ops = {"23", "24", "22"}  # CLEANUP, CLOSE, QUERY_INFO

        try:
            with open(csv_path, 'r',
                      encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"CSV read error: {e}")
            return events

        for line in lines:
            if 'Kernel-File' not in line and \
               'Kernel Trace' not in line:
                continue

            parts = line.split(',')
            if len(parts) < 20:
                continue

            try:
                task   = parts[7].strip()
                pid_hex = parts[9].strip()
                ts      = parts[16].strip()
                user_data = ','.join(parts[20:]).strip()

                if task in skip_ops:
                    continue

                op = op_map.get(task, None)
                if not op:
                    continue

                # Extract file path
                path_match = re.search(
                    r'"((?:\\Device\\[^"]+)|(?:[A-Za-z]:\\[^"]+))"',
                    user_data
                )
                if not path_match:
                    continue

                raw_path = path_match.group(1)

                # Convert device path
                if raw_path.startswith('\\Device'):
                    pos = raw_path.find('HarddiskVolume')
                    if pos != -1:
                        slash = raw_path.find('\\', pos)
                        if slash != -1:
                            raw_path = 'C:' + raw_path[slash:]
                        else:
                            continue
                    else:
                        continue

                if self._should_ignore(raw_path):
                    continue

                _, ext = os.path.splitext(raw_path)

                try:
                    pid = int(pid_hex, 16)
                except:
                    pid = 0

                try:
                    ts_ms = int(ts) // 10000
                except:
                    ts_ms = int(datetime.now().timestamp() * 1000)

                event = FileEvent(
                    process_name   = "unknown",
                    process_id     = pid,
                    operation      = op,
                    file_path      = raw_path,
                    file_extension = ext.lower(),
                    bytes_count    = 0,
                    timestamp_ms   = ts_ms
                )
                events.append(event)

            except Exception:
                continue

        return events

    def _collection_loop(self):
        logger.info("Logman collection loop starting")

        if not self._start_logman():
            logger.error("Failed to start logman session")
            return

        while self.running:
            time.sleep(INTERVAL_SEC)

            if not self.running:
                break

            # Stop current session
            self._stop_logman()

            # Convert ETL to CSV
            if not os.path.exists(ETL_PATH):
                logger.warning("ETL file not found — restarting session")
                self._start_logman()
                continue

            try:
                subprocess.run([
                    "tracerpt", ETL_PATH,
                    "-o", CSV_PATH,
                    "-of", "CSV", "-y"
                ], capture_output=True, timeout=30)
            except Exception as e:
                logger.error(f"tracerpt error: {e}")
                self._start_logman()
                continue

            # Parse and feed events
            events = self._parse_csv(CSV_PATH)
            logger.info(f"Parsed {len(events)} real ETW events")

            for event in events:
                if self.running:
                    self.event_callback(event)

            # Cleanup and restart
            for f in [ETL_PATH, CSV_PATH]:
                try:
                    if os.path.exists(f):
                        os.remove(f)
                except:
                    pass

            self._start_logman()

    def start(self):
        self.running = True
        self._thread = threading.Thread(
            target=self._collection_loop,
            daemon=True,
            name="LogmanCollector"
        )
        self._thread.start()
        logger.info(
            "LogmanCollector started — near real-time ETW collection active"
        )

    def stop(self):
        self.running = False
        self._stop_logman()
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("LogmanCollector stopped")