import os
import json
import threading
import subprocess
import time
import win32file
from loguru import logger

PIPE_NAME     = r"\\.\pipe\nesrd_etw"
COLLECTOR_EXE = r"C:\Users\USER\nesrd-etw\etw_collector.exe"


class CppETWCollector:
    """
    Real-time ETW collector using C++ kernel-level collection.
    Launches etw_collector.exe and reads events via named pipe.
    Falls back to WPR collector if exe not found.
    """

    def __init__(self, config, event_callback):
        self.config         = config
        self.event_callback = event_callback
        self.running        = False
        self.process        = None
        self._pipe_thread   = None
        self._proc_thread   = None
        self.ignored_paths  = [
            p.lower() for p in config.get("ignored_paths", [])
        ]
        logger.info("CppETWCollector initialized")

    def _should_ignore(self, path):
        lower = path.lower()
        ignore_prefixes = [
            "c:\\windows",
            "c:\\program files",
            "c:\\program files (x86)",
            "c:\\programdata",
        ]
        ignore_fragments = [
            "appdata\\local\\programs\\python",
            "appdata\\local\\programs\\modules",
            "nesrd-agent\\venv",
            "nesrd-etw",
        ]
        for prefix in ignore_prefixes:
            if lower.startswith(prefix):
                return True
        for fragment in ignore_fragments:
            if fragment in lower:
                return True
        for path_prefix in self.ignored_paths:
            if lower.startswith(path_prefix):
                return True
        return False

    def _read_pipe(self):
        """Read events from named pipe and feed into pipeline."""
        from collector.etw_collector import FileEvent

        # Wait for pipe to become available
        pipe = None
        for _ in range(30):
            if not self.running:
                return
            try:
                pipe = win32file.CreateFile(
                    PIPE_NAME,
                    win32file.GENERIC_READ,
                    0, None,
                    win32file.OPEN_EXISTING,
                    0, None
                )
                break
            except Exception:
                time.sleep(0.5)

        if pipe is None:
            logger.error("Could not connect to ETW pipe after 15 seconds")
            return

        logger.info("Connected to C++ ETW pipe — real-time events flowing")
        buffer    = ""
        evt_count = 0

        try:
            while self.running:
                try:
                    _, data = win32file.ReadFile(pipe, 4096)
                    buffer += data.decode('utf-8', errors='ignore')

                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        line = line.strip()
                        if not line:
                            continue

                        try:
                            raw = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        path = raw.get("path", "")
                        op   = raw.get("op", "")
                        pid  = raw.get("pid", 0)
                        ext  = raw.get("ext", "")
                        ts   = raw.get("ts", 0)

                        if self._should_ignore(path):
                            continue

                        if op not in ["CREATE", "WRITE", "DELETE", "RENAME"]:
                            continue

                        event = FileEvent(
                            process_name   = "unknown",
                            process_id     = pid,
                            operation      = op,
                            file_path      = path,
                            file_extension = ext,
                            bytes_count    = 0,
                            timestamp_ms   = ts // 10000 if ts > 0 else 0
                        )

                        evt_count += 1
                        if evt_count % 100 == 0:
                            logger.debug(
                                f"CppETW: {evt_count} events processed"
                            )

                        self.event_callback(event)

                except Exception as e:
                    if self.running:
                        logger.error(f"Pipe read error: {e}")
                    break
        finally:
            # Always close the handle so the OS releases the pipe instance.
            # Without this, a restarted etw_collector.exe gets ERROR_PIPE_BUSY
            # (error 231) when it tries to call CreateNamedPipe again.
            try:
                win32file.CloseHandle(pipe)
            except Exception:
                pass

    def _monitor_process(self):
        """Monitor C++ collector and restart if it dies."""
        while self.running:
            if self.process and self.process.poll() is not None:
                rc = self.process.returncode
                logger.warning(
                    f"C++ ETW collector exited (rc={rc}) — restarting..."
                )
                self._launch_collector()
                # Give the new exe time to create the pipe before we connect
                time.sleep(1)
                # The old pipe reader thread has already exited (pipe broken).
                # Spawn a fresh one so it connects to the new pipe instance.
                if self.running:
                    self._pipe_thread = threading.Thread(
                        target=self._read_pipe,
                        daemon=True,
                        name="CppETWPipeReader"
                    )
                    self._pipe_thread.start()
                    logger.info("Pipe reader thread restarted after collector restart")
            time.sleep(2)

    def _drain_stdout(self, proc):
        """Forward subprocess stdout to the logger (runs in its own thread)."""
        try:
            for raw in proc.stdout:
                line = raw.decode('utf-8', errors='ignore').rstrip()
                if not line:
                    continue
                lower = line.lower()
                if any(w in lower for w in ('fail', 'error', 'already owned')):
                    logger.warning(f"[etw.exe] {line}")
                else:
                    logger.debug(f"[etw.exe] {line}")
        except Exception:
            pass

    def _launch_collector(self):
        """Launch the C++ ETW collector executable."""
        try:
            self.process = subprocess.Popen(
                [COLLECTOR_EXE],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            logger.info(
                f"C++ ETW collector launched | PID={self.process.pid}"
            )
            # Drain stdout so pipe buffer never fills and lines appear in log
            threading.Thread(
                target=self._drain_stdout,
                args=(self.process,),
                daemon=True,
                name=f"ETWStdout-{self.process.pid}"
            ).start()
        except Exception as e:
            logger.error(f"Failed to launch ETW collector: {e}")

    def start(self):
        """Start the C++ ETW collector and pipe reader."""
        if not os.path.exists(COLLECTOR_EXE):
            logger.error(
                f"etw_collector.exe not found at {COLLECTOR_EXE}"
            )
            return False

        self.running = True

        # Launch C++ collector
        self._launch_collector()
        time.sleep(1)

        # Start pipe reader thread
        self._pipe_thread = threading.Thread(
            target=self._read_pipe,
            daemon=True,
            name="CppETWPipeReader"
        )
        self._pipe_thread.start()

        # Start process monitor thread
        self._proc_thread = threading.Thread(
            target=self._monitor_process,
            daemon=True,
            name="CppETWMonitor"
        )
        self._proc_thread.start()

        logger.info(
            "CppETWCollector started — real-time kernel ETW active"
        )
        return True

    def stop(self):
        """Stop the collector."""
        self.running = False
        if self.process:
            self.process.terminate()
        logger.info("CppETWCollector stopped")