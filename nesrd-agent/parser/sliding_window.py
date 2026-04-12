import threading
from collections import deque
from loguru import logger


class SlidingWindow:
    """
    Maintains a rolling buffer of FileEvents per process.
    Emits a window snapshot every `step` new events.
    
    This is what controls detection granularity:
    - window size 256 = look at last 256 events
    - step 50 = check for ransomware every 50 new events
    """

    def __init__(self, config, window_callback):
        self.window_size     = config["window"]["size"]
        self.step            = config["window"]["step"]
        self.window_callback = window_callback

        # Separate buffer per process_id
        self._buffers     = {}
        self._step_counts = {}
        self._lock        = threading.Lock()

        logger.info(
            f"SlidingWindow initialized | "
            f"size={self.window_size} | "
            f"step={self.step}"
        )

    def add_event(self, event):
        """
        Add a single FileEvent to the appropriate process buffer.
        Emits a window when step threshold is reached.
        """
        pid = event.process_id

        with self._lock:
            # Initialize buffer for new process
            if pid not in self._buffers:
                self._buffers[pid]     = deque(maxlen=self.window_size)
                self._step_counts[pid] = 0

            # Add event to buffer
            self._buffers[pid].append(event)
            self._step_counts[pid] += 1

            # Emit window every `step` events
            if self._step_counts[pid] >= self.step:
                self._step_counts[pid] = 0
                window_events = list(self._buffers[pid])
                self.window_callback(pid, window_events)
                logger.debug(
                    f"Window emitted for pid={pid} | "
                    f"events={len(window_events)}"
                )

    def get_buffer(self, pid):
        """Get current buffer for a process."""
        with self._lock:
            if pid in self._buffers:
                return list(self._buffers[pid])
            return []

    def clear(self):
        """Clear all buffers."""
        with self._lock:
            self._buffers.clear()
            self._step_counts.clear()
        logger.info("SlidingWindow buffers cleared")