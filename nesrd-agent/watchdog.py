import os
import sys
import time
import subprocess
import ctypes
from datetime import datetime
from loguru import logger

AGENT_SCRIPT   = r"C:\Users\USER\nesrd-agent\agent.py"
PYTHON_EXE     = r"C:\Users\USER\nesrd-agent\venv\Scripts\python.exe"
LOG_FILE       = r"C:\Users\USER\nesrd-agent\logs\watchdog.log"
CHECK_INTERVAL = 5    # seconds between health checks
MAX_RESTARTS   = 10   # max restarts before giving up
RESTART_DELAY  = 3    # seconds to wait before restarting


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


class AgentWatchdog:
    def __init__(self):
        self.process       = None
        self.restart_count = 0
        self.start_time    = None
        logger.info("AgentWatchdog initialized")

    def start_agent(self):
        """Start the agent process."""
        try:
            logger.info(f"Starting agent (restart #{self.restart_count})...")
            self.process = subprocess.Popen(
                [PYTHON_EXE, AGENT_SCRIPT],
                stdout=subprocess.DEVNULL,  # prevent pipe buffer blocking on Windows
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            self.start_time = datetime.now()
            logger.info(f"Agent started | PID={self.process.pid}")
            return True
        except Exception as e:
            logger.error(f"Failed to start agent: {e}")
            return False

    def is_agent_running(self):
        """Check if agent process is still alive."""
        if self.process is None:
            return False
        return self.process.poll() is None

    def stop_agent(self):
        """Stop the agent process cleanly."""
        if self.process and self.is_agent_running():
            logger.info("Stopping agent...")
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
            logger.info("Agent stopped")

    def run(self):
        """Main watchdog loop."""
        logger.info("Watchdog running — monitoring agent health")
        logger.info(f"Agent script: {AGENT_SCRIPT}")
        logger.info(f"Check interval: {CHECK_INTERVAL}s")

        if not self.start_agent():
            logger.error("Failed to start agent on first attempt")
            sys.exit(1)

        while True:
            time.sleep(CHECK_INTERVAL)

            if not self.is_agent_running():
                exit_code = self.process.returncode if self.process else -1
                uptime    = (datetime.now() - self.start_time).seconds if self.start_time else 0

                logger.warning(
                    f"Agent died | exit_code={exit_code} | "
                    f"uptime={uptime}s | restarts={self.restart_count}"
                )

                if self.restart_count >= MAX_RESTARTS:
                    logger.critical(
                        f"Agent died {MAX_RESTARTS} times — "
                        f"possible ransomware attack or critical error. "
                        f"Manual intervention required."
                    )
                    time.sleep(60)
                    continue

                self.restart_count += 1
                logger.info(f"Waiting {RESTART_DELAY}s before restart #{self.restart_count}...")
                time.sleep(RESTART_DELAY)

                if not self.start_agent():
                    logger.error(f"Restart #{self.restart_count} failed")
                else:
                    logger.info(f"Agent restarted successfully (restart #{self.restart_count})")

            else:
                logger.debug(
                    f"Agent healthy | PID={self.process.pid} | "
                    f"uptime={(datetime.now() - self.start_time).seconds}s"
                )


def main():
    logger.add(LOG_FILE, rotation="10 MB", level="INFO")

    if not is_admin():
        logger.warning(
            "Watchdog not running as Administrator. "
            "Agent will run in simulation mode."
        )

    watchdog = AgentWatchdog()
    try:
        watchdog.run()
    except KeyboardInterrupt:
        logger.info("Watchdog stopped by user")
        watchdog.stop_agent()


if __name__ == "__main__":
    main()