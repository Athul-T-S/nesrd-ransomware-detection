import os
import sys
import time
import yaml
import ctypes
import subprocess
from loguru import logger
from parser.sliding_window import SlidingWindow
from tokenizer.behavior_tokenizer import BehaviorTokenizer
from grpc_client.nesrd_client import NESRDClient


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def load_config():
    with open("config/agent_config.yaml", "r") as f:
        return yaml.safe_load(f)


def cleanup_etw_session():
    """
    Kill any orphaned NESRD ETW sessions left over from a previous run.
    Safe to call even when no session exists.
    """
    try:
        # Clean up logman session
        result = subprocess.run(
            ["logman", "stop", "NESRD-logman-session", "-ets"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            logger.info("Cleaned up orphaned logman session before launch")

        # Clean up C++ ETW session if present
        subprocess.run(
            ["logman", "stop", "NESRD-ETW-Session", "-ets"],
            capture_output=True, text=True
        )
    except Exception as e:
        logger.warning(f"ETW session pre-cleanup failed (non-critical): {e}")


def main():
    logger.add("logs/agent.log", rotation="50 MB", level="INFO")
    logger.info("NESRD Agent starting...")

    config    = load_config()
    tokenizer = BehaviorTokenizer()
    client    = NESRDClient(config)

    if not client.start():
        logger.error("Failed to connect to manager. Is the manager running?")
        sys.exit(1)

    def on_window(pid, events):
        logger.info(f"Window ready | pid={pid} | events={len(events)}")
        client.send_window(pid, events, tokenizer)

    window = SlidingWindow(config, on_window)

    def on_event(event):
        window.add_event(event)

    def on_decision(response):
        logger.info(
            f"Manager decision | "
            f"decision={response.decision} | "
            f"confidence={response.confidence:.3f} | "
            f"reason={response.reason}"
        )

    client.decision_callback = on_decision

    # -- Collector selection -------------------------------------------
    collector = None

    if is_admin():
        cleanup_etw_session()

        # Primary — logman real-time ETW collector
        logger.info(
            "Running as Administrator — using logman ETW collector"
        )
        try:
            from collector.etw_collector_logman import LogmanCollector
            collector = LogmanCollector(config, on_event)
            collector.start()
        except Exception as e:
            logger.warning(
                f"Logman collector error: {e} — falling back to WPR"
            )
            collector = None

        # Fallback — WPR batch collector
        if collector is None:
            logger.info(
                "Falling back to WPR ETW collector"
            )
            from collector.etw_collector_wpr import WPRCollector
            collector = WPRCollector(config, on_event)
            collector.start()

    else:
        logger.warning("Not Administrator — using simulation mode")
        from collector.etw_collector import ETWCollector
        collector = ETWCollector(config, on_event)
        collector.start()

    logger.info("Agent running. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping agent...")
        collector.stop()
        client.stop()
        logger.info("Agent stopped.")


if __name__ == "__main__":
    main()