import os
import sys
import grpc
import threading
import queue
import time
import yaml
from datetime import datetime
from loguru import logger

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nesrd_pb2 as pb2
import nesrd_pb2_grpc as pb2_grpc


def load_config():
    config_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "config", "agent_config.yaml"
    )
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


class NESRDClient:
    """
    gRPC client that streams event windows to the manager
    and receives detection decisions back.
    """

    def __init__(self, config):
        self.config     = config
        self.host       = config["manager"]["host"]
        self.port       = config["manager"]["port"]
        self.agent_id   = config["agent"]["id"]
        self.agent_ip   = config["agent"]["ip"]

        self.channel    = None
        self.stub       = None
        self.connected  = False

        self._send_queue    = queue.Queue()
        self._send_thread   = None
        self._hb_thread     = None
        self._running       = False
        self._isolated      = False

        self.decision_callback = None

        logger.info(f"NESRDClient initialized | target={self.host}:{self.port}")

    def connect(self):
        """Establish connection to manager."""
        try:
            target = f"{self.host}:{self.port}"
            self.channel = grpc.insecure_channel(target)
            self.stub    = pb2_grpc.NESRDServiceStub(self.channel)
            self.connected = True
            logger.info(f"Connected to manager at {target}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to manager: {e}")
            return False

    def _window_generator(self):
        """Yield EventWindow messages from queue."""
        while self._running:
            try:
                window_data = self._send_queue.get(timeout=1.0)
                yield window_data
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Window generator error: {e}")
                break

    def _stream_worker(self):
        """Maintains bidirectional stream."""
        while self._running:
            try:
                logger.info("Starting event stream to manager...")

                responses = self.stub.StreamEvents(self._window_generator())

                for response in responses:
                    if not self._running:
                        break

                    logger.info(
                        f"Decision received | "
                        f"decision={response.decision} | "
                        f"confidence={response.confidence:.3f} | "
                        f"reason={response.reason}"
                    )

                    self._handle_decision(response)

                    if self.decision_callback:
                        self.decision_callback(response)

            except grpc.RpcError as e:
                logger.error(f"Stream error: {e.code()} - {e.details()}")
                if self._running:
                    logger.info("Reconnecting in 5 seconds...")
                    time.sleep(5)

            except Exception as e:
                logger.error(f"Unexpected stream error: {e}")
                if self._running:
                    time.sleep(5)

    def _handle_decision(self, response):
        """Act on decisions received from manager."""
        decision   = response.decision
        process_id = response.process_id  # PID from manager

        if decision == "ISOLATE":
            logger.critical(
                f"ISOLATE order received | "
                f"confidence={response.confidence:.3f} | "
                f"reason={response.reason} | "
                f"mitre={response.mitre_technique} | "
                f"pid={process_id}"
            )

            if not self._isolated:
                # Step 1 — Kill the offending process first
                if process_id and process_id > 4:
                    self._kill_process(process_id)

                # Step 2 — Network isolation
                self._isolate_endpoint()
            else:
                logger.warning(
                    "Already isolated — skipping duplicate ISOLATE order"
                )

        elif decision == "ALERT":
            logger.warning(
                f"ALERT | "
                f"confidence={response.confidence:.3f} | "
                f"reason={response.reason}"
            )

        else:
            logger.debug(f"LOG | confidence={response.confidence:.3f}")

    def _kill_process(self, pid):
        """
        Kill the ransomware process by PID.
        Called before network isolation to stop encryption immediately.
        """
        import subprocess
        import ctypes

        if not ctypes.windll.shell32.IsUserAnAdmin():
            logger.error("Cannot kill process — not running as Administrator")
            return

        logger.critical(f"KILLING RANSOMWARE PROCESS | PID={pid}")

        try:
            result = subprocess.run(
                ["taskkill", "/PID", str(pid), "/F", "/T"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                logger.critical(
                    f"Process killed successfully | PID={pid}"
                )
            else:
                logger.error(
                    f"Failed to kill process | PID={pid} | "
                    f"Error: {result.stderr.strip()}"
                )

        except subprocess.TimeoutExpired:
            logger.error(f"Process kill timed out | PID={pid}")
        except Exception as e:
            logger.error(f"Process kill error: {e}")

    def _cleanup_existing_rules(self):
        """Remove any leftover firewall rules from previous isolation runs."""
        import subprocess

        rule_names = [
            "NESRD-ALLOW-MANAGER-OUT",
            "NESRD-ALLOW-MANAGER-IN",
            "NESRD-BLOCK-OUTBOUND",
            "NESRD-BLOCK-INBOUND",
        ]

        for rule_name in rule_names:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete",
                 "rule", f"name={rule_name}"],
                capture_output=True,
                text=True
            )

    def _isolate_endpoint(self):
        """
        Block all network traffic except to the manager.
        Uses Windows Firewall via netsh commands.
        Requires Administrator privileges.
        ALLOW rules must be added before BLOCK rules.
        """
        import subprocess
        import ctypes

        if not ctypes.windll.shell32.IsUserAnAdmin():
            logger.error("Cannot isolate — not running as Administrator")
            return

        manager_ip = self.host

        logger.critical("INITIATING ENDPOINT ISOLATION")
        logger.critical(
            f"Keeping connection to manager: {manager_ip}:{self.port}"
        )

        self._cleanup_existing_rules()

        rules = [
            # ALLOW manager traffic first
            ["netsh", "advfirewall", "firewall", "add", "rule",
             "name=NESRD-ALLOW-MANAGER-OUT",
             "dir=out", "action=allow", "protocol=tcp",
             f"remoteip={manager_ip}", f"remoteport={self.port}"],

            ["netsh", "advfirewall", "firewall", "add", "rule",
             "name=NESRD-ALLOW-MANAGER-IN",
             "dir=in", "action=allow", "protocol=tcp",
             f"remoteip={manager_ip}"],

            # BLOCK everything else after
            ["netsh", "advfirewall", "firewall", "add", "rule",
             "name=NESRD-BLOCK-OUTBOUND",
             "dir=out", "action=block", "protocol=any"],

            ["netsh", "advfirewall", "firewall", "add", "rule",
             "name=NESRD-BLOCK-INBOUND",
             "dir=in", "action=block", "protocol=any"],
        ]

        success_count = 0

        for rule in rules:
            try:
                result = subprocess.run(
                    rule,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                rule_name = next(
                    (r.split("=")[1] for r in rule if r.startswith("name=")),
                    "unknown"
                )
                if result.returncode == 0:
                    success_count += 1
                    logger.info(f"Firewall rule applied: {rule_name}")
                else:
                    logger.error(
                        f"Rule failed: {rule_name} | "
                        f"{result.stderr.strip()}"
                    )
            except subprocess.TimeoutExpired:
                rule_name = next(
                    (r.split("=")[1] for r in rule if r.startswith("name=")),
                    "unknown"
                )
                logger.error(f"Rule timed out: {rule_name}")
            except Exception as e:
                logger.error(f"Failed to apply rule: {e}")

        if success_count == len(rules):
            self._isolated = True
            logger.critical("ENDPOINT ISOLATED SUCCESSFULLY")
            logger.critical(
                "All traffic blocked except manager connection"
            )
        else:
            logger.error(
                f"Partial isolation: {success_count}/{len(rules)} "
                f"rules applied"
            )

    def _heartbeat_worker(self):
        """Send heartbeat periodically."""
        interval = self.config["agent"]["heartbeat_interval_sec"]

        while self._running:
            try:
                hb = pb2.Heartbeat(
                    agent_id     = self.agent_id,
                    agent_ip     = self.agent_ip,
                    timestamp_ms = int(datetime.now().timestamp() * 1000)
                )
                ack = self.stub.SendHeartbeat(hb)
                logger.debug(f"Heartbeat acknowledged: {ack.acknowledged}")
            except Exception as e:
                logger.warning(f"Heartbeat failed: {e}")

            time.sleep(interval)

    def send_window(self, pid, events, tokenizer):
        """Queue event window for sending."""
        try:
            proto_events = []

            for event in events:
                proto_events.append(
                    pb2.FileEvent(
                        process_name   = event.process_name,
                        process_id     = str(event.process_id),
                        operation      = event.operation,
                        file_path      = event.file_path,
                        file_extension = event.file_extension,
                        bytes          = event.bytes,
                        timestamp_ms   = event.timestamp_ms
                    )
                )

            window = pb2.EventWindow(
                agent_id   = self.agent_id,
                session_id = f"{self.agent_id}-{pid}-{int(time.time())}",
                agent_ip   = self.agent_ip,
                events     = proto_events
            )

            self._send_queue.put(window)
            logger.debug(f"Window queued | pid={pid} | events={len(events)}")

        except Exception as e:
            logger.error(f"Failed to queue window: {e}")

    def start(self):
        """Start client."""
        if not self.connect():
            logger.error("Cannot start - connection failed")
            return False

        self._running = True

        self._send_thread = threading.Thread(
            target=self._stream_worker,
            daemon=True,
            name="StreamWorker"
        )
        self._send_thread.start()

        self._hb_thread = threading.Thread(
            target=self._heartbeat_worker,
            daemon=True,
            name="HeartbeatWorker"
        )
        self._hb_thread.start()

        logger.info("NESRDClient started")
        return True

    def stop(self):
        """Stop client."""
        self._running = False
        if self.channel:
            self.channel.close()
        logger.info("NESRDClient stopped")