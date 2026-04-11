import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import grpc
import yaml
from concurrent import futures
from loguru import logger
from datetime import datetime

import api.nesrd_pb2 as pb2
import api.nesrd_pb2_grpc as pb2_grpc
from core.fusion.fusion_engine import FusionEngine
from core.fusion.tripwires import TripwireEngine
from api.alert_service import AlertService


def load_config():
    config_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "config", "detection_config.yaml"
    )
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def get_dominant_pid(events):
    """
    Find the PID responsible for most file I/O in this window.
    This is the process most likely to be ransomware.
    """
    pid_counts = {}
    for event in events:
        try:
            pid = int(event.process_id)
            if pid > 4:  # skip system processes
                pid_counts[pid] = pid_counts.get(pid, 0) + 1
        except (ValueError, TypeError):
            continue

    if not pid_counts:
        return 0

    return max(pid_counts, key=pid_counts.get)


class NESRDServicer(pb2_grpc.NESRDServiceServicer):

    def __init__(self, config):
        self.config           = config
        self.fusion           = FusionEngine(config)
        self.tripwires        = TripwireEngine(config)
        self.alert_service    = AlertService(config)
        self.connected_agents = {}
        logger.info("NESRD Manager initialized")
        logger.info(
            f"Listening for agents on "
            f"{config['manager']['host']}:{config['manager']['port']}"
        )

    def StreamEvents(self, request_iterator, context):
        peer = context.peer()
        logger.info(f"Agent connected: {peer}")

        try:
            for window in request_iterator:
                agent_id   = window.agent_id
                session_id = window.session_id
                events     = window.events

                self.connected_agents[agent_id] = {
                    "ip":        window.agent_ip,
                    "last_seen": datetime.now().isoformat(),
                    "session":   session_id
                }

                logger.info(
                    f"[{agent_id}] Received window | "
                    f"session={session_id} | "
                    f"events={len(events)}"
                )

                # Get dominant PID for this window
                dominant_pid = get_dominant_pid(events)

                # Step 1 — Check hard tripwires first
                tripwire_result = self.tripwires.check(events)
                if tripwire_result["triggered"]:
                    logger.warning(
                        f"[{agent_id}] TRIPWIRE triggered: "
                        f"{tripwire_result['reason']} | "
                        f"PID={dominant_pid}"
                    )
                    self.alert_service.send_alert(
                        agent_id   = agent_id,
                        session_id = session_id,
                        decision   = "ISOLATE",
                        confidence = 1.0,
                        reason     = f"Tripwire: {tripwire_result['reason']}",
                        mitre      = "T1486"
                    )
                    yield pb2.DetectionResult(
                        session_id      = session_id,
                        confidence      = 1.0,
                        decision        = "ISOLATE",
                        mitre_technique = "T1486",
                        reason          = f"Tripwire: {tripwire_result['reason']}",
                        timestamp_ms    = int(datetime.now().timestamp() * 1000),
                        process_id      = dominant_pid
                    )
                    continue

                # Step 2 — Run fusion engine
                decision, confidence, reason = self.fusion.decide(events)

                logger.info(
                    f"[{agent_id}] Decision={decision} | "
                    f"Confidence={confidence:.3f} | "
                    f"Reason={reason} | "
                    f"PID={dominant_pid}"
                )

                # Step 3 — Send alert if not LOG
                if decision != "LOG":
                    self.alert_service.send_alert(
                        agent_id   = agent_id,
                        session_id = session_id,
                        decision   = decision,
                        confidence = confidence,
                        reason     = reason,
                        mitre      = "T1486"
                    )

                # Step 4 — Yield result back to agent
                yield pb2.DetectionResult(
                    session_id      = session_id,
                    confidence      = confidence,
                    decision        = decision,
                    mitre_technique = "T1486" if decision != "LOG" else "",
                    reason          = reason,
                    timestamp_ms    = int(datetime.now().timestamp() * 1000),
                    process_id      = dominant_pid
                )

        except grpc.RpcError as e:
            logger.error(f"gRPC error from {peer}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error from {peer}: {e}")
        finally:
            logger.info(f"Agent disconnected: {peer}")

    def SendHeartbeat(self, request, context):
        agent_id = request.agent_id

        if agent_id in self.connected_agents:
            self.connected_agents[agent_id]["last_seen"] = \
                datetime.now().isoformat()

        logger.debug(f"Heartbeat from {agent_id} at {request.agent_ip}")

        return pb2.HeartbeatAck(
            acknowledged = True,
            timestamp_ms = int(datetime.now().timestamp() * 1000)
        )


def serve():
    config = load_config()

    host = config["manager"]["host"]
    port = config["manager"]["port"]

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

    pb2_grpc.add_NESRDServiceServicer_to_server(
        NESRDServicer(config), server
    )

    listen_addr = f"0.0.0.0:{port}"
    server.add_insecure_port(listen_addr)
    server.start()

    logger.info(f"NESRD Manager running on {listen_addr}")
    logger.info(f"Agents should connect to {host}:{port}")
    logger.info("Waiting for agent connections...")

    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("Shutting down manager...")
        server.stop(0)


if __name__ == "__main__":
    logger.add(
        "logs/nesrd.log",
        rotation="50 MB",
        level="INFO"
    )
    serve()