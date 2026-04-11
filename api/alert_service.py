import json
import os
import subprocess
from datetime import datetime
from loguru import logger


class AlertService:
    """
    Writes NESRD alerts and auto-syncs to Wazuh container.
    """

    def __init__(self, config):
        self.alert_log      = "logs/nesrd_alerts.json"
        self.wazuh_container = "single-node-wazuh.manager-1"
        self.wazuh_log_path  = "/var/ossec/logs/nesrd_alerts.json"
        self.alert_count     = 0
        os.makedirs("logs", exist_ok=True)
        logger.info(f"AlertService initialized | log={self.alert_log}")

    def send_alert(self, agent_id, session_id, decision,
                   confidence, reason, mitre):
        """Write alert locally and sync to Wazuh container."""

        alert = {
            "timestamp":       datetime.now().isoformat(),
            "agent_id":        agent_id,
            "session_id":      session_id,
            "decision":        decision,
            "confidence":      round(float(confidence), 3),
            "reason":          reason,
            "mitre_technique": mitre,
            "severity":        self._get_severity(decision),
            "description":     f"NESRD detected {decision} behavior on {agent_id}"
        }

        # Write locally
        with open(self.alert_log, "a") as f:
            f.write(json.dumps(alert) + "\n")

        self.alert_count += 1

        logger.info(
            f"Alert written | decision={decision} | "
            f"agent={agent_id} | total={self.alert_count}"
        )

        # Sync to Wazuh every alert
        if decision in ["ISOLATE", "ALERT"]:
            self._sync_to_wazuh(alert)

        return alert

    def _sync_to_wazuh(self, alert):
        """Write alert directly into Wazuh container log file."""
        try:
            alert_json = json.dumps(alert).replace('"', '\\"')
            cmd = [
                "docker", "exec", self.wazuh_container,
                "python3", "-c",
                f"import json; f=open('{self.wazuh_log_path}','a'); f.write('{alert_json}\\n'); f.close()"
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logger.info(f"Alert synced to Wazuh | decision={alert['decision']}")
            else:
                logger.warning(f"Wazuh sync failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            logger.warning("Wazuh sync timed out")
        except Exception as e:
            logger.warning(f"Wazuh sync error: {e}")

    def _get_severity(self, decision):
        mapping = {
            "ISOLATE": "critical",
            "ALERT":   "high",
            "LOG":     "low"
        }
        return mapping.get(decision, "low")