import json
from datetime import datetime

alert = {
    "timestamp": datetime.now().isoformat(),
    "agent_id": "vm-win10-001",
    "decision": "ISOLATE",
    "confidence": 1.0,
    "reason": "Tripwire: Rapid rename 54 files",
    "mitre_technique": "T1486",
    "severity": "critical",
    "description": "NESRD detected ISOLATE behavior on vm-win10-001"
}

with open("/var/ossec/logs/nesrd_alerts.json", "a") as f:
    f.write(json.dumps(alert) + "\n")

print("Alert appended")