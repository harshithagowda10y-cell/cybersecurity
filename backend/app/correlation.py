"""
MAS-CSI Stateful Correlator
Maintains sliding-window correlation across events.
"""
import time
import datetime
from typing import Dict, Any, List, Optional

class StatefulCorrelator:
    def __init__(self):
        self.incidents: List[Dict[str, Any]] = []
        self.auth_failures: Dict[str, List[float]] = {}
        self.port_probes: Dict[str, set] = {}

    def correlate(self, event: Dict[str, Any], detection: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        now = time.time()
        username = event.get("username", "anon")
        src_ip = event.get("source_ip", "127.0.0.1")

        # Brute Force: >= 3 failed logins within 120 seconds
        if event.get("event_type") == "login_failure":
            timestamps = self.auth_failures.setdefault(username, [])
            timestamps = [t for t in timestamps if now - t < 120]
            timestamps.append(now)
            self.auth_failures[username] = timestamps

            if len(timestamps) >= 3:
                inc_id = f"INC-BF-{int(now)}"
                incident = {
                    "incident_id": inc_id,
                    "title": f"Brute Force Authentication Spray on '{username}'",
                    "attack_type": "Brute Force (T1110)",
                    "detection_state": "CONFIRMED",
                    "severity": "HIGH",
                    "risk_score": 88,
                    "confidence": 0.94,
                    "source_ip": src_ip,
                    "actor_identity": "Source observed in telemetry (unattributed identity)",
                    "target": f"{event.get('destination_ip', '127.0.0.1')}:{event.get('destination_port', 3000)}",
                    "status": "NEW",
                    "mitre_technique": "T1110",
                    "mitre_tactic": "Credential Access",
                    "detection_reason": f"Stateful Correlation: {len(timestamps)} failed auth attempts within 120s window.",
                    "created_at": datetime.datetime.utcnow().isoformat() + "Z",
                    "correlated_event_ids": [event.get("event_id")]
                }
                self.incidents.append(incident)
                return incident

        if detection["detection_state"] == "CONFIRMED":
            inc_id = f"INC-DET-{int(now)}"
            incident = {
                "incident_id": inc_id,
                "title": f"Detected: {detection['attack_type']}",
                "attack_type": detection["attack_type"],
                "detection_state": "CONFIRMED",
                "severity": detection["severity"],
                "risk_score": detection["risk_score"],
                "confidence": detection["confidence"],
                "source_ip": src_ip,
                "actor_identity": "Source observed in telemetry (unattributed identity)",
                "target": f"{event.get('destination_ip', '127.0.0.1')}:{event.get('destination_port', 3000)}",
                "status": "NEW",
                "mitre_technique": detection["mitre_technique"],
                "mitre_tactic": detection["mitre_tactic"],
                "detection_reason": detection["reason"],
                "created_at": datetime.datetime.utcnow().isoformat() + "Z",
                "correlated_event_ids": [event.get("event_id")]
            }
            self.incidents.append(incident)
            return incident

        return None
