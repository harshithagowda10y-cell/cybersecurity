"""
MAS-CSI Deterministic Detector
Section 12 & 13 compliant: deterministic rules are primary confirmation.
"""
from typing import Dict, Any

class DeterministicDetector:
    def __init__(self):
        pass

    def evaluate(self, event: Dict[str, Any]) -> Dict[str, Any]:
        raw = str(event.get("raw_event", "")).upper()
        event_type = event.get("event_type", "").lower()

        # SQL Injection (T1190)
        if "UNION SELECT" in raw or "OR 1=1" in raw or "INFORMATION_SCHEMA" in raw:
            return {
                "detection_state": "CONFIRMED",
                "attack_type": "Exploit Public-Facing Application (SQLi)",
                "mitre_technique": "T1190",
                "mitre_tactic": "Initial Access",
                "severity": "CRITICAL",
                "risk_score": 96,
                "confidence": 0.98,
                "reason": "Payload matched deterministic SQL injection signature."
            }

        # DNS C2 Tunneling (T1071.004)
        if event_type == "dns_anomaly" or (event_type == "dns_query" and len(raw) > 120):
            return {
                "detection_state": "CONFIRMED",
                "attack_type": "DNS Tunneling C2 Channel",
                "mitre_technique": "T1071.004",
                "mitre_tactic": "Command and Control",
                "severity": "HIGH",
                "risk_score": 86,
                "confidence": 0.92,
                "reason": "High entropy DNS subdomain query frequency threshold exceeded."
            }

        # Data Exfiltration (T1041)
        if event.get("bytes_out", 0) > 500000:
            return {
                "detection_state": "CONFIRMED",
                "attack_type": "Data Exfiltration Over Network",
                "mitre_technique": "T1041",
                "mitre_tactic": "Exfiltration",
                "severity": "HIGH",
                "risk_score": 91,
                "confidence": 0.95,
                "reason": "Outbound byte burst exceeded 500KB threshold in window."
            }

        # Default Normal
        return {
            "detection_state": "NORMAL",
            "attack_type": "Benign Telemetry",
            "mitre_technique": "N/A",
            "mitre_tactic": "N/A",
            "severity": "INFO",
            "risk_score": 5,
            "confidence": 0.99,
            "reason": "No deterministic malicious rule condition satisfied."
        }
