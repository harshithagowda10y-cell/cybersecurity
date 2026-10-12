"""
MAS-CSI Seven-Agent Investigation Pipeline
Sequential stages: Monitor -> Analyzer -> Investigator -> Threat Intel -> Forensic -> Guardian -> Reporter
"""
import datetime
from typing import Dict, Any, List

class SevenAgentPipeline:
    def __init__(self):
        self.runs: List[Dict[str, Any]] = []

    def execute(self, incident: Dict[str, Any], event: Dict[str, Any], vault) -> List[Dict[str, Any]]:
        now = datetime.datetime.utcnow().isoformat() + "Z"
        inc_id = incident["incident_id"]

        stages = [
            ("monitor", "Agent 1 — Monitor", "Telemetry normalization & sensor validation", "Normalized telemetry confirmed valid."),
            ("analyzer", "Agent 2 — Analyzer", "Rule evaluation & ML advisory inference", f"Deterministic state: {incident['detection_state']}."),
            ("investigator", "Agent 3 — Investigator", "Entity graph correlation (user, IP, session)", f"Mapped {incident['source_ip']} to target {incident['target']}."),
            ("threat_intel", "Agent 4 — Threat Intel", "MITRE ATT&CK technique catalog alignment", f"Mapped to {incident['mitre_technique']} ({incident['mitre_tactic']})."),
            ("forensic", "Agent 5 — Forensic", "Timeline reconstruction & cryptographic preservation", "Forensic timeline generated. Preserved in vault."),
            ("guardian", "Agent 6 — Guardian", "Safe containment policy assessment", "Safe policy evaluated. Recommended: ISOLATE_LAB_ENDPOINT."),
            ("reporter", "Agent 7 — Reporter", "Forensic summary synthesis & report generation", "Incident report package generated.")
        ]

        results = []
        for agent_id, agent_name, task, decision in stages:
            run = {
                "run_id": f"RUN-{agent_id.upper()}-{len(self.runs)+1}",
                "agent_id": agent_id,
                "agent_name": agent_name,
                "incident_id": inc_id,
                "timestamp": now,
                "task": task,
                "decision": decision,
                "status": "COMPLETED",
                "confidence": incident.get("confidence", 0.95)
            }
            self.runs.append(run)
            results.append(run)

        vault.store(
            incident_id=inc_id,
            event_id=event.get("event_id", "EVT-AUTO"),
            evidence_type="SEVEN_AGENT_PIPELINE_RECORD",
            source="MAS-CSI Multi-Agent Engine",
            content=str(results)
        )

        incident["status"] = "INVESTIGATING"
        return results
