"""
MAS-CSI Evidence Vault
Cryptographic SHA-256 integrity verification module
"""
import hashlib
import datetime
from typing import Dict, Any, List

class EvidenceVault:
    def __init__(self):
        self.records: List[Dict[str, Any]] = []

    def store(self, incident_id: str, event_id: str, evidence_type: str, source: str, content: str) -> Dict[str, Any]:
        sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
        now = datetime.datetime.utcnow().isoformat() + "Z"
        prev_hash = self.records[0]["sha256"] if self.records else None

        record = {
            "evidence_id": f"EVD-{len(self.records)+101}",
            "incident_id": incident_id,
            "event_id": event_id,
            "type": evidence_type,
            "source": source,
            "collected_timestamp": now,
            "content": content,
            "sha256": sha256,
            "integrity_status": "VALID",
            "previous_evidence_hash": prev_hash,
            "custody_chain": {
                "collected_by": source,
                "verified_by": "MAS-CSI Automated Vault",
                "timestamp": now
            }
        }
        self.records.insert(0, record)
        return record

    def verify(self, evidence_id: str) -> Dict[str, Any]:
        for rec in self.records:
            if rec["evidence_id"] == evidence_id:
                calc = hashlib.sha256(rec["content"].encode("utf-8")).hexdigest()
                is_valid = (calc.lower() == rec["sha256"].lower())
                rec["integrity_status"] = "VALID" if is_valid else "INVALID"
                return {
                    "evidence_id": evidence_id,
                    "is_valid": is_valid,
                    "stored_hash": rec["sha256"],
                    "calculated_hash": calc
                }
        return {"error": "Evidence not found"}
