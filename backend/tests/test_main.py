"""
Pytest integration tests for MAS-CSI backend
"""
import pytest
from app.detector import DeterministicDetector
from app.correlation import StatefulCorrelator
from app.evidence import EvidenceVault
from app.security import SecurityAuthManager

def test_detector_sql_injection():
    detector = DeterministicDetector()
    event = {
        "event_type": "web_request",
        "raw_event": "SELECT * FROM users WHERE id = 1 UNION SELECT schema_name FROM information_schema.schemata--"
    }
    detection = detector.evaluate(event)
    assert detection["detection_state"] == "CONFIRMED"
    assert detection["mitre_technique"] == "T1190"

def test_detector_benign_event():
    detector = DeterministicDetector()
    event = {
        "event_type": "page_view",
        "raw_event": "GET /dashboard HTTP/1.1"
    }
    detection = detector.evaluate(event)
    assert detection["detection_state"] == "NORMAL"

def test_evidence_tamper_detection():
    vault = EvidenceVault()
    rec = vault.store("INC-01", "EVT-01", "LOG", "SENSOR", "Clean Data Payload")
    assert vault.verify(rec["evidence_id"])["is_valid"] is True

    # Tamper payload
    rec["content"] = "Corrupted Data Payload"
    assert vault.verify(rec["evidence_id"])["is_valid"] is False

def test_rbac_permissions():
    auth = SecurityAuthManager()
    assert auth.check_permission("Super Admin", "SUSPEND") is True
    assert auth.check_permission("Employee", "SUSPEND") is False
