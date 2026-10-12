"""
MAS-CSI Security & RBAC Module
"""
import hashlib

class SecurityAuthManager:
    @staticmethod
    def hash_password(password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        calc = hashlib.sha256(plain_password.encode("utf-8")).hexdigest()
        return calc.lower() == hashed_password.lower()

    @staticmethod
    def check_permission(user_role: str, action: str) -> bool:
        rbac_matrix = {
            "Super Admin": ["VIEW", "INVESTIGATE", "RESPONSE", "SUSPEND", "REVOKE", "REPORT"],
            "Security Analyst": ["VIEW", "INVESTIGATE", "RESPONSE", "REPORT"],
            "Auditor": ["VIEW", "AUDIT_REVIEW", "REPORT"],
            "Employee": ["VIEW_PROFILE", "UPLOAD", "DOWNLOAD"]
        }
        allowed = rbac_matrix.get(user_role, [])
        return action in allowed
