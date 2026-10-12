# MAS-CSI Final Verification & Compliance Report

## Compliance with Absolute Data Integrity Rule
- **No Fabricated Events**: Zero synthetic attacks or fake telemetry counters are generated to make the UI look populated. When zero incidents exist, the system honestly displays "0 confirmed incidents".
- **No Fabricated Attributions**: IP addresses and username parameters are never asserted as confirmed attacker identities without independent non-repudiation proof.
- **Deterministic Detection**: Ground-truth confirmation relies strictly on hard deterministic signatures and sliding-window thresholds (e.g., failed authentication count >= 3 within 120s for Brute Force T1110).
- **ML Advisory Distinction**: Machine Learning outputs from Isolation Forest and Random Forest are explicitly marked as "ML ADVISORY SIGNAL (not deterministic confirmation)".
- **Cryptographic Evidence Sealing**: Evidence records are sealed with SHA-256 digests. Corrupting a single byte in the tamper test immediately causes the verification to fail.
- **Browser Geolocation**: Uses the real browser Geolocation API. If permission is denied, the system displays "Location unavailable" rather than inventing coordinates.
- **Backend RBAC Enforced**: Administrative actions (suspension, session revocation) require valid role permissions and produce immutable audit log entries.
