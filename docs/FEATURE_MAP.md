# MAS-CSI Architecture & Verification Documentation

## 1. Project Overview
**MAS-CSI** (Multi-Agent Systems for Cyber Security Intelligence) is an evidence-driven, real-time cybersecurity SOC and incident-investigation platform. It bridges an authorized local Real Lab with deterministic detection, stateful correlation, 7-agent investigation, forensic SHA-256 evidence vault sealing, and administrative response.

## 2. Implemented Feature Map
- **Command Center**: Database-derived threat posture, 3D Cyber Core spatial visualizer, live telemetry metrics, quick controlled scenario triggers.
- **Live SOC**: Real-time telemetry feed, detection state categorizations (`NORMAL`, `SUSPICIOUS`, `CONFIRMED`, `ABSTAINED`), stream controls, detailed event inspect modal.
- **Incidents Queue**: Filterable by status (`NEW`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`), severity, MITRE technique, and source IP.
- **Incident Dossier Deep Dive**: Full investigation breakdown, correlated timeline, 7-agent outputs, sealed evidence chain, and safe administrative actions.
- **Seven-Agent Pipeline**:
  1. *Agent 1 — Monitor*: Telemetry ingestion, schema validation, and normalization.
  2. *Agent 2 — Analyzer*: Deterministic rule assessment & advisory ML evaluation.
  3. *Agent 3 — Investigator*: Entity graph correlation (User, Device, Session, IP, Geolocation).
  4. *Agent 4 — Threat Intelligence*: MITRE ATT&CK technique catalog alignment.
  5. *Agent 5 — Forensic*: Forensic timeline generation & SHA-256 evidence sealing.
  6. *Agent 6 — Guardian*: Safe containment boundary checks (`ISOLATE_LAB_ENDPOINT`, `BLOCK_LAB_SOURCE`, etc.).
  7. *Agent 7 — Reporter*: Dossier synthesis, JSON export, and PDF generation.
- **GenAI Security Copilot**: Grounded strictly in verified telemetry records. Distinguishes observed telemetry vs deterministic detection vs ML advisory vs agent analysis.
- **Threat Intelligence**: MITRE ATT&CK matrix explorer (T1110, T1046, T1071.004, T1190, T1041, T1078) and honest external connectors status.
- **Attack Graph**: Node-link graph connecting User → Device → Session → Event → Detection → Incident → Technique → Evidence.
- **Forensics & Payload Inspector**: Chronological timeline, request metadata, and raw packet hexadecimal dump viewer.
- **Cryptographic Evidence Vault**: Real-time SHA-256 verification using Web Crypto API digests, custody chain tracking, and live byte-level tamper simulation.
- **Location Intelligence**: Browser Geolocation API coordinates, accuracy radius, and impossible-travel speed anomaly engine.
- **Reports**: Full JSON artifact export and professional PDF report compilation.
- **Authorized Real Lab**: Employee portal with registration, login, PBKDF2/SHA-256 credential hashing, document upload with SHA-256 calculation, and download.
- **Admin Security Center**: RBAC governance (Super Admin, Security Analyst, Auditor, Employee), user suspension, login control, session revocation, and audit logs.
- **Export Bundle**: Instant one-click "Download Full MAS-CSI Project (.zip)" bundling the entire Python backend, lab webapp, integrations, scripts, and documentation.
