# MAS-CSI End-to-End Testing & Validation Runbook

## End-to-End Verification Sequence

1. **Start System**: Load the MAS-CSI platform and verify that initial counters reflect actual memory state (0 confirmed incidents, clean telemetry).
2. **Real Lab Employee Registration**:
   - Navigate to **Real Lab** tab.
   - Register a new account (e.g., `alice_lab`).
   - Notice that the password is cryptographically hashed with SHA-256 before storage.
   - Observe the `user_registration` telemetry event emitted to the Live SOC feed.
3. **Authentication Monitoring & Stateful Brute Force Correlation**:
   - Intentionally fail authentication 3 times within 120 seconds.
   - Observe stateful correlation detect the threshold condition.
   - A confirmed incident `Brute Force Credential Spray on 'alice_lab'` (T1110) is generated.
4. **Seven-Agent Execution**:
   - Inspect the incident dossier.
   - Verify that all 7 agents executed in sequence:
     * *Monitor*: Normalizes failed auth packet schema.
     * *Analyzer*: Asserts deterministic rule trigger.
     * *Investigator*: Correlates username to session and device.
     * *Threat Intel*: Aligns technique T1110.
     * *Forensic*: Seals raw evidence record into vault.
     * *Guardian*: Evaluates safe containment boundary (`ISOLATE_LAB_ENDPOINT`).
     * *Reporter*: Synthesizes forensic investigation package.
5. **Cryptographic Evidence Verification**:
   - Navigate to **Evidence Vault**.
   - Click **Verify SHA-256** on the sealed record (shows `VALID`).
   - Click **Inject Tamper Byte** to corrupt a byte.
   - Click **Verify SHA-256** again (immediately flags `INVALID` corruption).
   - Click **Restore & Reseal** to repair.
6. **Location Intelligence**:
   - Open **Location Intelligence**.
   - Click **Request Browser Geolocation**.
   - Verify real coordinates are plotted and impossible-travel speed is calculated.
7. **Reports Generation**:
   - Open **Reports**.
   - Click **Export JSON** to download forensic JSON artifact.
   - Click **Download PDF Report** to compile and download high-fidelity PDF report.
8. **Admin Governance & Audit**:
   - Navigate to **Admin Center**.
   - Review immutable audit log reflecting every action.
   - Test administrative account suspension and session revocation.
9. **Project Archive Export**:
   - Click **Download ZIP** in the navigation header to download the complete standalone `MAS-CSI-v9-FULL.zip` repository.
