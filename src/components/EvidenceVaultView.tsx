/**
 * MAS-CSI Cryptographic Evidence Vault
 * Section 24 compliant: SHA-256 integrity sealing, live Web Crypto verification,
 * and tamper detection testing.
 */

import React, { useState } from 'react';
import {
  KeyRound,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Lock,
  Unlock,
  CheckCircle2,
  XCircle,
  FileText,
  Search,
  ExternalLink
} from 'lucide-react';
import { store } from '../services/store';
import { EvidenceRecord } from '../types/mas_csi';

export const EvidenceVaultView: React.FC = () => {
  const evidence = store.evidenceVault;
  const currentUser = store.currentUser;

  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [verificationFeedback, setVerificationFeedback] = useState<{ [id: string]: string }>({});
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedRecord, setSelectedRecord] = useState<EvidenceRecord | null>(null);

  const filtered = evidence.filter(e =>
    searchTerm === '' ||
    e.evidence_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
    e.incident_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
    e.type.toLowerCase().includes(searchTerm.toLowerCase()) ||
    e.sha256.includes(searchTerm)
  );

  const handleVerify = async (record: EvidenceRecord) => {
    setVerifyingId(record.evidence_id);
    try {
      const res = await store.verifyEvidence(record.evidence_id);
      setVerificationFeedback(prev => ({
        ...prev,
        [record.evidence_id]: res.isValid
          ? `✓ SHA-256 MATCH: Cryptographic integrity confirmed (${res.calculatedHash.slice(0, 12)}...)`
          : `✗ CORRUPTION DETECTED: Hash mismatch. Calculated ${res.calculatedHash.slice(0, 12)}... ≠ Stored ${res.storedHash.slice(0, 12)}...`,
      }));
    } catch (err) {
      console.error(err);
    }
    setVerifyingId(null);
  };

  const handleTamperTest = (record: EvidenceRecord) => {
    store.tamperEvidenceForTest(record.evidence_id);
    setVerificationFeedback(prev => ({
      ...prev,
      [record.evidence_id]: '⚠ Tamper byte injected! Click "Verify SHA-256" to observe integrity failure.',
    }));
  };

  const handleRestoreRecord = async (record: EvidenceRecord) => {
    await store.restoreEvidenceHash(record.evidence_id);
    setVerificationFeedback(prev => ({
      ...prev,
      [record.evidence_id]: '✓ Tamper removed & record re-sealed with verified SHA-256 hash.',
    }));
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded bg-emerald-950 border border-emerald-500/40 text-emerald-400">
            <KeyRound className="w-4 h-4" />
          </div>
          <div>
            <h1 className="text-sm font-bold font-mono text-slate-100">
              Cryptographic Evidence Vault & Chain of Custody
            </h1>
            <p className="text-xs text-slate-400">
              SHA-256 immutable digital evidence sealing conforming to ISO/IEC 27037 standards
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs font-mono">
          <span className="text-slate-400">
            Sealed Records: <strong className="text-emerald-400">{evidence.length}</strong>
          </span>
          <span className="text-slate-500">|</span>
          <span className="text-slate-400">
            Integrity: <strong className="text-cyan-400">Web Crypto API Active</strong>
          </span>
        </div>
      </div>

      {/* Verification Protocol Notice */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3.5 text-xs font-mono text-slate-300 space-y-1">
        <div className="flex items-center gap-2 text-emerald-400 font-bold">
          <ShieldCheck className="w-4 h-4" />
          <span>Real Cryptographic Verification Guarantee</span>
        </div>
        <p className="text-slate-400 leading-relaxed text-[11px]">
          Every record's SHA-256 hash is computed in real-time over its raw payload bytes using standard Web Crypto digests.
          Use the <strong>"Inject Tamper Byte"</strong> button to alter a byte and test that the verifier catches forensic tampering immediately.
        </p>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 flex flex-wrap items-center justify-between gap-3">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search by evidence ID, incident, type, or hash prefix..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded pl-9 pr-3 py-1.5 text-xs font-mono text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
        <div className="text-xs font-mono text-slate-400">
          Showing {filtered.length} of {evidence.length} vault entries
        </div>
      </div>

      {/* Evidence Records List */}
      <div className="space-y-3 font-mono text-xs">
        {filtered.length === 0 ? (
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-12 text-center text-slate-500">
            0 evidence records sealed in vault. Execute a controlled scenario or submit files in Real Lab to create sealed forensic evidence.
          </div>
        ) : (
          filtered.map((record) => (
            <div
              key={record.evidence_id}
              className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3 hover:border-slate-700 transition"
            >
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
                <div className="flex items-center gap-2.5">
                  <span className="font-bold text-slate-100 text-sm">{record.evidence_id}</span>
                  <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-cyan-400 text-[11px]">
                    {record.type}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-400 text-[11px]">
                    Incident: {record.incident_id}
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <span className={`px-2.5 py-0.5 rounded text-[11px] font-bold flex items-center gap-1 ${
                    record.integrity_status === 'VALID'
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                      : record.integrity_status === 'INVALID'
                      ? 'bg-rose-950 text-rose-300 border border-rose-800'
                      : 'bg-amber-950 text-amber-300 border border-amber-800'
                  }`}>
                    {record.integrity_status === 'VALID' && <CheckCircle2 className="w-3.5 h-3.5" />}
                    {record.integrity_status === 'INVALID' && <XCircle className="w-3.5 h-3.5" />}
                    <span>{record.integrity_status}</span>
                  </span>
                </div>
              </div>

              {/* SHA-256 Digest Box (Wrapped) */}
              <div className="p-2.5 bg-slate-950 border border-slate-800 rounded space-y-1">
                <span className="text-[10px] text-slate-500 block uppercase">Cryptographic SHA-256 Digest</span>
                <code className="text-emerald-400 text-xs break-all block selection:bg-emerald-900">
                  {record.sha256}
                </code>
              </div>

              {/* Chain of Custody */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 text-[11px]">
                <div className="p-2 bg-slate-950/60 rounded border border-slate-800/80">
                  <span className="text-slate-500 block text-[10px]">Collected By</span>
                  <span className="text-slate-300">{record.custody_chain.collected_by}</span>
                </div>
                <div className="p-2 bg-slate-950/60 rounded border border-slate-800/80">
                  <span className="text-slate-500 block text-[10px]">Collection Timestamp</span>
                  <span className="text-slate-300">{record.collected_timestamp}</span>
                </div>
                <div className="p-2 bg-slate-950/60 rounded border border-slate-800/80">
                  <span className="text-slate-500 block text-[10px]">Previous Block Hash</span>
                  <span className="text-slate-400 truncate block">
                    {record.previous_evidence_hash ? `${record.previous_evidence_hash.slice(0, 16)}...` : 'Genesis Block'}
                  </span>
                </div>
              </div>

              {/* Live Verification Feedback Banner */}
              {verificationFeedback[record.evidence_id] && (
                <div className={`p-2.5 rounded text-xs border ${
                  verificationFeedback[record.evidence_id].includes('CORRUPTION')
                    ? 'bg-rose-950/70 border-rose-600 text-rose-300'
                    : verificationFeedback[record.evidence_id].includes('Tamper')
                    ? 'bg-amber-950/70 border-amber-600 text-amber-300'
                    : 'bg-emerald-950/70 border-emerald-600 text-emerald-300'
                }`}>
                  {verificationFeedback[record.evidence_id]}
                </div>
              )}

              {/* Action Controls */}
              <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800 text-xs">
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleVerify(record)}
                    disabled={verifyingId === record.evidence_id}
                    className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold rounded flex items-center gap-1.5 cursor-pointer transition"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${verifyingId === record.evidence_id ? 'animate-spin' : ''}`} />
                    <span>Verify SHA-256</span>
                  </button>

                  <button
                    onClick={() => handleTamperTest(record)}
                    className="px-3 py-1.5 bg-rose-950/60 hover:bg-rose-900/60 text-rose-300 border border-rose-800 rounded cursor-pointer transition text-[11px]"
                    title="Simulate forensic byte corruption to test that the verifier catches tamper"
                  >
                    Inject Tamper Byte
                  </button>

                  {record.integrity_status === 'INVALID' && (
                    <button
                      onClick={() => handleRestoreRecord(record)}
                      className="px-3 py-1.5 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 rounded cursor-pointer transition text-[11px]"
                    >
                      Restore & Reseal
                    </button>
                  )}
                </div>

                <button
                  onClick={() => setSelectedRecord(record)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded cursor-pointer transition"
                >
                  Inspect Payload Content →
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Raw Content Inspection Modal */}
      {selectedRecord && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-xs p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-2xl w-full p-5 text-slate-100 shadow-2xl relative font-mono text-xs">
            <h2 className="text-sm font-bold text-cyan-400 mb-2">
              Evidence Content Inspector: {selectedRecord.evidence_id}
            </h2>
            <p className="text-[11px] text-slate-400 mb-3">
              Type: {selectedRecord.type} · Incident: {selectedRecord.incident_id}
            </p>

            <pre className="p-3 bg-slate-950 border border-slate-800 rounded text-slate-300 max-h-80 overflow-y-auto whitespace-pre-wrap text-[11px]">
              {selectedRecord.content}
            </pre>

            <div className="flex justify-end pt-3 mt-3 border-t border-slate-800">
              <button
                onClick={() => setSelectedRecord(null)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
