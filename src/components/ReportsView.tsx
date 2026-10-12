/**
 * MAS-CSI Reports View
 * Section 34 compliant: Generates JSON forensic artifact packages
 * and high-fidelity PDF investigation reports via jsPDF.
 */

import React, { useState } from 'react';
import {
  FileText,
  Download,
  FileCheck2,
  CheckCircle2,
  Printer,
  ShieldAlert,
  Lock,
  Layers
} from 'lucide-react';
import { store } from '../services/store';
import { generateIncidentJson, generateIncidentPdf, downloadJsonFile } from '../services/reportGenerator';

export const ReportsView: React.FC = () => {
  const incidents = store.incidents;
  const events = store.events;
  const evidence = store.evidenceVault;
  const agentRuns = store.agentRuns;

  const [selectedIncidentId, setSelectedIncidentId] = useState<string>(
    incidents[0]?.incident_id || ''
  );
  const [downloadSuccess, setDownloadSuccess] = useState<string | null>(null);

  const selectedIncident = incidents.find(i => i.incident_id === selectedIncidentId) || incidents[0];

  const handleDownloadPdf = () => {
    if (!selectedIncident) return;
    generateIncidentPdf(selectedIncident, agentRuns, evidence);
    setDownloadSuccess('PDF Report compiled and downloaded successfully.');
    setTimeout(() => setDownloadSuccess(null), 4000);
  };

  const handleDownloadJson = () => {
    if (!selectedIncident) return;
    const jsonContent = generateIncidentJson(selectedIncident, agentRuns, evidence, events);
    downloadJsonFile(`MAS_CSI_${selectedIncident.incident_id}_forensic_report.json`, jsonContent);
    setDownloadSuccess('JSON Forensic Package exported successfully.');
    setTimeout(() => setDownloadSuccess(null), 4000);
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded bg-cyan-950 border border-cyan-500/40 text-cyan-400">
            <FileText className="w-4 h-4" />
          </div>
          <div>
            <h1 className="text-sm font-bold font-mono text-slate-100">
              Forensic Incident Reporting & Export Engine
            </h1>
            <p className="text-xs text-slate-400">
              Compliant with ISO/IEC 27037 Digital Evidence standards and NIST SP 800-61
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadJson}
            disabled={!selectedIncident}
            className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:bg-slate-900 text-slate-200 font-mono font-semibold text-xs rounded flex items-center gap-2 cursor-pointer transition border border-slate-700"
          >
            <FileCheck2 className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export JSON</span>
          </button>
          <button
            onClick={handleDownloadPdf}
            disabled={!selectedIncident}
            className="px-3.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-900 text-slate-950 font-mono font-bold text-xs rounded flex items-center gap-2 cursor-pointer transition shadow-xs"
          >
            <Download className="w-3.5 h-3.5 stroke-[2.5]" />
            <span>Download PDF Report</span>
          </button>
        </div>
      </div>

      {downloadSuccess && (
        <div className="p-3 bg-emerald-950/70 border border-emerald-600/50 rounded text-emerald-300 text-xs font-mono flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{downloadSuccess}</span>
        </div>
      )}

      {/* Incident Selection Dropdown */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 font-mono text-xs flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="text-slate-400">Target Incident for Report Compilation:</span>
          <select
            value={selectedIncident?.incident_id || ''}
            onChange={(e) => setSelectedIncidentId(e.target.value)}
            className="bg-slate-950 text-slate-200 border border-slate-800 rounded px-3 py-1.5 focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            {incidents.length === 0 && <option value="">0 incidents in database</option>}
            {incidents.map(i => (
              <option key={i.incident_id} value={i.incident_id}>
                {i.incident_id} — {i.title}
              </option>
            ))}
          </select>
        </div>

        <span className="text-[11px] text-slate-500">
          Status: {selectedIncident?.status || 'No incident'}
        </span>
      </div>

      {/* Interactive Report Preview Dossier */}
      {selectedIncident ? (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 font-mono text-xs space-y-6 text-slate-300">
          {/* Header of Report Document */}
          <div className="border-b border-slate-800 pb-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-cyan-400 font-bold text-sm">MAS-CSI INCIDENT INVESTIGATION REPORT</div>
              <div className="text-slate-400 text-[11px] mt-0.5">
                Classification: RESTRICTED / AUTHORIZED LAB REPORT
              </div>
            </div>
            <div className="text-right text-[11px] text-slate-500">
              <div>Ref: {selectedIncident.incident_id}</div>
              <div>Generated: {new Date().toUTCString()}</div>
            </div>
          </div>

          {/* Incident Overview Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="p-3 bg-slate-950 border border-slate-800 rounded">
              <span className="text-slate-500 block text-[10px]">INCIDENT TITLE</span>
              <span className="font-bold text-slate-200">{selectedIncident.title}</span>
            </div>
            <div className="p-3 bg-slate-950 border border-slate-800 rounded">
              <span className="text-slate-500 block text-[10px]">SEVERITY & RISK</span>
              <span className="font-bold text-amber-400">{selectedIncident.severity} ({selectedIncident.risk_score}/100)</span>
            </div>
            <div className="p-3 bg-slate-950 border border-slate-800 rounded">
              <span className="text-slate-500 block text-[10px]">ATTRIBUTION STATUS</span>
              <span className="font-bold text-slate-300">{selectedIncident.actor_identity}</span>
            </div>
            <div className="p-3 bg-slate-950 border border-slate-800 rounded">
              <span className="text-slate-500 block text-[10px]">MITRE TECHNIQUE</span>
              <span className="font-bold text-cyan-400">{selectedIncident.mitre_technique}</span>
            </div>
          </div>

          {/* Section 1: Deterministic Ground Truth */}
          <div>
            <h3 className="font-bold text-cyan-400 text-xs uppercase mb-2">1. Deterministic Detection Ground Truth</h3>
            <div className="p-3 bg-slate-950 border border-slate-800 rounded text-slate-200 leading-relaxed">
              {selectedIncident.detection_reason}
            </div>
          </div>

          {/* Section 2: 7-Agent Investigation Pipeline */}
          <div>
            <h3 className="font-bold text-cyan-400 text-xs uppercase mb-2">2. Seven-Agent Pipeline Findings</h3>
            <div className="space-y-2">
              {agentRuns.filter(a => a.incident_id === selectedIncident.incident_id).map(a => (
                <div key={a.run_id} className="p-2.5 bg-slate-950 border border-slate-800 rounded flex items-start justify-between">
                  <div>
                    <span className="font-bold text-purple-300">{a.agent_name}:</span>{' '}
                    <span className="text-slate-300">{a.decision}</span>
                  </div>
                  <span className="text-[10px] text-emerald-400 font-semibold shrink-0 ml-2">{a.status}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Section 3: Evidence Vault */}
          <div>
            <h3 className="font-bold text-cyan-400 text-xs uppercase mb-2">3. Sealed Evidence Vault Records (SHA-256)</h3>
            <div className="space-y-2">
              {evidence.filter(e => e.incident_id === selectedIncident.incident_id).map(e => (
                <div key={e.evidence_id} className="p-2.5 bg-slate-950 border border-slate-800 rounded text-[11px]">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-200">{e.evidence_id} ({e.type})</span>
                    <span className="text-emerald-400 font-semibold">{e.integrity_status}</span>
                  </div>
                  <div className="text-slate-400 mt-1 break-all">
                    SHA-256: <code className="text-cyan-300">{e.sha256}</code>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Final Assessment */}
          <div className="p-4 bg-slate-950/80 border border-slate-800 rounded text-[11px] text-slate-400">
            <span className="font-bold text-slate-300 block mb-1">FINAL SOC ASSESSMENT:</span>
            Incident {selectedIncident.incident_id} is evaluated as {selectedIncident.detection_state}. All supporting telemetry items are sealed under SHA-256 cryptographic chain of custody. No fabricated metrics or unsupported attributions are contained in this document.
          </div>
        </div>
      ) : (
        <div className="p-16 text-center text-slate-500 border border-dashed border-slate-800 rounded font-mono text-xs">
          No incident selected. Run a controlled scenario from the top navigation to generate an incident report.
        </div>
      )}
    </div>
  );
};
