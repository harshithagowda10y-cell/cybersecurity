/**
 * MAS-CSI Incident Details Modal
 * Complete forensic incident dossier with 7-agent pipeline execution,
 * evidence chain, timeline, and safe administrative response actions.
 */

import React, { useState } from 'react';
import {
  ShieldAlert,
  X,
  FileText,
  Download,
  Lock,
  Cpu,
  Clock,
  CheckCircle2,
  AlertTriangle,
  Radio,
  FileCheck2,
  ShieldCheck
} from 'lucide-react';
import { Incident, ResponseAction } from '../types/mas_csi';
import { store } from '../services/store';
import { generateIncidentJson, generateIncidentPdf, downloadJsonFile } from '../services/reportGenerator';

interface IncidentDetailsModalProps {
  incident: Incident | null;
  onClose: () => void;
}

export const IncidentDetailsModal: React.FC<IncidentDetailsModalProps> = ({
  incident,
  onClose,
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'agents' | 'evidence' | 'timeline' | 'response'>('overview');
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  if (!incident) return null;

  const agentRuns = store.agentRuns.filter(r => r.incident_id === incident.incident_id);
  const evidenceItems = store.evidenceVault.filter(e => e.incident_id === incident.incident_id);
  const correlatedEvents = store.events.filter(e => incident.correlated_event_ids.includes(e.event_id));
  const currentUser = store.currentUser;

  const handleResponseAction = (actionType: ResponseAction['action_type']) => {
    if (!currentUser) return;
    const res = store.executeResponseAction(incident.incident_id, actionType, currentUser);
    if (res.success) {
      setActionSuccess(`Controlled policy [${actionType}] executed successfully.`);
      setTimeout(() => setActionSuccess(null), 4000);
    } else {
      alert(res.error || 'Failed to execute response.');
    }
  };

  const handleExportJson = () => {
    const json = generateIncidentJson(incident, store.agentRuns, store.evidenceVault, store.events);
    downloadJsonFile(`MAS_CSI_Incident_${incident.incident_id}.json`, json);
  };

  const handleExportPdf = () => {
    generateIncidentPdf(incident, store.agentRuns, store.evidenceVault);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-xs p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-4xl w-full max-h-[90vh] flex flex-col text-slate-100 shadow-2xl relative font-mono text-xs">
        {/* Modal Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded border ${
              incident.severity === 'CRITICAL'
                ? 'bg-rose-950/80 border-rose-600 text-rose-300'
                : incident.severity === 'HIGH'
                ? 'bg-amber-950/80 border-amber-600 text-amber-300'
                : 'bg-blue-950/80 border-blue-600 text-blue-300'
            }`}>
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-sm text-slate-100">{incident.title}</span>
                <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 border border-slate-700 text-slate-300">
                  {incident.incident_id}
                </span>
                {incident.is_lab_scenario && (
                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-amber-950 text-amber-300 border border-amber-800">
                    CONTROLLED LAB SCENARIO
                  </span>
                )}
              </div>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Observed: {incident.created_at} · Status: <strong className="text-cyan-400">{incident.status}</strong>
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleExportJson}
              className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded flex items-center gap-1 cursor-pointer transition"
              title="Export Incident JSON artifact"
            >
              <FileCheck2 className="w-3.5 h-3.5 text-cyan-400" />
              <span>JSON</span>
            </button>
            <button
              onClick={handleExportPdf}
              className="px-2.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded flex items-center gap-1 cursor-pointer transition"
              title="Download Professional Incident PDF Report"
            >
              <Download className="w-3.5 h-3.5 stroke-[2.5]" />
              <span>PDF Report</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-slate-200 cursor-pointer ml-2"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex border-b border-slate-800 bg-slate-950/40 px-4">
          {[
            { id: 'overview', label: 'Overview & Ground Truth' },
            { id: 'agents', label: `7-Agent Pipeline (${agentRuns.length})` },
            { id: 'evidence', label: `Evidence Vault (${evidenceItems.length})` },
            { id: 'timeline', label: `Correlated Events (${correlatedEvents.length})` },
            { id: 'response', label: 'Administrative Response' },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`py-2.5 px-3 border-b-2 font-medium transition cursor-pointer text-xs ${
                activeTab === tab.id
                  ? 'border-cyan-400 text-cyan-300'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Modal Body */}
        <div className="p-5 overflow-y-auto space-y-4 flex-1">
          {actionSuccess && (
            <div className="p-3 bg-emerald-950/70 border border-emerald-600/50 rounded text-emerald-300 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{actionSuccess}</span>
            </div>
          )}

          {/* OVERVIEW TAB */}
          {activeTab === 'overview' && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="p-3 bg-slate-950 border border-slate-800 rounded">
                  <span className="text-slate-500 block text-[10px]">Detection State</span>
                  <span className="text-rose-400 font-bold">{incident.detection_state}</span>
                </div>
                <div className="p-3 bg-slate-950 border border-slate-800 rounded">
                  <span className="text-slate-500 block text-[10px]">Risk Score</span>
                  <span className="text-amber-400 font-bold">{incident.risk_score}/100</span>
                </div>
                <div className="p-3 bg-slate-950 border border-slate-800 rounded">
                  <span className="text-slate-500 block text-[10px]">MITRE Technique</span>
                  <span className="text-cyan-400 font-bold">{incident.mitre_technique} ({incident.mitre_tactic})</span>
                </div>
                <div className="p-3 bg-slate-950 border border-slate-800 rounded">
                  <span className="text-slate-500 block text-[10px]">Target</span>
                  <span className="text-slate-200 font-bold">{incident.target}</span>
                </div>
              </div>

              {/* Attribution Honesty Note */}
              <div className="p-3 bg-slate-950 border border-slate-800 rounded space-y-1">
                <span className="text-slate-500 block text-[10px]">Telemetry Source & Attribution Status</span>
                <p className="text-slate-300">
                  Observed IP: <span className="text-cyan-400 font-semibold">{incident.source_ip}</span> ·
                  Attribution: <span className="text-slate-400 italic">{incident.actor_identity}</span>
                </p>
                <p className="text-[11px] text-slate-500">
                  Note: Under MAS-CSI data integrity standards, IP addresses and usernames are not asserted as attacker identities without independent non-repudiation proof.
                </p>
              </div>

              {/* Deterministic Ground Truth Reason */}
              <div className="p-3 bg-slate-950 border border-slate-800 rounded">
                <span className="text-cyan-400 font-semibold block mb-1">Deterministic Detection Reason:</span>
                <p className="text-slate-300 leading-relaxed">{incident.detection_reason}</p>
              </div>

              {/* Incident Summary */}
              <div className="p-3 bg-slate-950 border border-slate-800 rounded">
                <span className="text-slate-400 font-semibold block mb-1">Investigation Summary:</span>
                <p className="text-slate-300 leading-relaxed">{incident.summary}</p>
              </div>
            </div>
          )}

          {/* AGENTS TAB */}
          {activeTab === 'agents' && (
            <div className="space-y-3">
              <p className="text-slate-400 text-[11px]">
                The seven distinct workflow stages executed sequentially for this incident:
              </p>
              {agentRuns.map((agent) => (
                <div key={agent.run_id} className="p-3.5 bg-slate-950 border border-slate-800 rounded space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-cyan-400">{agent.agent_name}</span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-400">
                      {agent.status} ({Math.round(agent.confidence * 100)}% Confidence)
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">Task Objective</span>
                    <span className="text-slate-300">{agent.task}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">Input Data</span>
                    <pre className="text-slate-400 text-[11px] whitespace-pre-wrap">{agent.input}</pre>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">Decision & Action</span>
                    <p className="text-emerald-300 font-medium">{agent.decision}</p>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* EVIDENCE TAB */}
          {activeTab === 'evidence' && (
            <div className="space-y-3">
              <p className="text-slate-400 text-[11px]">
                Evidence items sealed in the cryptographic vault with SHA-256 digests:
              </p>
              {evidenceItems.map((ev) => (
                <div key={ev.evidence_id} className="p-3.5 bg-slate-950 border border-slate-800 rounded space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-200">{ev.evidence_id} [{ev.type}]</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] ${
                      ev.integrity_status === 'VALID'
                        ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        : 'bg-rose-950 text-rose-400 border border-rose-800'
                    }`}>
                      {ev.integrity_status}
                    </span>
                  </div>
                  <div className="p-2 bg-slate-900 rounded border border-slate-800 text-[11px]">
                    <span className="text-slate-500 block">SHA-256 Digest:</span>
                    <code className="text-cyan-300 break-all">{ev.sha256}</code>
                  </div>
                  <pre className="p-2 bg-slate-900 rounded text-slate-400 text-[11px] max-h-32 overflow-y-auto">
                    {ev.content}
                  </pre>
                  <div className="text-[10px] text-slate-500">
                    Collected by {ev.custody_chain.collected_by} at {ev.collected_timestamp}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* TIMELINE TAB */}
          {activeTab === 'timeline' && (
            <div className="space-y-3">
              <div className="border-l-2 border-slate-800 pl-4 space-y-4">
                {correlatedEvents.map((ev) => (
                  <div key={ev.event_id} className="relative">
                    <span className="absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full bg-cyan-500 ring-4 ring-slate-900" />
                    <div className="p-3 bg-slate-950 border border-slate-800 rounded">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-slate-200">{ev.event_type}</span>
                        <span className="text-slate-500 text-[11px]">{ev.timestamp}</span>
                      </div>
                      <p className="text-slate-300 mt-1">{ev.message}</p>
                      <div className="mt-2 text-[10px] text-slate-400 flex gap-4">
                        <span>Source: {ev.source_ip}:{ev.source_port}</span>
                        <span>Protocol: {ev.protocol}</span>
                        <span>ML Label: {ev.ml_label}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* RESPONSE TAB */}
          {activeTab === 'response' && (
            <div className="space-y-4">
              <div className="p-3 bg-slate-950 border border-amber-900/40 rounded">
                <div className="flex items-center gap-2 text-amber-300 font-semibold mb-1">
                  <AlertTriangle className="w-4 h-4" />
                  <span>Controlled Response Policies (Safe Lab Boundaries)</span>
                </div>
                <p className="text-slate-400 text-[11px]">
                  All response actions are safe, controlled, and reversible. No destructive network alterations or external reach. Requires Security Analyst or Super Admin role.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <button
                  onClick={() => handleResponseAction('ISOLATE_LAB_ENDPOINT')}
                  className="p-3 bg-slate-950 border border-slate-800 hover:border-rose-500 text-left rounded cursor-pointer transition"
                >
                  <span className="font-bold text-rose-400 block mb-1">ISOLATE LAB ENDPOINT</span>
                  <p className="text-slate-400 text-[11px]">
                    Sever simulated network socket for lab endpoint. Changes incident status to CONTAINED.
                  </p>
                </button>

                <button
                  onClick={() => handleResponseAction('BLOCK_LAB_SOURCE')}
                  className="p-3 bg-slate-950 border border-slate-800 hover:border-amber-500 text-left rounded cursor-pointer transition"
                >
                  <span className="font-bold text-amber-400 block mb-1">BLOCK LAB SOURCE</span>
                  <p className="text-slate-400 text-[11px]">
                    Simulate firewall drop rule for lab fixture IP {incident.source_ip}.
                  </p>
                </button>

                <button
                  onClick={() => handleResponseAction('PRESERVE_EVIDENCE')}
                  className="p-3 bg-slate-950 border border-slate-800 hover:border-emerald-500 text-left rounded cursor-pointer transition"
                >
                  <span className="font-bold text-emerald-400 block mb-1">PRESERVE EVIDENCE</span>
                  <p className="text-slate-400 text-[11px]">
                    Trigger immutable cryptographic lockdown of all records in vault.
                  </p>
                </button>

                <button
                  onClick={() => handleResponseAction('SIMULATE_CONTAINMENT')}
                  className="p-3 bg-slate-950 border border-slate-800 hover:border-cyan-500 text-left rounded cursor-pointer transition"
                >
                  <span className="font-bold text-cyan-400 block mb-1">SIMULATE CONTAINMENT</span>
                  <p className="text-slate-400 text-[11px]">
                    Verify full remediation workflow and update incident status to RESOLVED.
                  </p>
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-slate-800 flex items-center justify-between bg-slate-950/60">
          <span className="text-slate-500 text-[11px]">
            MAS-CSI Forensic Investigation Engine · Ground Truth Verified
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded cursor-pointer transition"
          >
            Close Dossier
          </button>
        </div>
      </div>
    </div>
  );
};
