/**
 * MAS-CSI Threat Intelligence View
 * MITRE ATT&CK Matrix Alignment, Technique Catalog Justification,
 * and Honest Integrations Status Monitoring.
 */

import React, { useState } from 'react';
import {
  Radar,
  Shield,
  Activity,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  Layers,
  Terminal,
  Cpu
} from 'lucide-react';
import { store } from '../services/store';

export const ThreatIntelligenceView: React.FC = () => {
  const incidents = store.incidents;
  const integrations = store.integrations;

  const [selectedTechnique, setSelectedTechnique] = useState<string | null>('T1110');

  const mitreCatalog = [
    {
      id: 'T1110',
      name: 'Brute Force',
      tactic: 'Credential Access',
      description: 'Adversaries may use brute force techniques to attempt credential guess sequences.',
      technicalCondition: 'Observed when failed authentication attempts >= 3 within 120s rolling window.',
      observedInLab: incidents.some(i => i.mitre_technique === 'T1110'),
    },
    {
      id: 'T1046',
      name: 'Network Service Discovery (Port Scan)',
      tactic: 'Discovery',
      description: 'Adversaries may attempt to get a listing of services running on remote hosts.',
      technicalCondition: 'Observed when horizontal port sweep probes >= 5 distinct ports within rolling window.',
      observedInLab: incidents.some(i => i.mitre_technique === 'T1046'),
    },
    {
      id: 'T1071.004',
      name: 'Application Layer Protocol: DNS',
      tactic: 'Command and Control',
      description: 'Adversaries may communicate using the DNS protocol to tunnel command data.',
      technicalCondition: 'Observed when high-entropy TXT subdomains or burst queries to sinkhole domain occur.',
      observedInLab: incidents.some(i => i.mitre_technique === 'T1071.004'),
    },
    {
      id: 'T1190',
      name: 'Exploit Public-Facing Application',
      tactic: 'Initial Access',
      description: 'Adversaries may attempt to exploit vulnerabilities in Internet-facing software.',
      technicalCondition: 'Observed when input payloads match deterministic SQLi union or tautology patterns.',
      observedInLab: incidents.some(i => i.mitre_technique === 'T1190'),
    },
    {
      id: 'T1041',
      name: 'Exfiltration Over C2 Channel',
      tactic: 'Exfiltration',
      description: 'Adversaries may steal data by transferring it over an existing command and control channel.',
      technicalCondition: 'Observed when outbound data transfer bursts exceed 500 KB threshold within 5s window.',
      observedInLab: incidents.some(i => i.mitre_technique === 'T1041'),
    },
    {
      id: 'T1078',
      name: 'Valid Accounts',
      tactic: 'Defense Evasion / Initial Access',
      description: 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining access.',
      technicalCondition: 'Observed when session token is re-used from sudden divergent fingerprint.',
      observedInLab: incidents.some(i => i.mitre_technique === 'T1078'),
    },
  ];

  const activeTech = mitreCatalog.find(t => t.id === selectedTechnique) || mitreCatalog[0];

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded bg-cyan-950 border border-cyan-500/40 text-cyan-400">
            <Radar className="w-4 h-4" />
          </div>
          <div>
            <h1 className="text-sm font-bold font-mono text-slate-100">
              Threat Intelligence & MITRE ATT&CK Matrix
            </h1>
            <p className="text-xs text-slate-400">
              Ground-truth technique alignments and external security subsystem status
            </p>
          </div>
        </div>

        <div className="text-[11px] font-mono text-cyan-400 bg-cyan-950/80 px-2.5 py-1 rounded border border-cyan-800">
          ATT&CK Framework v14 Alignment
        </div>
      </div>

      {/* MITRE ATT&CK Techniques Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <div className="lg:col-span-5 space-y-2">
          <h2 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider mb-2">
            Technique Catalog (Strictly Grounded)
          </h2>
          {mitreCatalog.map(tech => (
            <button
              key={tech.id}
              onClick={() => setSelectedTechnique(tech.id)}
              className={`w-full p-3 rounded-lg border text-left font-mono text-xs transition cursor-pointer ${
                selectedTechnique === tech.id
                  ? 'bg-cyan-950/80 border-cyan-500 text-cyan-200'
                  : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-200">{tech.id} · {tech.name}</span>
                <span className={`text-[10px] px-1.5 py-0.2 rounded ${
                  tech.observedInLab
                    ? 'bg-rose-950 text-rose-300 border border-rose-800'
                    : 'bg-slate-950 text-slate-500 border border-slate-800'
                }`}>
                  {tech.observedInLab ? 'OBSERVED IN LAB' : 'INACTIVE'}
                </span>
              </div>
              <span className="text-[11px] text-slate-500 block mt-1">Tactic: {tech.tactic}</span>
            </button>
          ))}
        </div>

        {/* Selected Technique Details */}
        <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-lg p-5 font-mono text-xs space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <span className="text-cyan-400 font-bold text-base">{activeTech.id} — {activeTech.name}</span>
              <p className="text-slate-400 text-xs">MITRE Tactic: {activeTech.tactic}</p>
            </div>
            <span className={`px-2.5 py-1 rounded text-xs font-bold ${
              activeTech.observedInLab
                ? 'bg-rose-950 text-rose-300 border border-rose-800'
                : 'bg-slate-950 text-slate-400 border border-slate-800'
            }`}>
              {activeTech.observedInLab ? 'Active in Laboratory Incidents' : 'Not Currently Observed'}
            </span>
          </div>

          <div>
            <span className="text-slate-400 font-semibold block mb-1">Technique Overview:</span>
            <p className="text-slate-300 leading-relaxed">{activeTech.description}</p>
          </div>

          <div className="p-3 bg-slate-950 border border-slate-800 rounded">
            <span className="text-cyan-400 font-semibold block mb-1">Strict Triggering Condition:</span>
            <p className="text-slate-300">{activeTech.technicalCondition}</p>
          </div>

          <div className="p-3 bg-slate-950 border border-slate-800 rounded space-y-1">
            <span className="text-slate-500 block text-[10px]">EVIDENCE INTEGRITY STANDARD</span>
            <p className="text-[11px] text-slate-400">
              MAS-CSI maps this technique strictly when the telemetry signature satisfies the hard deterministic threshold. We never declare an attack technique merely because it exists in a reference catalog.
            </p>
          </div>
        </div>
      </div>

      {/* External Subsystems Status (Honest Reporting) */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 font-mono text-xs">
        <div className="flex items-center justify-between mb-3">
          <h2 className="font-bold text-slate-100 flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            External Security Subsystem Connectors
          </h2>
          <span className="text-[11px] text-slate-500">
            Mandate: No simulated connection status. Honest state only.
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {integrations.map(integ => (
            <div key={integ.name} className="p-3 bg-slate-950 border border-slate-800 rounded space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-200">{integ.name}</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-900 text-amber-400 border border-amber-800/40">
                  {integ.status}
                </span>
              </div>
              <span className="text-[10px] text-slate-500 block">Category: {integ.category}</span>
              <p className="text-[11px] text-slate-400 leading-tight">{integ.details}</p>
              {integ.version && (
                <div className="text-[10px] text-cyan-400/80 pt-1 border-t border-slate-900">
                  {integ.version}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
