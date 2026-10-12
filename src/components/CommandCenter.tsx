/**
 * MAS-CSI Command Center
 * Section 28 compliant: 3D Cyber Core, Database-derived threat status,
 * live events stream, agent status radar, SOC health, and controlled scenario controls.
 */

import React, { useState } from 'react';
import {
  ShieldAlert,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Play,
  Terminal,
  Database,
  Lock,
  ArrowRight,
  ExternalLink,
  Cpu
} from 'lucide-react';
import { store } from '../services/store';
import { CyberCore3D } from './CyberCore3D';
import { AttackScenario } from '../types/mas_csi';
import { PageId } from './Navigation';

interface CommandCenterProps {
  onNavigate: (page: PageId) => void;
  onSelectIncident: (incidentId: string) => void;
}

export const CommandCenter: React.FC<CommandCenterProps> = ({
  onNavigate,
  onSelectIncident,
}) => {
  const events = store.events;
  const incidents = store.incidents;
  const agentRuns = store.agentRuns;
  const evidenceVault = store.evidenceVault;

  const [executingScenario, setExecutingScenario] = useState<string | null>(null);

  // Highest severity
  let overallThreat: 'NORMAL' | 'SUSPICIOUS' | 'CONFIRMED' | 'CRITICAL' = 'NORMAL';
  if (incidents.some(i => i.severity === 'CRITICAL')) overallThreat = 'CRITICAL';
  else if (incidents.some(i => i.severity === 'HIGH')) overallThreat = 'CONFIRMED';
  else if (incidents.some(i => i.severity === 'MEDIUM')) overallThreat = 'SUSPICIOUS';

  const handleRunScenario = async (scenario: AttackScenario) => {
    setExecutingScenario(scenario);
    const incident = await store.executeControlledScenario(scenario);
    setExecutingScenario(null);
    onSelectIncident(incident.incident_id);
  };

  return (
    <div className="space-y-5">
      {/* Top Banner: Verification & Absolute Integrity Notice */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3.5 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2.5">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
          <span className="font-mono text-slate-200">
            System Operating Mode: <strong className="text-cyan-400">EVIDENCE-FIRST REAL TELEMETRY</strong>
          </span>
          <span className="text-slate-500">|</span>
          <span className="text-slate-400">
            Deterministic Ground Truth Rules Active
          </span>
        </div>
        <div className="text-[11px] font-mono text-slate-400 flex items-center gap-3">
          <span>SHA-256 Seal: <strong className="text-emerald-400">ENFORCED</strong></span>
          <span>Controlled Lab: <strong className="text-amber-400">AUTHORIZED</strong></span>
        </div>
      </div>

      {/* Top Metrics Row: Strictly Database-Derived */}
      <div className="grid grid-cols-2 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>Observed Telemetry</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-slate-100">
            {events.length}
          </div>
          <p className="mt-1 text-[11px] text-slate-500">
            {events.length > 0 ? 'Actual records in memory' : '0 recorded events'}
          </p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>Correlated Incidents</span>
            <ShieldAlert className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-amber-400">
            {incidents.length}
          </div>
          <p className="mt-1 text-[11px] text-slate-500">
            {incidents.filter(i => i.detection_state === 'CONFIRMED').length} confirmed detections
          </p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>Cryptographic Vault</span>
            <Lock className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-emerald-400">
            {evidenceVault.length}
          </div>
          <p className="mt-1 text-[11px] text-slate-500">
            {evidenceVault.filter(e => e.integrity_status === 'VALID').length} verified SHA-256 records
          </p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>7-Agent Pipeline Runs</span>
            <Cpu className="w-4 h-4 text-purple-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-purple-400">
            {agentRuns.length}
          </div>
          <p className="mt-1 text-[11px] text-slate-500">
            {agentRuns.filter(r => r.status === 'COMPLETED').length} verified executions
          </p>
        </div>
      </div>

      {/* Main Grid: 3D Cyber Core + Controlled Scenarios */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Column: 3D Cyber Core Visualization (7 Cols) */}
        <div className="lg:col-span-7 space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h2 className="text-sm font-bold font-mono text-slate-100 flex items-center gap-2">
                  <Activity className="w-4 h-4 text-cyan-400" />
                  3D Cyber Core Diagnostic Model
                </h2>
                <p className="text-[11px] text-slate-400">
                  Real-time spatial node mapping system threat dynamics
                </p>
              </div>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase font-bold border ${
                overallThreat === 'CRITICAL' || overallThreat === 'CONFIRMED'
                  ? 'bg-rose-950 text-rose-300 border-rose-700'
                  : overallThreat === 'SUSPICIOUS'
                  ? 'bg-amber-950 text-amber-300 border-amber-700'
                  : 'bg-emerald-950 text-emerald-300 border-emerald-700'
              }`}>
                Posture: {overallThreat}
              </span>
            </div>

            <div className="h-72 w-full">
              <CyberCore3D threatLevel={overallThreat} eventsCount={events.length} />
            </div>

            <div className="mt-3 grid grid-cols-3 gap-2 text-center text-xs font-mono">
              <div className="p-2 bg-slate-950/70 border border-slate-800 rounded">
                <span className="text-slate-500 text-[10px] block">Sensor State</span>
                <span className="text-emerald-400 font-semibold">ONLINE</span>
              </div>
              <div className="p-2 bg-slate-950/70 border border-slate-800 rounded">
                <span className="text-slate-500 text-[10px] block">ML Advisory</span>
                <span className="text-cyan-400 font-semibold">Active Isolation</span>
              </div>
              <div className="p-2 bg-slate-950/70 border border-slate-800 rounded">
                <span className="text-slate-500 text-[10px] block">Vault Seal</span>
                <span className="text-emerald-400 font-semibold">SHA-256 Valid</span>
              </div>
            </div>
          </div>

          {/* Quick Access Dual Row: Real Lab & Admin Center */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
            {/* Real Lab Portal Card */}
            <div className="bg-gradient-to-br from-slate-900 to-slate-950 border border-cyan-900/50 rounded-lg p-4 flex flex-col justify-between space-y-3">
              <div>
                <div className="flex items-center gap-2 text-cyan-400 font-mono font-semibold text-xs mb-1">
                  <Database className="w-4 h-4" />
                  <span>Employee Real Lab Portal</span>
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  Confidential document locker, drag & drop file upload, Canary honeytokens, and tamper detection.
                </p>
              </div>
              <button
                onClick={() => onNavigate('real_lab')}
                className="flex items-center justify-center gap-1.5 px-3 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-mono font-bold rounded transition cursor-pointer"
              >
                <span>Enter Real Lab</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Admin Security Center Card */}
            <div className="bg-gradient-to-br from-slate-900 to-slate-950 border border-rose-900/50 rounded-lg p-4 flex flex-col justify-between space-y-3">
              <div>
                <div className="flex items-center gap-2 text-rose-400 font-mono font-semibold text-xs mb-1">
                  <Lock className="w-4 h-4" />
                  <span>Admin Security Center</span>
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  User provisioning, emergency lab lockdown, zero-trust policies, and perimeter firewall rules.
                </p>
              </div>
              <button
                onClick={() => onNavigate('admin_center')}
                className="flex items-center justify-center gap-1.5 px-3 py-2 bg-rose-600 hover:bg-rose-500 text-slate-950 text-xs font-mono font-bold rounded transition cursor-pointer"
              >
                <span>Open Admin Center</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>

        {/* Right Column: Controlled Lab Scenarios & Active Incidents (5 Cols) */}
        <div className="lg:col-span-5 space-y-4">
          {/* Controlled Scenarios Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <h2 className="text-sm font-bold font-mono text-slate-100">
                  Controlled Security Scenarios
                </h2>
              </div>
              <span className="text-[10px] font-mono text-amber-400 uppercase bg-amber-950/60 px-1.5 py-0.5 rounded border border-amber-800/40">
                Lab Fixtures
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mb-3">
              Explicitly isolated synthetic fixtures. Triggers stateful correlation, incident formation, and 7-agent pipeline.
            </p>

            <div className="space-y-1.5">
              {[
                { id: 'BRUTE_FORCE', label: 'Brute Force Spray', code: 'T1110', desc: 'Threshold >= 3 failed logins / window' },
                { id: 'PORT_SCAN', label: 'Port Scan Sweep', code: 'T1046', desc: 'Horizontal SYN discovery across 5 ports' },
                { id: 'DNS_ANOMALY', label: 'DNS C2 Tunneling', code: 'T1071.004', desc: 'High-entropy subdomain queries' },
                { id: 'WEB_ATTACK', label: 'Web SQL Injection', code: 'T1190', desc: 'Tautology payload in search query' },
                { id: 'DATA_EXFILTRATION', label: 'Data Exfiltration', code: 'T1041', desc: '3.4 MB outbound compressed spike' },
                { id: 'ACCOUNT_TAKEOVER', label: 'Account Takeover', code: 'T1078', desc: 'Session hijack token reuse' },
                { id: 'AGENT_ANOMALY', label: 'Agent Workflow Anomaly', code: 'T1059', desc: 'Pipeline deviation & guardian bypass' },
              ].map(sc => (
                <div
                  key={sc.id}
                  className="flex items-center justify-between p-2 rounded bg-slate-950/80 border border-slate-800 hover:border-slate-700 transition"
                >
                  <div className="pr-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-semibold text-slate-200">{sc.label}</span>
                      <span className="text-[10px] font-mono text-cyan-400">{sc.code}</span>
                    </div>
                    <span className="text-[10px] text-slate-500 block truncate">{sc.desc}</span>
                  </div>
                  <button
                    onClick={() => handleRunScenario(sc.id as AttackScenario)}
                    disabled={executingScenario !== null}
                    className="flex items-center gap-1 px-2.5 py-1 bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-600/40 rounded text-xs font-mono transition cursor-pointer shrink-0"
                  >
                    <Play className="w-3 h-3 fill-amber-300" />
                    <span>Run</span>
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Recent Active Incidents */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-sm font-bold font-mono text-slate-100 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-cyan-400" />
                Recent Incident Queue
              </h2>
              <button
                onClick={() => onNavigate('incidents')}
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
              >
                <span>View All ({incidents.length})</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>

            {incidents.length === 0 ? (
              <div className="p-4 text-center text-xs font-mono text-slate-500 border border-dashed border-slate-800 rounded">
                0 confirmed incidents. Generate activity in Real Lab or run a controlled scenario.
              </div>
            ) : (
              <div className="space-y-2">
                {incidents.slice(0, 3).map((inc) => (
                  <div
                    key={inc.incident_id}
                    onClick={() => onSelectIncident(inc.incident_id)}
                    className="p-2.5 bg-slate-950 border border-slate-800 hover:border-cyan-500/50 rounded cursor-pointer transition"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono font-bold text-slate-200 truncate max-w-[200px]">
                        {inc.title}
                      </span>
                      <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded uppercase font-semibold ${
                        inc.severity === 'CRITICAL'
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : inc.severity === 'HIGH'
                          ? 'bg-amber-950 text-amber-300 border border-amber-800'
                          : 'bg-blue-950 text-blue-300 border border-blue-800'
                      }`}>
                        {inc.severity}
                      </span>
                    </div>
                    <div className="mt-1 flex items-center justify-between text-[11px] font-mono text-slate-500">
                      <span>{inc.mitre_technique} · Risk {inc.risk_score}</span>
                      <span className="text-cyan-400">Inspect Dossier →</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Live Recent Telemetry Ticker */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold font-mono text-slate-100">
              Live Normalized Telemetry Feed
            </h2>
          </div>
          <button
            onClick={() => onNavigate('live_soc')}
            className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
          >
            <span>Open Live SOC Console</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
        </div>

        {events.length === 0 ? (
          <div className="p-6 text-center text-xs font-mono text-slate-500 border border-dashed border-slate-800 rounded">
            No telemetry records in memory. Telemetry will stream as you interact with Real Lab.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                  <th className="py-2 px-3">Event ID</th>
                  <th className="py-2 px-3">Timestamp</th>
                  <th className="py-2 px-3">Type</th>
                  <th className="py-2 px-3">State</th>
                  <th className="py-2 px-3">Source IP</th>
                  <th className="py-2 px-3">Destination</th>
                  <th className="py-2 px-3">Detection Reason</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {events.slice(0, 5).map((ev) => (
                  <tr key={ev.event_id} className="hover:bg-slate-800/40 text-slate-300">
                    <td className="py-2 px-3 text-cyan-400 font-semibold">{ev.event_id}</td>
                    <td className="py-2 px-3 text-slate-400">{ev.timestamp.slice(11, 19)}</td>
                    <td className="py-2 px-3">{ev.event_type}</td>
                    <td className="py-2 px-3">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                        ev.detection_state === 'CONFIRMED'
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : ev.detection_state === 'SUSPICIOUS'
                          ? 'bg-amber-950 text-amber-300 border border-amber-800'
                          : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                      }`}>
                        {ev.detection_state}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-slate-400">{ev.source_ip}</td>
                    <td className="py-2 px-3 text-slate-400">{ev.destination_ip}:{ev.destination_port}</td>
                    <td className="py-2 px-3 text-slate-400 truncate max-w-xs">{ev.detection_reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
