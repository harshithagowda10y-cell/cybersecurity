/**
 * MAS-CSI Incidents View
 * List and filter correlated incidents with honest attribution and MITRE alignments.
 */

import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  ExternalLink
} from 'lucide-react';
import { store } from '../services/store';
import { Incident, IncidentStatus } from '../types/mas_csi';

interface IncidentsViewProps {
  onSelectIncident: (incidentId: string) => void;
}

export const IncidentsView: React.FC<IncidentsViewProps> = ({ onSelectIncident }) => {
  const incidents = store.incidents;
  const [statusFilter, setStatusFilter] = useState<IncidentStatus | 'ALL'>('ALL');
  const [search, setSearch] = useState('');

  const filtered = incidents.filter(i => {
    const matchesStatus = statusFilter === 'ALL' || i.status === statusFilter;
    const matchesSearch =
      search === '' ||
      i.title.toLowerCase().includes(search.toLowerCase()) ||
      i.incident_id.toLowerCase().includes(search.toLowerCase()) ||
      i.attack_type.toLowerCase().includes(search.toLowerCase()) ||
      i.mitre_technique.toLowerCase().includes(search.toLowerCase()) ||
      i.source_ip.includes(search);
    return matchesStatus && matchesSearch;
  });

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded bg-amber-950 border border-amber-500/40 text-amber-400">
            <ShieldAlert className="w-4 h-4" />
          </div>
          <div>
            <h1 className="text-sm font-bold font-mono text-slate-100">
              Correlated Security Incidents Queue
            </h1>
            <p className="text-xs text-slate-400">
              Evidence-grounded stateful detections with 7-agent automated investigation
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-400">
            Total Correlated: <strong className="text-cyan-400">{incidents.length}</strong>
          </span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search by title, ID, MITRE technique, or source IP..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded pl-9 pr-3 py-1.5 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Status Filter buttons */}
        <div className="flex items-center gap-1.5 flex-wrap">
          {(['ALL', 'NEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'] as const).map(st => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-2.5 py-1 rounded text-[11px] font-semibold transition cursor-pointer border ${
                statusFilter === st
                  ? 'bg-cyan-950 text-cyan-300 border-cyan-500'
                  : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Incidents Table / Cards */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        {filtered.length === 0 ? (
          <div className="p-12 text-center text-xs font-mono text-slate-500 space-y-2">
            <p>0 incidents match the selected criteria.</p>
            <p className="text-slate-600">
              Use the top "Controlled Scenario" dropdown or generate authentication storms in Real Lab to trigger detection.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 text-[11px]">
                  <th className="py-2.5 px-3">Incident ID</th>
                  <th className="py-2.5 px-3">Title & Attack Type</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Risk</th>
                  <th className="py-2.5 px-3">Technique</th>
                  <th className="py-2.5 px-3">Source IP</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filtered.map((inc) => (
                  <tr
                    key={inc.incident_id}
                    onClick={() => onSelectIncident(inc.incident_id)}
                    className="hover:bg-slate-800/40 text-slate-300 cursor-pointer transition"
                  >
                    <td className="py-3 px-3 font-semibold text-cyan-400">
                      {inc.incident_id}
                    </td>
                    <td className="py-3 px-3">
                      <div className="font-bold text-slate-100">{inc.title}</div>
                      <span className="text-[11px] text-slate-400">{inc.attack_type}</span>
                    </td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        inc.severity === 'CRITICAL'
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : inc.severity === 'HIGH'
                          ? 'bg-amber-950 text-amber-300 border border-amber-800'
                          : 'bg-blue-950 text-blue-300 border border-blue-800'
                      }`}>
                        {inc.severity}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <span className="font-bold text-amber-400">{inc.risk_score}</span>
                      <span className="text-slate-500">/100</span>
                    </td>
                    <td className="py-3 px-3">
                      <span className="text-cyan-400 font-semibold">{inc.mitre_technique}</span>
                      <div className="text-[10px] text-slate-500">{inc.mitre_tactic}</div>
                    </td>
                    <td className="py-3 px-3 text-slate-400">
                      {inc.source_ip}
                    </td>
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-slate-950 border border-slate-700 text-slate-300 font-semibold">
                        {inc.status}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectIncident(inc.incident_id);
                        }}
                        className="px-2.5 py-1 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-700/50 rounded text-[11px] font-mono cursor-pointer transition"
                      >
                        Investigate Dossier →
                      </button>
                    </td>
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
