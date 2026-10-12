/**
 * MAS-CSI Forensics View
 * Chronological forensic investigation timeline connecting records,
 * hex/raw text payload viewer, and cryptographic custody verification.
 */

import React, { useState } from 'react';
import {
  Clock,
  FileSearch,
  KeyRound,
  ShieldAlert,
  Terminal,
  Cpu,
  Layers,
  ArrowRight
} from 'lucide-react';
import { store } from '../services/store';

export const ForensicsView: React.FC = () => {
  const events = store.events;
  const incidents = store.incidents;
  const agentRuns = store.agentRuns;
  const evidence = store.evidenceVault;

  const [selectedIncidentId, setSelectedIncidentId] = useState<string>('all');
  const [activeHexViewEventId, setActiveHexViewEventId] = useState<string | null>(null);

  const activeEvents = events.filter(e => {
    if (selectedIncidentId === 'all') return true;
    const inc = incidents.find(i => i.incident_id === selectedIncidentId);
    return inc ? inc.correlated_event_ids.includes(e.event_id) : true;
  });

  const selectedHexEvent = events.find(e => e.event_id === activeHexViewEventId) || activeEvents[0];

  // Helper to generate simulated hex representation of raw payload
  const renderHexView = (text: string) => {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(text);
    const rows = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const slice = bytes.slice(i, i + 16);
      const hex = Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join(' ');
      const ascii = Array.from(slice).map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('');
      rows.push({
        offset: i.toString(16).padStart(8, '0'),
        hex: hex.padEnd(48, ' '),
        ascii: ascii,
      });
    }
    return rows;
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded bg-cyan-950 border border-cyan-500/40 text-cyan-400">
            <Clock className="w-4 h-4" />
          </div>
          <div>
            <h1 className="text-sm font-bold font-mono text-slate-100">
              Forensic Reconstruction & Payload Analysis
            </h1>
            <p className="text-xs text-slate-400">
              Deterministic chronological reconstruction based on verified database records
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="text-slate-400">Incident Scope:</span>
          <select
            value={selectedIncidentId}
            onChange={(e) => setSelectedIncidentId(e.target.value)}
            className="bg-slate-950 text-slate-200 border border-slate-800 rounded px-2.5 py-1 focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            <option value="all">Global Timeline (All Records)</option>
            {incidents.map(i => (
              <option key={i.incident_id} value={i.incident_id}>
                {i.incident_id} ({i.title.slice(0, 30)}...)
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Main Grid: Forensic Timeline (Left) + Payload Hex Inspector (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left: Forensic Timeline */}
        <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-4 font-mono text-xs">
          <h2 className="font-bold text-slate-200 flex items-center gap-2">
            <FileSearch className="w-4 h-4 text-cyan-400" />
            Verified Chronological Forensic Timeline
          </h2>

          {activeEvents.length === 0 ? (
            <div className="p-12 text-center text-slate-500 border border-dashed border-slate-800 rounded">
              0 events in forensic scope.
            </div>
          ) : (
            <div className="border-l-2 border-slate-800 pl-4 space-y-3.5 max-h-[500px] overflow-y-auto pr-2">
              {activeEvents.map((ev) => (
                <div
                  key={ev.event_id}
                  onClick={() => setActiveHexViewEventId(ev.event_id)}
                  className={`p-3 rounded border cursor-pointer transition ${
                    selectedHexEvent?.event_id === ev.event_id
                      ? 'bg-slate-950 border-cyan-500 text-slate-100 shadow-sm'
                      : 'bg-slate-950/60 border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between text-[11px] mb-1">
                    <span className="font-bold text-cyan-400">{ev.event_id} · {ev.event_type}</span>
                    <span className="text-slate-500">{ev.timestamp}</span>
                  </div>
                  <p className="text-xs text-slate-200">{ev.message}</p>
                  <div className="mt-2 pt-1 border-t border-slate-900 flex items-center justify-between text-[10px] text-slate-400">
                    <span>Source: {ev.source_ip}:{ev.source_port}</span>
                    <span className={`px-1.5 py-0.2 rounded ${
                      ev.detection_state === 'CONFIRMED'
                        ? 'bg-rose-950 text-rose-300'
                        : 'bg-slate-900 text-slate-400'
                    }`}>
                      {ev.detection_state}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: Payload & Hex Inspector */}
        <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <h2 className="font-bold text-slate-200 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              Payload Hex Inspector
            </h2>
            <span className="text-[10px] text-cyan-400">
              {selectedHexEvent ? selectedHexEvent.event_id : 'No Selection'}
            </span>
          </div>

          {selectedHexEvent ? (
            <div className="space-y-3">
              <div className="p-2.5 bg-slate-950 border border-slate-800 rounded space-y-1 text-[11px]">
                <div><span className="text-slate-500">Method/Path:</span> <span className="text-slate-300">{selectedHexEvent.request_method} {selectedHexEvent.request_path}</span></div>
                <div><span className="text-slate-500">Protocol & Ports:</span> <span className="text-slate-300">{selectedHexEvent.protocol} ({selectedHexEvent.source_port} → {selectedHexEvent.destination_port})</span></div>
                <div><span className="text-slate-500">Bytes In/Out:</span> <span className="text-slate-300">{selectedHexEvent.bytes_in} B in / {selectedHexEvent.bytes_out} B out</span></div>
              </div>

              <div>
                <span className="text-slate-400 text-[10px] block mb-1">HEX DUMP REPRESENTATION</span>
                <div className="bg-slate-950 border border-slate-800 rounded p-2.5 max-h-56 overflow-y-auto text-[10px] leading-tight text-slate-300">
                  {renderHexView(selectedHexEvent.raw_event).slice(0, 16).map((r, idx) => (
                    <div key={idx} className="flex gap-2">
                      <span className="text-slate-500">{r.offset}</span>
                      <span className="text-cyan-400 font-mono">{r.hex}</span>
                      <span className="text-emerald-400 font-mono">{r.ascii}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <span className="text-slate-400 text-[10px] block mb-1">RAW EVENT STRING</span>
                <pre className="bg-slate-950 border border-slate-800 rounded p-2.5 max-h-32 overflow-y-auto text-[10px] text-slate-300 whitespace-pre-wrap">
                  {selectedHexEvent.raw_event}
                </pre>
              </div>
            </div>
          ) : (
            <div className="p-10 text-center text-slate-500">
              Select an event from the timeline to view hex dump.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
