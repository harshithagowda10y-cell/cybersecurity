/**
 * MAS-CSI Live SOC Console
 * Real-time event inspection, stream controls, detection state breakdown,
 * and endpoint health telemetry. No fabricated counters.
 */

import React, { useState } from 'react';
import {
  Radio,
  Filter,
  Play,
  Pause,
  Eye,
  Server,
  ShieldCheck,
  Cpu,
  RefreshCw,
  Search,
  X
} from 'lucide-react';
import { store } from '../services/store';
import { TelemetryEvent, DetectionState } from '../types/mas_csi';

export const LiveSOC: React.FC = () => {
  const events = store.events;
  const incidents = store.incidents;

  const [stateFilter, setStateFilter] = useState<DetectionState | 'ALL'>('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedEvent, setSelectedEvent] = useState<TelemetryEvent | null>(null);
  const [isPaused, setIsPaused] = useState(false);

  const filteredEvents = events.filter((ev) => {
    const matchesState = stateFilter === 'ALL' || ev.detection_state === stateFilter;
    const matchesSearch =
      searchTerm === '' ||
      ev.event_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ev.event_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ev.source_ip.includes(searchTerm) ||
      ev.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ev.username.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesState && matchesSearch;
  });

  const stateCounts = {
    NORMAL: events.filter(e => e.detection_state === 'NORMAL').length,
    SUSPICIOUS: events.filter(e => e.detection_state === 'SUSPICIOUS').length,
    CONFIRMED: events.filter(e => e.detection_state === 'CONFIRMED').length,
    ABSTAINED: events.filter(e => e.detection_state === 'ABSTAINED').length,
  };

  return (
    <div className="space-y-5">
      {/* SOC Status Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded bg-cyan-950 border border-cyan-500/40 text-cyan-400">
            <Radio className="w-4 h-4 animate-pulse" />
          </div>
          <div>
            <h1 className="text-sm font-bold font-mono text-slate-100">
              Live SOC Telemetry Stream
            </h1>
            <p className="text-xs text-slate-400">
              Observed telemetry stream with deterministic detection evaluation
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono font-semibold transition cursor-pointer border ${
              isPaused
                ? 'bg-amber-950 text-amber-300 border-amber-700'
                : 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700'
            }`}
          >
            {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            <span>{isPaused ? 'Stream Paused' : 'Live Stream'}</span>
          </button>
        </div>
      </div>

      {/* Detection State Breakdown Filter Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
        <button
          onClick={() => setStateFilter(stateFilter === 'NORMAL' ? 'ALL' : 'NORMAL')}
          className={`p-3 rounded-lg border text-left transition cursor-pointer ${
            stateFilter === 'NORMAL'
              ? 'bg-emerald-950/80 border-emerald-500 text-emerald-300'
              : 'bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="font-semibold">NORMAL</span>
            <span className="text-emerald-400 text-sm font-bold">{stateCounts.NORMAL}</span>
          </div>
          <p className="text-[10px] text-slate-500 mt-1">No malicious signature</p>
        </button>

        <button
          onClick={() => setStateFilter(stateFilter === 'SUSPICIOUS' ? 'ALL' : 'SUSPICIOUS')}
          className={`p-3 rounded-lg border text-left transition cursor-pointer ${
            stateFilter === 'SUSPICIOUS'
              ? 'bg-amber-950/80 border-amber-500 text-amber-300'
              : 'bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="font-semibold">SUSPICIOUS</span>
            <span className="text-amber-400 text-sm font-bold">{stateCounts.SUSPICIOUS}</span>
          </div>
          <p className="text-[10px] text-slate-500 mt-1">Requires investigation</p>
        </button>

        <button
          onClick={() => setStateFilter(stateFilter === 'CONFIRMED' ? 'ALL' : 'CONFIRMED')}
          className={`p-3 rounded-lg border text-left transition cursor-pointer ${
            stateFilter === 'CONFIRMED'
              ? 'bg-rose-950/80 border-rose-500 text-rose-300'
              : 'bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="font-semibold">CONFIRMED</span>
            <span className="text-rose-400 text-sm font-bold">{stateCounts.CONFIRMED}</span>
          </div>
          <p className="text-[10px] text-slate-500 mt-1">Ground truth verified</p>
        </button>

        <button
          onClick={() => setStateFilter(stateFilter === 'ABSTAINED' ? 'ALL' : 'ABSTAINED')}
          className={`p-3 rounded-lg border text-left transition cursor-pointer ${
            stateFilter === 'ABSTAINED'
              ? 'bg-purple-950/80 border-purple-500 text-purple-300'
              : 'bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="font-semibold">ABSTAINED</span>
            <span className="text-purple-400 text-sm font-bold">{stateCounts.ABSTAINED}</span>
          </div>
          <p className="text-[10px] text-slate-500 mt-1">Insufficient evidence</p>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 flex flex-wrap items-center justify-between gap-3">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search by event ID, IP, username, type, or payload..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded pl-9 pr-3 py-1.5 text-xs font-mono text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
        <div className="text-xs font-mono text-slate-400">
          Showing {filteredEvents.length} of {events.length} observed events
        </div>
      </div>

      {/* Events Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        {filteredEvents.length === 0 ? (
          <div className="p-10 text-center text-xs font-mono text-slate-500">
            {events.length === 0
              ? '0 telemetry events observed. Generate activity in Real Lab or run a controlled scenario.'
              : 'No events match the current filter criteria.'}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 text-[11px]">
                  <th className="py-2.5 px-3">Event ID</th>
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">State</th>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">Source & Port</th>
                  <th className="py-2.5 px-3">Destination</th>
                  <th className="py-2.5 px-3">User</th>
                  <th className="py-2.5 px-3">ML Advisory</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredEvents.map((ev) => (
                  <tr key={ev.event_id} className="hover:bg-slate-800/40 text-slate-300 transition">
                    <td className="py-2.5 px-3 text-cyan-400 font-semibold">{ev.event_id}</td>
                    <td className="py-2.5 px-3 text-slate-400">{ev.timestamp.slice(11, 19)}</td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                        ev.detection_state === 'CONFIRMED'
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : ev.detection_state === 'SUSPICIOUS'
                          ? 'bg-amber-950 text-amber-300 border border-amber-800'
                          : ev.detection_state === 'ABSTAINED'
                          ? 'bg-purple-950 text-purple-300 border border-purple-800'
                          : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                      }`}>
                        {ev.detection_state}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-medium text-slate-200">{ev.event_type}</td>
                    <td className="py-2.5 px-3 text-slate-400">
                      {ev.source_ip}:{ev.source_port}
                    </td>
                    <td className="py-2.5 px-3 text-slate-400">
                      {ev.destination_ip}:{ev.destination_port} ({ev.protocol})
                    </td>
                    <td className="py-2.5 px-3 text-slate-300">{ev.username}</td>
                    <td className="py-2.5 px-3 text-[11px] text-slate-400">
                      <span className="text-cyan-400 font-semibold">{ev.ml_label}</span>
                      <span className="text-slate-500"> ({Math.round(ev.ml_confidence * 100)}%)</span>
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={() => setSelectedEvent(ev)}
                        className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-[11px] font-mono cursor-pointer transition"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Inspect Event Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-xs p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-2xl w-full p-5 text-slate-100 shadow-2xl relative font-mono text-xs">
            <button
              onClick={() => setSelectedEvent(null)}
              className="absolute top-4 right-4 text-slate-400 hover:text-slate-200 cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>

            <h2 className="text-sm font-bold text-cyan-400 mb-3 flex items-center gap-2">
              <Eye className="w-4 h-4" />
              Telemetry Event Inspection: {selectedEvent.event_id}
            </h2>

            <div className="grid grid-cols-2 gap-3 mb-4 p-3 bg-slate-950 border border-slate-800 rounded">
              <div>
                <span className="text-slate-500 block">Event Type</span>
                <span className="text-slate-200">{selectedEvent.event_type}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Detection State</span>
                <span className="text-rose-400 font-bold">{selectedEvent.detection_state}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Source Endpoint</span>
                <span className="text-slate-200">{selectedEvent.source_ip}:{selectedEvent.source_port}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Destination Endpoint</span>
                <span className="text-slate-200">{selectedEvent.destination_ip}:{selectedEvent.destination_port}</span>
              </div>
              <div>
                <span className="text-slate-500 block">User & Session</span>
                <span className="text-slate-200">{selectedEvent.username} ({selectedEvent.session_id})</span>
              </div>
              <div>
                <span className="text-slate-500 block">Location Telemetry</span>
                <span className="text-slate-200">
                  {selectedEvent.latitude && selectedEvent.longitude
                    ? `${selectedEvent.latitude.toFixed(4)}, ${selectedEvent.longitude.toFixed(4)}`
                    : 'Data unavailable'}
                </span>
              </div>
            </div>

            <div className="mb-3">
              <span className="text-slate-400 font-semibold block mb-1">Deterministic Reason:</span>
              <div className="p-2.5 bg-slate-950 border border-slate-800 rounded text-slate-300">
                {selectedEvent.detection_reason}
              </div>
            </div>

            <div className="mb-3">
              <span className="text-slate-400 font-semibold block mb-1">Raw Payload Event:</span>
              <pre className="p-2.5 bg-slate-950 border border-slate-800 rounded text-slate-400 overflow-x-auto text-[11px]">
                {selectedEvent.raw_event}
              </pre>
            </div>

            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => setSelectedEvent(null)}
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
