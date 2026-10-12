/**
 * MAS-CSI Seven-Agent Pipeline View
 * Detailed interactive inspection of all 7 agent execution stages.
 * Supports on-demand execution and live step-by-step progress tracking.
 */

import React, { useState } from 'react';
import {
  Cpu,
  Activity,
  Layers,
  Search,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  Shield,
  FileText,
  Clock,
  Radio,
  Network,
  Play,
  RefreshCw,
  Sparkles
} from 'lucide-react';
import { store } from '../services/store';
import { AgentRun } from '../types/mas_csi';

export const AIAgentsView: React.FC = () => {
  const agentRuns = store.agentRuns;
  const incidents = store.incidents;

  const [selectedAgentId, setSelectedAgentId] = useState<string>('all');
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>('all');
  const [isRunningPipeline, setIsRunningPipeline] = useState(false);
  const [activeStep, setActiveStep] = useState<number | null>(null);

  const filteredRuns = agentRuns.filter(r => {
    const matchesAgent = selectedAgentId === 'all' || r.agent_id === selectedAgentId;
    const matchesIncident = selectedIncidentId === 'all' || r.incident_id === selectedIncidentId;
    return matchesAgent && matchesIncident;
  });

  const agentDefinitions = [
    { id: 'monitor', name: 'Agent 1 — Monitor', icon: Radio, desc: 'Collect and normalize raw telemetry stream' },
    { id: 'analyzer', name: 'Agent 2 — Analyzer', icon: Activity, desc: 'Evaluate deterministic rules and ML advisory signals' },
    { id: 'investigator', name: 'Agent 3 — Investigator', icon: Network, desc: 'Correlate User, Device, Session, IP, Geolocation' },
    { id: 'threat_intel', name: 'Agent 4 — Threat Intelligence', icon: Search, desc: 'Align MITRE ATT&CK techniques & threat context' },
    { id: 'forensic', name: 'Agent 5 — Forensic', icon: Clock, desc: 'Construct timeline & seal SHA-256 evidence vault' },
    { id: 'guardian', name: 'Agent 6 — Guardian', icon: Shield, desc: 'Evaluate safe controlled containment boundaries' },
    { id: 'reporter', name: 'Agent 7 — Reporter', icon: FileText, desc: 'Synthesize investigation dossiers, JSON, and PDF' },
  ];

  // Interactive Live Execution of the 7-Agent Pipeline
  const handleRunPipelineLive = async () => {
    setIsRunningPipeline(true);
    setActiveStep(1);

    // Simulate animated step-by-step sequence through the 7 stages
    for (let step = 1; step <= 7; step++) {
      setActiveStep(step);
      await new Promise(resolve => setTimeout(resolve, 350));
    }

    // Execute scenario to add concrete records
    await store.executeControlledScenario('BRUTE_FORCE');
    setIsRunningPipeline(false);
    setActiveStep(null);
  };

  return (
    <div className="space-y-5 font-mono text-xs">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded bg-purple-950 border border-purple-500/40 text-purple-400">
            <Cpu className="w-4 h-4" />
          </div>
          <div>
            <h1 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              Seven-Agent Multi-Stage Investigation Pipeline
              <span className="text-[10px] px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800">
                SEQUENTIAL ORCHESTRATION
              </span>
            </h1>
            <p className="text-slate-400 text-[11px]">
              Deterministic, evidence-driven multi-agent orchestration for cyber threat forensics
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleRunPipelineLive}
            disabled={isRunningPipeline}
            className="px-3.5 py-1.5 bg-purple-600 hover:bg-purple-500 disabled:bg-slate-800 text-slate-950 font-bold rounded flex items-center gap-1.5 cursor-pointer transition shadow-xs"
          >
            {isRunningPipeline ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Play className="w-3.5 h-3.5 fill-slate-950" />
            )}
            <span>{isRunningPipeline ? `Agent ${activeStep} Executing...` : 'Run 7-Agent Pipeline Live'}</span>
          </button>
        </div>
      </div>

      {/* Pipeline Visual Flow Ribbon */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
        <h2 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center justify-between">
          <span>Sequential Agent Execution Architecture</span>
          <span className="text-purple-400 text-[11px]">100% Deterministic Guarantee</span>
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2">
          {agentDefinitions.map((ag, idx) => {
            const Icon = ag.icon;
            const runCount = agentRuns.filter(r => r.agent_id === ag.id).length;
            const isFilterActive = selectedAgentId === ag.id;
            const isCurrentlyStep = activeStep === idx + 1;

            return (
              <button
                key={ag.id}
                onClick={() => setSelectedAgentId(isFilterActive ? 'all' : ag.id)}
                className={`p-2.5 rounded border text-left transition cursor-pointer flex flex-col justify-between ${
                  isCurrentlyStep
                    ? 'bg-purple-600 text-slate-950 border-white ring-2 ring-purple-400 animate-pulse'
                    : isFilterActive
                    ? 'bg-purple-950/80 border-purple-500 text-purple-200'
                    : 'bg-slate-950/80 border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <Icon className={`w-4 h-4 ${isCurrentlyStep ? 'text-slate-950' : 'text-purple-400'}`} />
                    <span className={`text-[10px] px-1 py-0.2 rounded ${isCurrentlyStep ? 'bg-slate-950 text-white' : 'bg-slate-900 text-slate-300'}`}>
                      Step {idx + 1}
                    </span>
                  </div>
                  <div className={`text-xs font-bold truncate ${isCurrentlyStep ? 'text-slate-950' : 'text-slate-200'}`}>
                    {ag.name.replace('Agent ', 'A')}
                  </div>
                </div>
                <div className={`mt-2 pt-1 border-t text-[10px] flex items-center justify-between ${isCurrentlyStep ? 'border-purple-700 text-slate-900' : 'border-slate-900 text-slate-500'}`}>
                  <span>Executions</span>
                  <span className={`font-bold ${isCurrentlyStep ? 'text-slate-950' : 'text-cyan-400'}`}>{runCount}</span>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Filter by incident */}
      <div className="flex items-center justify-between bg-slate-900 border border-slate-800 rounded-lg p-3">
        <div className="flex items-center gap-2">
          <span className="text-slate-400">Scope Filter:</span>
          <select
            value={selectedIncidentId}
            onChange={(e) => setSelectedIncidentId(e.target.value)}
            className="bg-slate-950 text-slate-200 border border-slate-800 rounded px-2.5 py-1 focus:outline-none focus:border-purple-500 cursor-pointer"
          >
            <option value="all">All Incidents ({incidents.length})</option>
            {incidents.map(i => (
              <option key={i.incident_id} value={i.incident_id}>
                {i.incident_id} — {i.title.slice(0, 36)}...
              </option>
            ))}
          </select>
        </div>

        <div className="text-slate-500">
          Showing {filteredRuns.length} of {agentRuns.length} verified executions
        </div>
      </div>

      {/* Agent Execution Logs Feed */}
      <div className="space-y-3">
        {filteredRuns.length === 0 ? (
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-10 text-center text-slate-500 space-y-2">
            <p>0 agent execution runs recorded in active memory.</p>
            <p className="text-slate-600">
              Click <strong>"Run 7-Agent Pipeline Live"</strong> above or trigger authentication failures in Real Lab to initiate the pipeline.
            </p>
          </div>
        ) : (
          filteredRuns.map((run) => (
            <div
              key={run.run_id}
              className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-2.5 hover:border-slate-700 transition"
            >
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
                <div className="flex items-center gap-2.5">
                  <span className="font-bold text-purple-400 text-sm">{run.agent_name}</span>
                  <span className="text-[10px] bg-slate-950 px-2 py-0.5 rounded border border-slate-800 text-slate-400">
                    Run ID: {run.run_id}
                  </span>
                  <span className="text-[10px] bg-cyan-950 text-cyan-300 px-2 py-0.5 rounded border border-cyan-800">
                    Incident: {run.incident_id}
                  </span>
                </div>
                <div className="flex items-center gap-2 text-[11px]">
                  <span className="text-emerald-400 font-semibold flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    {run.status}
                  </span>
                  <span className="text-slate-500">({run.timestamp})</span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
                <div className="p-2.5 bg-slate-950 border border-slate-800/80 rounded">
                  <span className="text-slate-500 block text-[10px] mb-1">TASK OBJECTIVE</span>
                  <p className="text-slate-300">{run.task}</p>
                </div>
                <div className="p-2.5 bg-slate-950 border border-slate-800/80 rounded">
                  <span className="text-slate-500 block text-[10px] mb-1">NORMALIZED INPUT</span>
                  <p className="text-slate-300 truncate">{run.input}</p>
                </div>
              </div>

              <div className="p-2.5 bg-slate-950 border border-slate-800/80 rounded text-[11px]">
                <span className="text-slate-500 block text-[10px] mb-1">OUTPUT ANALYSIS</span>
                <p className="text-slate-300">{run.output}</p>
              </div>

              <div className="p-2.5 bg-purple-950/30 border border-purple-800/40 rounded text-[11px] flex items-center justify-between">
                <div>
                  <span className="text-purple-400 font-semibold block text-[10px]">DECISION & DISPATCH</span>
                  <p className="text-slate-200">{run.decision}</p>
                </div>
                <span className="text-[10px] text-purple-300 shrink-0">
                  Confidence: {Math.round(run.confidence * 100)}%
                </span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
