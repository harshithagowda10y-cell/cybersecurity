/**
 * MAS-CSI Hack Predictor & Threat Forecasting Engine
 * Analyzes early-stage indicators to predict incoming cyber attacks,
 * forecasts next stage in Cyber Kill Chain, and provides preemptive defenses.
 */

import React, { useState } from 'react';
import {
  TrendingUp,
  AlertTriangle,
  ShieldCheck,
  Zap,
  Activity,
  Layers,
  Clock,
  ArrowRight,
  Crosshair,
  Radar,
  Lock,
  Play
} from 'lucide-react';
import { store } from '../services/store';

export const HackPredictorView: React.FC = () => {
  const prediction = store.calculateThreatPrediction();
  const events = store.events;
  const incidents = store.incidents;

  const [appliedDefenses, setAppliedDefenses] = useState<string[]>([]);
  const [simulationActive, setSimulationActive] = useState<string | null>(null);

  const handleApplyDefense = (rec: string) => {
    setAppliedDefenses(prev => [...prev, rec]);
    store.addAuditLog({
      actor_username: store.currentUser?.username || 'analyst',
      actor_role: 'Security Analyst',
      action: 'PREEMPTIVE_DEFENSE_ENFORCED',
      target: 'Perimeter Protection',
      details: `Enforced proactive defense: ${rec}`,
      ip_address: '127.0.0.1',
      status: 'SUCCESS',
    });
  };

  const handleSimulateIndicator = async (type: 'failed_auth' | 'port_probe' | 'file_tamper') => {
    setSimulationActive(type);
    if (type === 'failed_auth') {
      store.recordTelemetry({
        event_type: 'login_failure',
        severity: 'HIGH',
        message: 'Simulated rapid credential failure on target employee endpoint',
        risk_score: 80,
        detection_state: 'SUSPICIOUS',
        detection_reason: 'Predictive simulation trigger',
        source_ip: '192.168.1.105',
        destination_ip: '127.0.0.1',
        protocol: 'HTTPS',
        source_port: 49201,
        destination_port: 3000,
        username: 'alice_admin',
        device_id: 'DEV-SIM',
        session_id: 'SES-SIM',
        user_agent: 'Simulated Probe',
        request_method: 'POST',
        request_path: '/api/auth/login',
        request_status: 401,
        bytes_in: 290,
        bytes_out: 180,
        city: 'Controlled Lab',
        country: 'Isolated Lab',
        latitude: null,
        longitude: null,
        location_label: 'Data unavailable',
        event_source: 'Hack Predictor Simulator',
        raw_event: '{"simulated": true, "type": "AUTH_SPIKE"}',
        ml_label: 'Credential Spray In-Progress',
        ml_confidence: 0.96,
        ml_anomaly: true,
        evidence_quality: 'HIGH',
        mitre_technique: 'T1110',
        mitre_tactic: 'Credential Access',
      });
    } else if (type === 'port_probe') {
      for (const p of [22, 80, 443, 3306, 8080]) {
        store.recordTelemetry({
          event_type: 'port_probe',
          severity: 'MEDIUM',
          message: `Simulated SYN scan probing internal port ${p}`,
          risk_score: 70,
          detection_state: 'SUSPICIOUS',
          detection_reason: 'Predictive simulation trigger',
          source_ip: '192.168.1.105',
          destination_ip: '127.0.0.1',
          protocol: 'TCP',
          source_port: 51200 + p,
          destination_port: p,
          username: 'unauthenticated',
          device_id: 'DEV-SIM',
          session_id: 'SES-SIM',
          user_agent: 'Simulated Port Scanner',
          request_method: 'SYN',
          request_path: `/port/${p}`,
          request_status: 0,
          bytes_in: 64,
          bytes_out: 64,
          city: 'Controlled Lab',
          country: 'Isolated Lab',
          latitude: null,
          longitude: null,
          location_label: 'Data unavailable',
          event_source: 'Hack Predictor Simulator',
          raw_event: `{"port": ${p}, "simulated": true}`,
          ml_label: 'Host Sweep Scan',
          ml_confidence: 0.94,
          ml_anomaly: true,
          evidence_quality: 'HIGH',
          mitre_technique: 'T1046',
          mitre_tactic: 'Discovery',
        });
      }
    }
    setSimulationActive(null);
  };

  const prob = prediction.overall_threat_probability;
  const isHighRisk = prob >= 65;
  const isMediumRisk = prob >= 35 && prob < 65;

  return (
    <div className="space-y-5 font-mono text-xs">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded bg-cyan-950 border border-cyan-500/40 text-cyan-400">
            <TrendingUp className="w-4 h-4" />
          </div>
          <div>
            <h1 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              Cyber Attack Predictor & Threat Forecaster
              <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                PROACTIVE DEFENSE
              </span>
            </h1>
            <p className="text-slate-400 text-[11px]">
              Multi-signal kinematic analysis forecasting attack trajectory and breach probability
            </p>
          </div>
        </div>

        <div className="text-slate-400 text-xs">
          Engine Confidence: <strong className="text-emerald-400">{Math.round(prediction.confidence_score * 100)}%</strong>
        </div>
      </div>

      {/* Main Threat Probability Gauge & Forecast Banner */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-5">
        {/* Left: Probability Score Card (5 Cols) */}
        <div className="md:col-span-5 bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
          <span className="text-[11px] text-slate-400 font-bold block">
            PREDICTED CYBER ATTACK PROBABILITY
          </span>

          <div className="flex items-baseline gap-3">
            <span className={`text-5xl font-black font-mono tracking-tight ${
              isHighRisk ? 'text-rose-400' : isMediumRisk ? 'text-amber-400' : 'text-emerald-400'
            }`}>
              {prob}%
            </span>
            <span className={`text-xs font-bold uppercase px-2 py-0.5 rounded border ${
              isHighRisk
                ? 'bg-rose-950 text-rose-300 border-rose-800'
                : isMediumRisk
                ? 'bg-amber-950 text-amber-300 border-amber-800'
                : 'bg-emerald-950 text-emerald-300 border-emerald-800'
            }`}>
              {isHighRisk ? 'HIGH RISK' : isMediumRisk ? 'ELEVATED' : 'LOW RISK'}
            </span>
          </div>

          {/* Progress bar */}
          <div className="w-full bg-slate-950 h-3 rounded overflow-hidden border border-slate-800">
            <div
              className={`h-full transition-all duration-500 ${
                isHighRisk ? 'bg-rose-500' : isMediumRisk ? 'bg-amber-500' : 'bg-emerald-500'
              }`}
              style={{ width: `${prob}%` }}
            />
          </div>

          <div className="space-y-2 pt-2 text-[11px] text-slate-400">
            <div className="flex justify-between border-b border-slate-800 pb-1.5">
              <span>Forecasted Kill Chain Stage:</span>
              <strong className="text-cyan-300">{prediction.attack_stage}</strong>
            </div>
            <div className="flex justify-between border-b border-slate-800 pb-1.5">
              <span>Estimated Time to Breach:</span>
              <strong className="text-amber-300">{prediction.estimated_time_to_breach}</strong>
            </div>
            <div className="flex justify-between">
              <span>Projected Threat Vector:</span>
              <strong className="text-slate-200 truncate max-w-[200px]">{prediction.forecasted_incident_type}</strong>
            </div>
          </div>
        </div>

        {/* Right: Attack Trajectory & Kill Chain Progression (7 Cols) */}
        <div className="md:col-span-7 bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
          <h2 className="font-bold text-slate-200 text-sm flex items-center gap-2">
            <Crosshair className="w-4 h-4 text-cyan-400" />
            Cyber Kill Chain Progression Stage
          </h2>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-[11px]">
            {[
              { stage: 'Reconnaissance', desc: 'Port / Service Probing' },
              { stage: 'Initial Access', desc: 'Web Vector Exploits' },
              { stage: 'Credential Stuffing', desc: 'Auth Failure Sequence' },
              { stage: 'Privilege Escalation', desc: 'Role Manipulation' },
              { stage: 'Data Exfiltration', desc: 'File Tampering / Drain' },
              { stage: 'Dormant', desc: 'Normal Baseline' },
            ].map(s => {
              const isActive = prediction.attack_stage === s.stage;
              return (
                <div
                  key={s.stage}
                  className={`p-2.5 rounded border transition ${
                    isActive
                      ? 'bg-rose-950/80 border-rose-500 text-rose-200 shadow-xs'
                      : 'bg-slate-950/60 border-slate-800 text-slate-500'
                  }`}
                >
                  <div className="font-bold truncate">{s.stage}</div>
                  <div className="text-[10px] text-slate-400 mt-0.5">{s.desc}</div>
                  {isActive && (
                    <span className="text-[9px] text-rose-400 font-bold block mt-1">
                      CURRENT STAGE
                    </span>
                  )}
                </div>
              );
            })}
          </div>

          <div className="p-3 bg-slate-950 border border-slate-800 rounded space-y-1.5">
            <span className="text-[10px] text-slate-400 font-bold block">CONTRIBUTING TELEMETRY INDICATORS:</span>
            {prediction.contributing_indicators.map((ind, idx) => (
              <div key={idx} className="flex items-center gap-2 text-[11px] text-slate-300">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 shrink-0" />
                <span>{ind}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Preemptive Defenses & Simulator Controls */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-5">
        {/* Left: Recommended Preemptive Defenses (7 Cols) */}
        <div className="md:col-span-7 bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-3.5">
          <h2 className="font-bold text-slate-200 text-sm flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            Recommended Preemptive Defenses (Stop the Hack Early)
          </h2>
          <p className="text-[11px] text-slate-400">
            Execute proactive defensive measures before malicious activity reaches execution phase:
          </p>

          <div className="space-y-2">
            {prediction.preventative_recommendations.map((rec, idx) => {
              const isApplied = appliedDefenses.includes(rec);
              return (
                <div
                  key={idx}
                  className="p-3 bg-slate-950 border border-slate-800 rounded flex items-center justify-between gap-3"
                >
                  <span className="text-slate-300 text-[11px]">{rec}</span>
                  <button
                    onClick={() => handleApplyDefense(rec)}
                    disabled={isApplied}
                    className={`px-3 py-1 rounded text-[10px] font-bold transition cursor-pointer shrink-0 border ${
                      isApplied
                        ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                        : 'bg-cyan-600 hover:bg-cyan-500 text-slate-950 border-cyan-500'
                    }`}
                  >
                    {isApplied ? 'Enforced ✓' : 'Enforce Defense'}
                  </button>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Threat Signal Simulation Tester (5 Cols) */}
        <div className="md:col-span-5 bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-3.5">
          <h2 className="font-bold text-slate-200 text-sm flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            Attack Signal Simulator
          </h2>
          <p className="text-[11px] text-slate-400">
            Inject early-stage signals to observe how the predictive probability meter and defensive guidance dynamically respond:
          </p>

          <div className="space-y-2">
            <button
              onClick={() => handleSimulateIndicator('failed_auth')}
              disabled={simulationActive !== null}
              className="w-full p-2.5 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-left flex items-center justify-between cursor-pointer transition"
            >
              <div>
                <span className="font-bold text-slate-200 block text-[11px]">Inject Credential Spray Anomaly</span>
                <span className="text-[10px] text-slate-500">Triggers failed auth velocity</span>
              </div>
              <Play className="w-3.5 h-3.5 text-amber-400" />
            </button>

            <button
              onClick={() => handleSimulateIndicator('port_probe')}
              disabled={simulationActive !== null}
              className="w-full p-2.5 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-left flex items-center justify-between cursor-pointer transition"
            >
              <div>
                <span className="font-bold text-slate-200 block text-[11px]">Inject Multi-Port SYN Reconnaissance</span>
                <span className="text-[10px] text-slate-500">Triggers horizontal port discovery</span>
              </div>
              <Play className="w-3.5 h-3.5 text-cyan-400" />
            </button>
          </div>

          <div className="p-2.5 bg-slate-950/80 rounded border border-slate-800 text-[10px] text-slate-500">
            *Predictive algorithms evaluate telemetry patterns in real time without modifying operational baseline configs.
          </div>
        </div>
      </div>
    </div>
  );
};
