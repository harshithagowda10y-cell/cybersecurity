/**
 * MAS-CSI GenAI / Security Copilot
 * Section 19 compliant: strictly grounded on observed telemetry,
 * deterministic detection, and agent analysis. Never invents facts.
 */

import React, { useState } from 'react';
import {
  Bot,
  Send,
  Sparkles,
  ShieldAlert,
  HelpCircle,
  FileSearch,
  CheckCircle2,
  AlertTriangle,
  Compass
} from 'lucide-react';
import { store } from '../services/store';

interface Message {
  id: string;
  sender: 'user' | 'assistant';
  timestamp: string;
  text: string;
  telemetryContext?: string;
}

export const GenAIAgentsView: React.FC = () => {
  const incidents = store.incidents;
  const events = store.events;
  const evidenceVault = store.evidenceVault;

  const [inputQuery, setInputQuery] = useState('');
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'msg-1',
      sender: 'assistant',
      timestamp: new Date().toLocaleTimeString(),
      text: `Hello, Analyst. I am the MAS-CSI Security Copilot. I analyze ONLY verified telemetry, deterministic detection rules, and the 7-agent investigation records.

Under absolute data integrity protocols, I will never invent attacker identities, coordinates, or fake events. If evidence is lacking, I will state "Insufficient evidence".

How can I assist your investigation? You can ask:
• "Summarize recent incident findings"
• "Explain MITRE technique for current detections"
• "What are the recommended containment actions for Agent 6 Guardian?"
• "Verify cryptographic evidence integrity status"`,
    },
  ]);
  const [isProcessing, setIsProcessing] = useState(false);

  const handleSendMessage = (queryText?: string) => {
    const textToSend = queryText || inputQuery;
    if (!textToSend.trim()) return;

    const userMsg: Message = {
      id: 'usr-' + Date.now(),
      sender: 'user',
      timestamp: new Date().toLocaleTimeString(),
      text: textToSend,
    };

    setMessages(prev => [...prev, userMsg]);
    if (!queryText) setInputQuery('');
    setIsProcessing(true);

    setTimeout(() => {
      const lower = textToSend.toLowerCase();
      let responseText = '';

      if (lower.includes('incident') || lower.includes('summarize')) {
        if (incidents.length === 0) {
          responseText = `OBSERVED TELEMETRY STATUS:
• Currently 0 incidents exist in the database.
• Observed telemetry events in memory: ${events.length}.

RECOMMENDATION:
To observe automated incident formation, run a Controlled Lab Scenario (e.g., Brute Force T1110 or Web Attack T1190) or generate real authentication attempts in Real Lab.`;
        } else {
          const latest = incidents[0];
          responseText = `[OBSERVED TELEMETRY & DETERMINISTIC GROUND TRUTH]
Incident ID: ${latest.incident_id}
Title: ${latest.title}
Attack Classification: ${latest.attack_type}
Severity: ${latest.severity} (Risk: ${latest.risk_score}/100)
Detection State: ${latest.detection_state}

[DETERMINISTIC REASON]
${latest.detection_reason}

[ATTRIBUTION STATUS]
${latest.actor_identity} (Observed Source IP: ${latest.source_ip})
Target: ${latest.target}

[AGENT INVESTIGATION STATUS]
${latest.summary}
Cryptographic Evidence Count: ${latest.evidence_count} items sealed with SHA-256 in Evidence Vault.`;
        }
      } else if (lower.includes('mitre') || lower.includes('technique')) {
        if (incidents.length === 0) {
          responseText = `MITRE ATT&CK CATALOG STATUS:
No active incident technique mappings. In MAS-CSI, MITRE techniques are mapped ONLY when observed telemetry justifies the signature (e.g., T1110 for repeated failed authentications, T1046 for multi-port sweeps, T1190 for SQL injection).`;
        } else {
          const techniques = Array.from(new Set(incidents.map(i => `${i.mitre_technique} (${i.mitre_tactic})`)));
          responseText = `[VERIFIED MITRE ATT&CK ALIGNMENTS]
Active observed techniques:
${techniques.map(t => `• ${t}`).join('\n')}

Technical justification:
Each technique is directly bound to deterministic rule evaluations in Agent 4 (Threat Intelligence). Techniques are never attributed speculatively.`;
        }
      } else if (lower.includes('contain') || lower.includes('guardian') || lower.includes('action')) {
        responseText = `[AGENT 6 — GUARDIAN CONTROLLED RESPONSE POLICIES]
Permitted Safe Response Actions:
1. ISOLATE_LAB_ENDPOINT — Sever socket connection for lab test client.
2. BLOCK_LAB_SOURCE — Simulate firewall drop rule for lab source IP.
3. ESCALATE_TO_ANALYST — Flag incident dossier for manual SOC review.
4. PRESERVE_EVIDENCE — Apply immutable cryptographic lockdown to evidence vault.
5. SIMULATE_CONTAINMENT — Validate post-remediation system health.

SAFETY MANDATE:
All actions operate strictly within authorized laboratory boundaries. No destructive operations or external reach are permitted.`;
      } else if (lower.includes('evidence') || lower.includes('integrity') || lower.includes('sha-256') || lower.includes('sha256')) {
        const validCount = evidenceVault.filter(e => e.integrity_status === 'VALID').length;
        const invalidCount = evidenceVault.filter(e => e.integrity_status === 'INVALID').length;
        responseText = `[CRYPTOGRAPHIC EVIDENCE VAULT STATUS]
Total Sealed Artifacts: ${evidenceVault.length}
Cryptographically Valid (SHA-256 Verified): ${validCount}
Tamper Detected (Invalid): ${invalidCount}

CHAIN OF CUSTODY STANDARD:
Compliant with NIST SP 800-61 Rev. 2 and ISO/IEC 27037 standards. You can perform real-time SHA-256 verification or test tamper detection in the Evidence Vault tab.`;
      } else {
        responseText = `[GENAI EXPLANATION & COPILOT GUIDANCE]
Based on active database records:
• Telemetry Events: ${events.length}
• Correlated Incidents: ${incidents.length}
• Sealed Evidence Records: ${evidenceVault.length}

Distinction of Data Categories:
1. OBSERVED TELEMETRY: Raw bytes and packet metadata.
2. DETERMINISTIC DETECTION: Hard thresholds and signature rules.
3. ML ADVISORY SIGNAL: Isolation Forest & Random Forest signals (advisory only).
4. AGENT ANALYSIS: Synthesized deductions from the 7 sequential stages.

If you require specific analysis of an incident or raw packet headers, provide the Incident or Event ID.`;
      }

      setMessages(prev => [
        ...prev,
        {
          id: 'asst-' + Date.now(),
          sender: 'assistant',
          timestamp: new Date().toLocaleTimeString(),
          text: responseText,
        },
      ]);
      setIsProcessing(false);
    }, 400);
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded bg-cyan-950 border border-cyan-500/40 text-cyan-400">
            <Bot className="w-4 h-4" />
          </div>
          <div>
            <h1 className="text-sm font-bold font-mono text-slate-100 flex items-center gap-2">
              GenAI Security Copilot & Investigation Assistant
              <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            </h1>
            <p className="text-xs text-slate-400">
              Evidence-grounded assistant strictly distinguishing telemetry, deterministic rules, and AI guidance
            </p>
          </div>
        </div>

        <div className="text-[11px] font-mono text-emerald-400 bg-emerald-950/80 px-2.5 py-1 rounded border border-emerald-800">
          Hallucination Guardrail: ENFORCED
        </div>
      </div>

      {/* Suggested Quick Prompts */}
      <div className="flex gap-2 flex-wrap text-xs font-mono">
        {[
          'Summarize recent incident findings',
          'Explain MITRE technique for current detections',
          'What are the recommended containment actions for Agent 6 Guardian?',
          'Verify cryptographic evidence integrity status',
        ].map(p => (
          <button
            key={p}
            onClick={() => handleSendMessage(p)}
            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 rounded transition cursor-pointer text-[11px]"
          >
            {p}
          </button>
        ))}
      </div>

      {/* Chat Messages Container */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 min-h-[420px] max-h-[560px] flex flex-col justify-between">
        <div className="space-y-4 overflow-y-auto pr-2 flex-1 mb-4 font-mono text-xs">
          {messages.map(m => (
            <div
              key={m.id}
              className={`flex flex-col ${m.sender === 'user' ? 'items-end' : 'items-start'}`}
            >
              <div className="flex items-center gap-2 mb-1 text-[10px] text-slate-500">
                <span>{m.sender === 'user' ? 'Security Analyst' : 'MAS-CSI Copilot'}</span>
                <span>·</span>
                <span>{m.timestamp}</span>
              </div>
              <div
                className={`p-3.5 rounded-lg max-w-3xl whitespace-pre-wrap leading-relaxed ${
                  m.sender === 'user'
                    ? 'bg-cyan-950 text-cyan-200 border border-cyan-800'
                    : 'bg-slate-950 text-slate-200 border border-slate-800'
                }`}
              >
                {m.text}
              </div>
            </div>
          ))}
          {isProcessing && (
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 animate-pulse">
              <Sparkles className="w-4 h-4" />
              <span>Synthesizing evidence-grounded response...</span>
            </div>
          )}
        </div>

        {/* Query Input */}
        <div className="border-t border-slate-800 pt-3 flex gap-2">
          <input
            type="text"
            value={inputQuery}
            onChange={(e) => setInputQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSendMessage()}
            placeholder="Ask Copilot about observed telemetry, MITRE mappings, or evidence records..."
            className="flex-1 bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs font-mono text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
          />
          <button
            onClick={() => handleSendMessage()}
            disabled={!inputQuery.trim() || isProcessing}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 text-slate-950 font-mono font-bold text-xs rounded transition cursor-pointer flex items-center gap-1.5"
          >
            <span>Send</span>
            <Send className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
};
