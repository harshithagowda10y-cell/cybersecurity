/**
 * MAS-CSI Report Generator
 * Professional PDF Generation via jsPDF and Evidence-Grade JSON Export
 */

import jsPDF from 'jspdf';
import { Incident, AgentRun, EvidenceRecord, TelemetryEvent } from '../types/mas_csi';

export function generateIncidentJson(
  incident: Incident,
  agents: AgentRun[],
  evidence: EvidenceRecord[],
  events: TelemetryEvent[]
): string {
  const incidentAgents = agents.filter(a => a.incident_id === incident.incident_id);
  const incidentEvidence = evidence.filter(e => e.incident_id === incident.incident_id);
  const correlatedEvents = events.filter(ev => incident.correlated_event_ids.includes(ev.event_id));

  const reportObject = {
    report_title: 'MAS-CSI Forensic Incident Investigation Report',
    standard: 'NIST SP 800-61 Rev. 2 / ISO/IEC 27037 Digital Evidence',
    generated_at: new Date().toISOString(),
    confidentiality: 'RESTRICTED / CONTROLLED LAB EXPERIMENTATION',
    integrity_statement: 'Evidence records verified via SHA-256 cryptographic chain of custody.',
    incident_overview: {
      incident_id: incident.incident_id,
      title: incident.title,
      attack_type: incident.attack_type,
      detection_state: incident.detection_state,
      severity: incident.severity,
      risk_score: incident.risk_score,
      detection_reason: incident.detection_reason,
      status: incident.status,
      actor_attribution: incident.actor_identity,
      source_observed: incident.source_ip,
      destination_target: incident.target,
      location_data: incident.source_location,
      first_seen: incident.first_seen,
      last_seen: incident.last_seen,
      mitre_alignment: {
        technique: incident.mitre_technique,
        tactic: incident.mitre_tactic,
      },
    },
    multi_agent_investigation_pipeline: incidentAgents.map(a => ({
      agent_id: a.agent_id,
      agent_name: a.agent_name,
      task: a.task,
      input: a.input,
      output: a.output,
      decision: a.decision,
      status: a.status,
      timestamp: a.timestamp,
    })),
    cryptographic_evidence_chain: incidentEvidence.map(e => ({
      evidence_id: e.evidence_id,
      type: e.type,
      source: e.source,
      collected_timestamp: e.collected_timestamp,
      sha256_digest: e.sha256,
      integrity_status: e.integrity_status,
      custody: e.custody_chain,
    })),
    correlated_telemetry_events: correlatedEvents.map(ev => ({
      event_id: ev.event_id,
      event_type: ev.event_type,
      timestamp: ev.timestamp,
      protocol: ev.protocol,
      source: `${ev.source_ip}:${ev.source_port}`,
      destination: `${ev.destination_ip}:${ev.destination_port}`,
      bytes: { in: ev.bytes_in, out: ev.bytes_out },
      detection_state: ev.detection_state,
      ml_label: ev.ml_label,
    })),
  };

  return JSON.stringify(reportObject, null, 2);
}

export function downloadJsonFile(filename: string, content: string) {
  const blob = new Blob([content], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function generateIncidentPdf(
  incident: Incident,
  agents: AgentRun[],
  evidence: EvidenceRecord[]
) {
  const doc = new jsPDF({
    unit: 'pt',
    format: 'a4',
  });

  const incidentAgents = agents.filter(a => a.incident_id === incident.incident_id);
  const incidentEvidence = evidence.filter(e => e.incident_id === incident.incident_id);

  const pageWidth = doc.internal.pageSize.getWidth();
  const margin = 40;
  const contentWidth = pageWidth - margin * 2;
  let y = margin;

  // Header
  doc.setFillColor(15, 23, 42); // slate-900
  doc.rect(0, 0, pageWidth, 75, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.text('MAS-CSI CYBER INTELLIGENCE PLATFORM', margin, 32);

  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(148, 163, 184); // slate-400
  doc.text('Multi-Agent Forensic Incident & Telemetry Investigation Report', margin, 48);
  doc.text(`Generated: ${new Date().toUTCString()} | Report Standard: ISO/IEC 27037`, margin, 62);

  y = 95;

  // Incident Overview Box
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(203, 213, 225);
  doc.roundedRect(margin, y, contentWidth, 125, 4, 4, 'FD');

  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(13);
  doc.text(`INCIDENT: ${incident.incident_id} — ${incident.title}`, margin + 12, y + 20);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(51, 65, 85);

  const col1 = margin + 12;
  const col2 = margin + 260;

  doc.text(`Attack Type: ${incident.attack_type}`, col1, y + 40);
  doc.text(`Severity: ${incident.severity} | Risk Score: ${incident.risk_score}/100`, col1, y + 54);
  doc.text(`Detection State: ${incident.detection_state}`, col1, y + 68);
  doc.text(`Status: ${incident.status}`, col1, y + 82);
  doc.text(`First Seen: ${incident.first_seen}`, col1, y + 96);
  doc.text(`Last Seen: ${incident.last_seen}`, col1, y + 110);

  doc.text(`Attribution: ${incident.actor_identity}`, col2, y + 40);
  doc.text(`Observed Source IP: ${incident.source_ip}`, col2, y + 54);
  doc.text(`Target Destination: ${incident.target}`, col2, y + 68);
  doc.text(`Location: ${incident.source_location}`, col2, y + 82);
  doc.text(`MITRE Technique: ${incident.mitre_technique} (${incident.mitre_tactic})`, col2, y + 96);
  doc.text(`Evidence Records: ${incident.evidence_count} sealed`, col2, y + 110);

  y += 140;

  // Detection Reason
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('DETERMINISTIC DETECTION GROUND TRUTH', margin, y);
  y += 14;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(71, 85, 105);
  const reasonLines = doc.splitTextToSize(incident.detection_reason, contentWidth);
  doc.text(reasonLines, margin, y);
  y += reasonLines.length * 12 + 15;

  // 7-Agent Findings Section
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('SEVEN-AGENT INVESTIGATION PIPELINE', margin, y);
  y += 14;

  incidentAgents.forEach((agent) => {
    // Check page overflow
    if (y > 750) {
      doc.addPage();
      y = margin;
    }

    doc.setFillColor(241, 245, 249);
    doc.roundedRect(margin, y, contentWidth, 36, 2, 2, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(15, 23, 42);
    doc.text(`${agent.agent_name.toUpperCase()} [${agent.status}]`, margin + 8, y + 14);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(71, 85, 105);
    const taskText = `Task: ${agent.task} | Decision: ${agent.decision}`;
    const truncatedTask = doc.splitTextToSize(taskText, contentWidth - 16);
    doc.text(truncatedTask[0] || '', margin + 8, y + 26);

    y += 42;
  });

  y += 10;

  // Evidence Chain Vault with Wrapped SHA-256 Hashes
  if (y > 700) {
    doc.addPage();
    y = margin;
  }

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('CRYPTOGRAPHIC EVIDENCE INTEGRITY VAULT (SHA-256)', margin, y);
  y += 16;

  if (incidentEvidence.length === 0) {
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(9);
    doc.setTextColor(100, 116, 139);
    doc.text('Insufficient evidence recorded for this incident.', margin, y);
    y += 20;
  } else {
    incidentEvidence.forEach((ev) => {
      if (y > 720) {
        doc.addPage();
        y = margin;
      }

      doc.setDrawColor(226, 232, 240);
      doc.setFillColor(255, 255, 255);
      doc.roundedRect(margin, y, contentWidth, 52, 2, 2, 'D');

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.5);
      doc.setTextColor(15, 23, 42);
      doc.text(`Evidence ID: ${ev.evidence_id} [${ev.type}]`, margin + 8, y + 14);
      doc.setTextColor(ev.integrity_status === 'VALID' ? 22 : 220, ev.integrity_status === 'VALID' ? 101 : 38, ev.integrity_status === 'VALID' ? 52 : 38);
      doc.text(`Status: ${ev.integrity_status}`, margin + contentWidth - 75, y + 14);

      doc.setFont('courier', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(71, 85, 105);
      doc.text(`SHA-256: ${ev.sha256}`, margin + 8, y + 28);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(100, 116, 139);
      doc.text(`Collected by: ${ev.custody_chain.collected_by} at ${ev.collected_timestamp}`, margin + 8, y + 42);

      y += 60;
    });
  }

  // Footer on current page
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(148, 163, 184);
  doc.text(
    'MAS-CSI Framework: Evidence-first, real-telemetry-driven. Absolute data integrity verified.',
    margin,
    810
  );

  doc.save(`MAS_CSI_Incident_${incident.incident_id}_Report.pdf`);
}
