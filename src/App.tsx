/**
 * MAS-CSI — Multi-Agent Systems for Cyber Security Intelligence
 * Main Application Shell with Interactive 3D Background & Role Portal
 */

import React, { useState, useEffect } from 'react';
import { store } from './services/store';
import { PageId, Navigation } from './components/Navigation';
import { CommandCenter } from './components/CommandCenter';
import { LiveSOC } from './components/LiveSOC';
import { IncidentsView } from './components/IncidentsView';
import { IncidentDetailsModal } from './components/IncidentDetailsModal';
import { AIAgentsView } from './components/AIAgentsView';
import { GenAIAgentsView } from './components/GenAIAgentsView';
import { ThreatIntelligenceView } from './components/ThreatIntelligenceView';
import { HackPredictorView } from './components/HackPredictorView';
import { SecurityToolsView } from './components/SecurityToolsView';
import { AttackGraphView } from './components/AttackGraphView';
import { ForensicsView } from './components/ForensicsView';
import { EvidenceVaultView } from './components/EvidenceVaultView';
import { LocationIntelligenceView } from './components/LocationIntelligenceView';
import { ReportsView } from './components/ReportsView';
import { RealLabView } from './components/RealLabView';
import { AdminSecurityCenterView } from './components/AdminSecurityCenterView';
import { ZipExportModal } from './components/ZipExportModal';
import { RoleLoginModal } from './components/RoleLoginModal';
import { EmailInboxModal } from './components/EmailInboxModal';
import { InteractiveCyber3DBackground } from './components/InteractiveCyber3DBackground';
import { Incident, UserRole } from './types/mas_csi';
import { Download, ShieldCheck, Database, Lock } from 'lucide-react';

export default function App() {
  const [currentPage, setCurrentPage] = useState<PageId>('command_center');
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [isZipModalOpen, setIsZipModalOpen] = useState(false);
  const [isRoleModalOpen, setIsRoleModalOpen] = useState(false);
  const [isEmailInboxOpen, setIsEmailInboxOpen] = useState(false);
  const [is3dEnabled, setIs3dEnabled] = useState(true);
  const [, setStoreVersion] = useState(0);

  // Subscribe to real-time engine changes
  useEffect(() => {
    const unsubscribe = store.subscribe(() => {
      setStoreVersion(v => v + 1);
    });
    return unsubscribe;
  }, []);

  const selectedIncident = store.incidents.find(i => i.incident_id === selectedIncidentId) || null;

  // Determine global threat level for 3D background color reaction
  let overallThreat: 'NORMAL' | 'SUSPICIOUS' | 'CONFIRMED' | 'CRITICAL' = 'NORMAL';
  if (store.incidents.some(i => i.severity === 'CRITICAL')) overallThreat = 'CRITICAL';
  else if (store.incidents.some(i => i.severity === 'HIGH')) overallThreat = 'CONFIRMED';
  else if (store.incidents.some(i => i.severity === 'MEDIUM')) overallThreat = 'SUSPICIOUS';

  const handleRoleSelect = (role: UserRole) => {
    if (role === 'Employee') setCurrentPage('real_lab');
    else if (role === 'Auditor') setCurrentPage('evidence_vault');
    else if (role === 'Security Analyst') setCurrentPage('live_soc');
    else setCurrentPage('command_center');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-900 selection:text-cyan-200 relative overflow-x-hidden">
      {/* Interactive 3D Cyber Background */}
      {is3dEnabled && <InteractiveCyber3DBackground threatLevel={overallThreat} />}

      {/* Top Navigation */}
      <Navigation
        currentPage={currentPage}
        onNavigate={(p) => setCurrentPage(p)}
        onOpenZipModal={() => setIsZipModalOpen(true)}
        onOpenRoleModal={() => setIsRoleModalOpen(true)}
        is3dEnabled={is3dEnabled}
        onToggle3d={() => setIs3dEnabled(!is3dEnabled)}
        activeIncidentCount={store.incidents.length}
      />

      {/* Main Container View Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 relative z-10">
        {currentPage === 'command_center' && (
          <CommandCenter
            onNavigate={(p) => setCurrentPage(p)}
            onSelectIncident={(id) => setSelectedIncidentId(id)}
          />
        )}

        {currentPage === 'live_soc' && <LiveSOC />}

        {currentPage === 'incidents' && (
          <IncidentsView onSelectIncident={(id) => setSelectedIncidentId(id)} />
        )}

        {currentPage === 'hack_predictor' && <HackPredictorView />}

        {currentPage === 'ai_agents' && <AIAgentsView />}

        {currentPage === 'security_tools' && <SecurityToolsView />}

        {currentPage === 'genai' && <GenAIAgentsView />}

        {currentPage === 'threat_intel' && <ThreatIntelligenceView />}

        {currentPage === 'attack_graph' && <AttackGraphView />}

        {currentPage === 'forensics' && <ForensicsView />}

        {currentPage === 'evidence_vault' && <EvidenceVaultView />}

        {currentPage === 'location_intel' && <LocationIntelligenceView />}

        {currentPage === 'reports' && <ReportsView />}

        {currentPage === 'real_lab' && <RealLabView />}

        {currentPage === 'admin_center' && <AdminSecurityCenterView />}
      </main>

      {/* Incident Dossier Deep-Dive Modal */}
      {selectedIncident && (
        <IncidentDetailsModal
          incident={selectedIncident}
          onClose={() => setSelectedIncidentId(null)}
        />
      )}

      {/* Full Repository ZIP Export Modal */}
      <ZipExportModal
        isOpen={isZipModalOpen}
        onClose={() => setIsZipModalOpen(false)}
      />

      {/* Role & Persona Login Portal Modal */}
      <RoleLoginModal
        isOpen={isRoleModalOpen}
        onClose={() => setIsRoleModalOpen(false)}
        onSelectRole={handleRoleSelect}
      />

      {/* Standard SOC Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/90 backdrop-blur-xs py-4 px-6 text-xs font-mono text-slate-500 relative z-10">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="font-bold text-slate-400">MAS-CSI v9.0</span>
            <span>·</span>
            <span>Evidence-Driven Real Telemetry Core</span>
            <span>·</span>
            <span className="text-emerald-500">SHA-256 Vault Active</span>
            <span>·</span>
            <span className="text-cyan-400">Active Persona: {store.currentUser?.username} ({store.currentUser?.role})</span>
          </div>

          <div className="flex items-center gap-4">
            <button
              onClick={() => setIsRoleModalOpen(true)}
              className="text-amber-400 hover:text-amber-300 cursor-pointer"
            >
              Switch Role
            </button>
            <span className="text-slate-700">|</span>
            <button
              onClick={() => setIsZipModalOpen(true)}
              className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download Full Project ZIP (.zip)</span>
            </button>
            <span className="text-slate-700">|</span>
            <span>NIST SP 800-61 / ISO 27037</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
