/**
 * MAS-CSI Navigation Header & Menu
 * Provides seamless routing, role-based navigation filtering,
 * 3D live background toggle, and full ZIP download.
 */

import React from 'react';
import {
  ShieldAlert,
  Activity,
  Layers,
  Cpu,
  Bot,
  Radar,
  Network,
  Clock,
  KeyRound,
  MapPin,
  FileText,
  FlaskConical,
  Lock,
  Download,
  AlertTriangle,
  UserCheck,
  TrendingUp,
  Wrench,
  LockKeyhole,
  Radio,
  Eye,
  EyeOff,
  User
} from 'lucide-react';
import { store } from '../services/store';
import { AttackScenario, PageId, UserRole } from '../types/mas_csi';

export type { PageId };

interface NavigationProps {
  currentPage: PageId;
  onNavigate: (page: PageId) => void;
  onOpenZipModal: () => void;
  onOpenRoleModal: () => void;
  is3dEnabled: boolean;
  onToggle3d: () => void;
  activeIncidentCount: number;
}

export const Navigation: React.FC<NavigationProps> = ({
  currentPage,
  onNavigate,
  onOpenZipModal,
  onOpenRoleModal,
  is3dEnabled,
  onToggle3d,
  activeIncidentCount,
}) => {
  const currentUser = store.currentUser;
  const labUser = store.labUser;
  const role = currentUser?.role || 'Super Admin';

  const allNavItems: { id: PageId; label: string; icon: React.ComponentType<{ className?: string }>; roles: UserRole[] }[] = [
    { id: 'command_center', label: 'Command Center', icon: Activity, roles: ['Super Admin', 'Security Analyst', 'Auditor', 'Employee'] },
    { id: 'live_soc', label: 'Live SOC', icon: Radio, roles: ['Super Admin', 'Security Analyst'] },
    { id: 'incidents', label: `Incidents (${activeIncidentCount})`, icon: ShieldAlert, roles: ['Super Admin', 'Security Analyst', 'Auditor'] },
    { id: 'hack_predictor', label: 'Hack Predictor', icon: TrendingUp, roles: ['Super Admin', 'Security Analyst'] },
    { id: 'ai_agents', label: '7-Agent Pipeline', icon: Cpu, roles: ['Super Admin', 'Security Analyst'] },
    { id: 'security_tools', label: 'Security Tools', icon: Wrench, roles: ['Super Admin', 'Security Analyst'] },
    { id: 'genai', label: 'GenAI Copilot', icon: Bot, roles: ['Super Admin', 'Security Analyst'] },
    { id: 'threat_intel', label: 'Threat Intel', icon: Radar, roles: ['Super Admin', 'Security Analyst'] },
    { id: 'attack_graph', label: 'Attack Graph', icon: Network, roles: ['Super Admin', 'Security Analyst'] },
    { id: 'forensics', label: 'Forensics', icon: Clock, roles: ['Super Admin', 'Security Analyst', 'Auditor'] },
    { id: 'evidence_vault', label: 'Evidence Vault', icon: KeyRound, roles: ['Super Admin', 'Security Analyst', 'Auditor'] },
    { id: 'location_intel', label: 'Location Intel', icon: MapPin, roles: ['Super Admin', 'Security Analyst', 'Auditor', 'Employee'] },
    { id: 'reports', label: 'Reports', icon: FileText, roles: ['Super Admin', 'Security Analyst', 'Auditor'] },
    { id: 'real_lab', label: labUser ? `Real Lab (${labUser.username})` : 'Real Lab (Locked)', icon: FlaskConical, roles: ['Super Admin', 'Employee', 'Security Analyst'] },
    { id: 'admin_center', label: 'Admin Center', icon: Lock, roles: ['Super Admin', 'Auditor'] },
  ];

  // Filter items matching currently logged-in role
  const visibleNavItems = allNavItems.filter(item => item.roles.includes(role));

  const handleScenarioTrigger = async (e: React.ChangeEvent<HTMLSelectElement>) => {
    const scenario = e.target.value as AttackScenario;
    if (!scenario) return;
    await store.executeControlledScenario(scenario);
    e.target.value = '';
    onNavigate('incidents');
  };

  return (
    <header className="sticky top-0 z-50 bg-slate-950/95 backdrop-blur-md border-b border-slate-800 text-slate-100 shadow-xl">
      {/* Top Banner Bar */}
      <div className="max-w-7xl mx-auto px-4 py-2.5 flex flex-wrap items-center justify-between gap-3">
        {/* Brand identity */}
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded bg-cyan-950 border border-cyan-500/40 text-cyan-400 font-bold font-mono text-sm shadow-xs">
            CSI
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono font-bold tracking-tight text-slate-100 text-base">
                MAS-CSI
              </span>
              <span className="text-[11px] font-mono uppercase px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                Live SOC v9.0
              </span>
            </div>
            <p className="text-[11px] text-slate-400 hidden sm:block">
              Multi-Agent Systems for Cyber Security Intelligence
            </p>
          </div>
        </div>

        {/* Action Controls & User Role */}
        <div className="flex items-center gap-2.5 flex-wrap">
          {/* 3D Live Background Toggle */}
          <button
            onClick={onToggle3d}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-semibold transition cursor-pointer border ${
              is3dEnabled
                ? 'bg-cyan-950 text-cyan-300 border-cyan-600/60'
                : 'bg-slate-900 text-slate-400 border-slate-700'
            }`}
            title="Toggle Live 3D Spatial Grid Background"
          >
            {is3dEnabled ? <Eye className="w-3.5 h-3.5 text-cyan-400" /> : <EyeOff className="w-3.5 h-3.5 text-slate-500" />}
            <span>3D Live: {is3dEnabled ? 'ON' : 'OFF'}</span>
          </button>

          {/* Controlled Lab Scenario Selector (For Analyst & Admin) */}
          {(role === 'Super Admin' || role === 'Security Analyst') && (
            <div className="flex items-center gap-1.5 bg-slate-900 border border-amber-500/30 rounded px-2.5 py-1">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
              <span className="text-xs font-mono text-amber-300 font-semibold hidden md:inline">
                Scenario:
              </span>
              <select
                defaultValue=""
                onChange={handleScenarioTrigger}
                className="bg-slate-950 text-slate-200 text-xs font-mono rounded px-2 py-0.5 border border-slate-700 focus:outline-none focus:border-amber-400 cursor-pointer"
              >
                <option value="" disabled>Run Authorized Scenario...</option>
                <option value="BRUTE_FORCE">Brute Force (T1110)</option>
                <option value="PORT_SCAN">Port Scan (T1046)</option>
                <option value="DNS_ANOMALY">DNS Anomaly (T1071.004)</option>
                <option value="WEB_ATTACK">Web Attack SQLi (T1190)</option>
                <option value="DATA_EXFILTRATION">Data Exfiltration (T1041)</option>
                <option value="ACCOUNT_TAKEOVER">Account Takeover (T1078)</option>
                <option value="AGENT_ANOMALY">Agent Workflow Anomaly</option>
              </select>
            </div>
          )}

          {/* Exact Login Timestamp Indicator */}
          <div
            className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300"
            title="Exact authenticated session timestamp"
          >
            <Clock className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span>
              {currentUser?.last_login_formatted_time
                ? currentUser.last_login_formatted_time.slice(0, 25)
                : 'Live Auth: Valid'}
            </span>
          </div>

          {/* Exact Geolocation Telemetry Sensor */}
          <div
            className="hidden xl:flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300"
            title="Login GPS & Workstation Telemetry Coordinates"
          >
            <MapPin className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
            <span>
              {currentUser?.last_location
                ? currentUser.last_location
                : '37.7749° N, -122.4194° W'}
            </span>
          </div>

          {/* Persona / Role Login Portal Trigger */}
          <button
            onClick={onOpenRoleModal}
            className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono font-bold transition cursor-pointer border ${
              role === 'Super Admin'
                ? 'bg-rose-950 text-rose-300 border-rose-700 hover:bg-rose-900'
                : role === 'Security Analyst'
                ? 'bg-cyan-950 text-cyan-300 border-cyan-700 hover:bg-cyan-900'
                : role === 'Auditor'
                ? 'bg-purple-950 text-purple-300 border-purple-700 hover:bg-purple-900'
                : 'bg-emerald-950 text-emerald-300 border-emerald-700 hover:bg-emerald-900'
            }`}
            title="Click to switch persona: Super Admin, Security Analyst, Auditor, or Employee"
          >
            <User className="w-3.5 h-3.5" />
            <span>Role: {currentUser?.username} ({role})</span>
          </button>

          {/* Download Full Project ZIP Button */}
          <button
            onClick={onOpenZipModal}
            className="flex items-center gap-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 px-3 py-1 rounded font-mono font-semibold text-xs transition shadow-sm cursor-pointer"
            title="Download complete standalone MAS-CSI repository archive"
          >
            <Download className="w-3.5 h-3.5 stroke-[2.5]" />
            <span>Download ZIP</span>
          </button>
        </div>
      </div>

      {/* Horizontal Nav Bar (Filtered by Role) */}
      <nav className="bg-slate-900/90 border-t border-slate-800 overflow-x-auto scrollbar-thin">
        <div className="max-w-7xl mx-auto px-4 flex items-center space-x-1 py-1.5 min-w-max">
          {visibleNavItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentPage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onNavigate(item.id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded transition cursor-pointer ${
                  isActive
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/40 shadow-xs'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </div>
      </nav>
    </header>
  );
};
