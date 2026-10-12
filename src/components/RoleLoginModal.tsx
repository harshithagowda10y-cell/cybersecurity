/**
 * MAS-CSI Persona & Role Authentication Portal
 * Dedicated authentication modal providing separate logins and tailored workspaces for:
 * 1. Super Admin
 * 2. Security Analyst
 * 3. Auditor
 * 4. Employee
 */

import React, { useState } from 'react';
import {
  ShieldAlert,
  UserCheck,
  Lock,
  X,
  CheckCircle2,
  AlertTriangle,
  KeyRound,
  FileCheck2,
  FlaskConical,
  Activity,
  ArrowRight,
  Eye,
  EyeOff,
  Shield,
  Fingerprint,
  MapPin,
  Clock
} from 'lucide-react';
import { store } from '../services/store';
import { UserRole } from '../types/mas_csi';

interface RoleLoginModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectRole: (role: UserRole) => void;
}

export const RoleLoginModal: React.FC<RoleLoginModalProps> = ({
  isOpen,
  onClose,
  onSelectRole,
}) => {
  const [selectedRole, setSelectedRole] = useState<UserRole>('Super Admin');
  const [usernameInput, setUsernameInput] = useState('admin');
  const [passwordInput, setPasswordInput] = useState('Admin@CSI2026!');
  const [adminSecurityToken, setAdminSecurityToken] = useState('ADM-KEY-9941-SEC');
  const [showPassword, setShowPassword] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [authSuccess, setAuthSuccess] = useState<string | null>(null);

  if (!isOpen) return null;

  const roleProfiles = [
    {
      role: 'Super Admin' as UserRole,
      defaultUser: 'admin',
      defaultPass: 'Admin@CSI2026!',
      icon: Lock,
      color: 'rose',
      title: 'Super Admin Console',
      description: 'Master platform governance, user provisioning, account suspension, session revocation, policy enforcement.',
      capabilities: ['Full Platform Access', 'User Provisioning & Suspension', 'Session Revocation', 'Master Audit Trails'],
    },
    {
      role: 'Security Analyst' as UserRole,
      defaultUser: 'sec_analyst',
      defaultPass: 'Analyst@CSI2026!',
      icon: Activity,
      color: 'cyan',
      title: 'Security Operations Analyst',
      description: 'Real-time threat monitoring, 7-agent pipeline execution, containment actions, forensics, attack graph analysis.',
      capabilities: ['Live SOC Telemetry Stream', '7-Agent Pipeline Control', 'Containment & Isolation Actions', 'Hack Prediction Engine'],
    },
    {
      role: 'Auditor' as UserRole,
      defaultUser: 'auditor',
      defaultPass: 'Auditor@CSI2026!',
      icon: FileCheck2,
      color: 'purple',
      title: 'Compliance & Audit Inspector',
      description: 'Regulatory compliance (ISO/IEC 27037, NIST), cryptographic SHA-256 evidence chain verification, audit trail review.',
      capabilities: ['SHA-256 Cryptographic Verification', 'Non-Repudiation Audit Logs', 'Forensic Timeline Inspection', 'Compliance PDF/JSON Export'],
    },
    {
      role: 'Employee' as UserRole,
      defaultUser: 'john_doe',
      defaultPass: 'Employee@CSI2026!',
      icon: FlaskConical,
      color: 'emerald',
      title: 'Employee Real Lab Portal',
      description: 'Authorized workspace, confidential document storage, file upload/download, personal account security monitoring.',
      capabilities: ['Secure Document Storage', 'Multi-User Change Detection', 'Personal Session Security', 'File Hash Checksums'],
    },
  ];

  const activeProfile = roleProfiles.find(p => p.role === selectedRole)!;

  const handleSelectRolePreset = (r: typeof roleProfiles[0]) => {
    setSelectedRole(r.role);
    setUsernameInput(r.defaultUser);
    setPasswordInput(r.defaultPass);
    setAuthError(null);
    setAuthSuccess(null);
  };

  const handleAuthenticate = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setAuthSuccess(null);

    const user = store.users.find(u => u.username.toLowerCase() === usernameInput.toLowerCase());
    if (!user) {
      setAuthError('Identity not found in directory.');
      return;
    }

    const res = await store.loginUser(usernameInput, passwordInput);
    if (!res.success) {
      setAuthError(res.error || 'Authentication failed. Check credentials.');
    } else {
      setAuthSuccess(`✓ Authenticated as ${user.username} (${user.role}) at ${user.last_login_formatted_time || 'now'} | Location Lock: ${user.last_location || 'Verified'}. Launching workspace...`);
      setTimeout(() => {
        onSelectRole(user.role);
        onClose();
      }, 1000);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-xs p-4 font-mono text-xs">
      <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-3xl w-full p-6 text-slate-100 shadow-2xl relative space-y-5">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-slate-200 cursor-pointer"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded bg-cyan-950 border border-cyan-500/40 text-cyan-400">
            <UserCheck className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-100">
              MAS-CSI Role & Persona Authentication Portal
            </h2>
            <p className="text-[11px] text-slate-400">
              Select persona to log in with dedicated access permissions and tailored page views
            </p>
          </div>
        </div>

        {authError && (
          <div className="p-3 bg-rose-950/80 border border-rose-600 rounded text-rose-200 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{authError}</span>
          </div>
        )}

        {authSuccess && (
          <div className="p-3 bg-emerald-950/80 border border-emerald-600 rounded text-emerald-200 text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{authSuccess}</span>
          </div>
        )}

        {/* Four Role Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5">
          {roleProfiles.map(p => {
            const Icon = p.icon;
            const isSelected = selectedRole === p.role;
            return (
              <button
                key={p.role}
                type="button"
                onClick={() => handleSelectRolePreset(p)}
                className={`p-3 rounded-lg border text-left transition cursor-pointer flex flex-col justify-between ${
                  isSelected
                    ? 'bg-slate-800 border-cyan-500 text-slate-100 ring-1 ring-cyan-500'
                    : 'bg-slate-950/80 border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <Icon className="w-4 h-4 text-cyan-400" />
                    <span className="text-[9px] px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800 text-slate-300">
                      {p.role.split(' ')[0]}
                    </span>
                  </div>
                  <div className="font-bold text-slate-200 text-xs">{p.role}</div>
                  <p className="text-[10px] text-slate-500 mt-1 line-clamp-2">{p.title}</p>
                </div>
                <div className="mt-2 pt-1 border-t border-slate-900 text-[10px] text-cyan-400">
                  User: {p.defaultUser}
                </div>
              </button>
            );
          })}
        </div>

        {/* Selected Persona Detail & Credentials Form */}
        <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div>
              <span className="font-bold text-cyan-300 text-sm">{activeProfile.title}</span>
              <p className="text-[11px] text-slate-400 mt-0.5">{activeProfile.description}</p>
            </div>
            <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
              Role: {activeProfile.role}
            </span>
          </div>

          <div className="flex flex-wrap gap-2 text-[10px]">
            {activeProfile.capabilities.map((cap, idx) => (
              <span key={idx} className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                ✓ {cap}
              </span>
            ))}
          </div>

          <form onSubmit={handleAuthenticate} className="space-y-3 pt-2">
            <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
              <div className={selectedRole === 'Super Admin' ? 'md:col-span-4' : 'md:col-span-5'}>
                <label className="text-slate-400 block mb-1">Username</label>
                <input
                  type="text"
                  required
                  value={usernameInput}
                  onChange={(e) => setUsernameInput(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div className={selectedRole === 'Super Admin' ? 'md:col-span-4' : 'md:col-span-5'}>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-slate-400">Password</label>
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer font-mono"
                  >
                    {showPassword ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                    <span>{showPassword ? 'Hide' : 'View Password'}</span>
                  </button>
                </div>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    value={passwordInput}
                    onChange={(e) => setPasswordInput(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono pr-9"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-2.5 top-2 text-slate-400 hover:text-slate-200 cursor-pointer"
                    title={showPassword ? 'Hide password' : 'View password'}
                  >
                    {showPassword ? <EyeOff className="w-3.5 h-3.5 text-cyan-400" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              {selectedRole === 'Super Admin' && (
                <div className="md:col-span-4">
                  <label className="text-rose-400 block mb-1 flex items-center gap-1 font-mono">
                    <Fingerprint className="w-3.5 h-3.5" />
                    <span>Admin Security Token</span>
                  </label>
                  <input
                    type="text"
                    required
                    value={adminSecurityToken}
                    onChange={(e) => setAdminSecurityToken(e.target.value)}
                    placeholder="ADM-KEY-XXXX-SEC"
                    className="w-full bg-rose-950/40 border border-rose-800/80 rounded px-3 py-1.5 text-rose-200 focus:outline-none focus:border-rose-500 font-mono"
                  />
                </div>
              )}
            </div>

            <div className="flex items-center gap-2 p-2 bg-slate-900 border border-slate-800 rounded text-[11px] text-slate-300">
              <MapPin className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>Physical GPS coordinates &amp; exact microsecond timestamp will be recorded on login.</span>
            </div>

            <div className="flex items-center justify-between pt-1">
              <span className="text-[10px] text-slate-500 font-mono">
                {selectedRole === 'Super Admin'
                  ? '🔒 Super Admin privileges enforced: User provisioning, session revocation, master policies.'
                  : selectedRole === 'Employee'
                  ? '🧪 Employee Real Lab workspace: File storage, SHA-256 seal, intrusion detection.'
                  : '🔍 Operational access: SOC telemetry, threat prediction, compliance records.'}
              </span>
              <button
                type="submit"
                className={`py-2 px-6 font-bold rounded cursor-pointer transition shadow-xs font-mono text-xs ${
                  selectedRole === 'Super Admin'
                    ? 'bg-rose-600 hover:bg-rose-500 text-slate-950'
                    : 'bg-cyan-600 hover:bg-cyan-500 text-slate-950'
                }`}
              >
                Sign In to {activeProfile.role}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};
