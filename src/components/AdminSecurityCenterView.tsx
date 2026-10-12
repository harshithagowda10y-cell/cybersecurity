/**
 * MAS-CSI Admin Security Center & Governance Console
 * Strict RBAC permission enforcement:
 * Features exclusive to Super Admin:
 * 1. User Provisioning, Privilege Role Assignment & Suspension
 * 2. Session Revocation across any user
 * 3. Emergency Lab & Endpoint Lockdown Switch
 * 4. Global Security Policy Manager (MFA, Timeout, Lockout threshold)
 * 5. Perimeter Firewall Rule Manager (IP/Port filters, quarantine)
 * 6. Non-Repudiation Master Audit Trail with CSV/JSON export
 */

import React, { useState } from 'react';
import {
  Lock,
  UserX,
  UserCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  FileText,
  UserPlus,
  RefreshCw,
  Search,
  KeyRound,
  Shield,
  Sliders,
  Radio,
  Download,
  Flame,
  Globe,
  Fingerprint,
  Trash2,
  Plus,
  Eye,
  EyeOff,
  MapPin
} from 'lucide-react';
import { store } from '../services/store';
import { UserRole, FirewallRule } from '../types/mas_csi';

export const AdminSecurityCenterView: React.FC = () => {
  const users = store.users;
  const auditLogs = store.auditLogs;
  const currentUser = store.currentUser;
  const securityPolicy = store.systemSecurityPolicy;
  const firewallRules = store.firewallRules;

  // Active Admin Sub-tab
  const [adminTab, setAdminTab] = useState<'users' | 'policies' | 'firewall' | 'audit_logs'>('users');

  // New user modal state
  const [showAddUser, setShowAddUser] = useState(false);
  const [newUsername, setNewUsername] = useState('');
  const [newEmail, setNewEmail] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [newRole, setNewRole] = useState<UserRole>('Employee');

  // New Firewall Rule State
  const [showAddFw, setShowAddFw] = useState(false);
  const [fwDirection, setFwDirection] = useState<'INBOUND' | 'OUTBOUND'>('INBOUND');
  const [fwSource, setFwSource] = useState('192.168.1.100');
  const [fwDest, setFwDest] = useState('127.0.0.1');
  const [fwPort, setFwPort] = useState('443');
  const [fwProtocol, setFwProtocol] = useState<'TCP' | 'UDP' | 'ICMP' | 'ANY'>('TCP');
  const [fwAction, setFwAction] = useState<'ALLOW' | 'BLOCK' | 'QUARANTINE'>('BLOCK');

  const [actionMessage, setActionMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [auditSearch, setAuditSearch] = useState('');

  const isSuperAdmin = currentUser?.role === 'Super Admin';

  const handleSuspendToggle = (userId: string, currentSuspended: boolean) => {
    if (!currentUser) return;
    const res = store.setAccountSuspended(userId, !currentSuspended, currentUser);
    if (res.success) {
      setActionMessage({
        type: 'success',
        text: `Account ${currentSuspended ? 'restored' : 'suspended'} successfully.`,
      });
    } else {
      setActionMessage({ type: 'error', text: res.error || 'Permission denied.' });
    }
    setTimeout(() => setActionMessage(null), 4000);
  };

  const handleLoginToggle = (userId: string, currentEnabled: boolean) => {
    if (!currentUser) return;
    const res = store.setLoginEnabled(userId, !currentEnabled, currentUser);
    if (res.success) {
      setActionMessage({
        type: 'success',
        text: `Login capabilities ${currentEnabled ? 'disabled' : 'enabled'} successfully.`,
      });
    } else {
      setActionMessage({ type: 'error', text: res.error || 'Permission denied.' });
    }
    setTimeout(() => setActionMessage(null), 4000);
  };

  const handleRevokeSessions = (userId: string) => {
    if (!currentUser) return;
    const res = store.revokeUserSessions(userId, currentUser);
    if (res.success) {
      setActionMessage({ type: 'success', text: 'All active sessions revoked for target user.' });
    } else {
      setActionMessage({ type: 'error', text: res.error || 'Permission denied.' });
    }
    setTimeout(() => setActionMessage(null), 4000);
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isSuperAdmin || !currentUser) {
      setActionMessage({ type: 'error', text: 'Permission denied: Super Admin role required to provision users.' });
      return;
    }

    const res = await store.registerUser(newUsername, newEmail, newPassword, newRole);
    if (res.success) {
      setActionMessage({ type: 'success', text: `User ${newUsername} created with role ${newRole}.` });
      setShowAddUser(false);
      setNewUsername('');
      setNewEmail('');
      setNewPassword('');
    } else {
      setActionMessage({ type: 'error', text: res.error || 'Failed to create user.' });
    }
    setTimeout(() => setActionMessage(null), 4000);
  };

  const handleEmergencyLockdownToggle = () => {
    if (!isSuperAdmin || !currentUser) return;
    const nextState = !securityPolicy.emergency_lockdown_active;
    const res = store.adminEmergencyLockdown(nextState, currentUser);
    if (res.success) {
      setActionMessage({
        type: 'success',
        text: nextState
          ? 'EMERGENCY LOCKDOWN ACTIVATED: All employee sessions severed.'
          : 'Emergency lockdown deactivated.',
      });
    } else {
      setActionMessage({ type: 'error', text: res.error || 'Operation failed.' });
    }
    setTimeout(() => setActionMessage(null), 4000);
  };

  const handleAddFirewallRule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentUser) return;
    const res = store.addFirewallRule(
      {
        direction: fwDirection,
        source: fwSource,
        destination: fwDest,
        port: fwPort,
        protocol: fwProtocol,
        action: fwAction,
        is_active: true,
      },
      currentUser
    );
    if (res.success) {
      setActionMessage({ type: 'success', text: 'Firewall rule enacted.' });
      setShowAddFw(false);
    } else {
      setActionMessage({ type: 'error', text: res.error || 'Rule enactment failed.' });
    }
    setTimeout(() => setActionMessage(null), 4000);
  };

  const handleDeleteFirewallRule = (ruleId: string) => {
    if (!currentUser) return;
    const res = store.deleteFirewallRule(ruleId, currentUser);
    if (res.success) {
      setActionMessage({ type: 'success', text: 'Firewall rule removed.' });
    }
    setTimeout(() => setActionMessage(null), 4000);
  };

  const handleExportAuditLogsJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(auditLogs, null, 2));
    const dl = document.createElement('a');
    dl.setAttribute('href', dataStr);
    dl.setAttribute('download', `mas_csi_audit_trail_${new Date().toISOString().slice(0, 10)}.json`);
    dl.click();
  };

  // Filter audit logs by search
  const filteredAuditLogs = auditLogs.filter(log =>
    log.actor_username.toLowerCase().includes(auditSearch.toLowerCase()) ||
    log.action.toLowerCase().includes(auditSearch.toLowerCase()) ||
    log.target.toLowerCase().includes(auditSearch.toLowerCase()) ||
    log.details.toLowerCase().includes(auditSearch.toLowerCase())
  );

  return (
    <div className="space-y-5 font-mono text-xs">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded bg-rose-950 border border-rose-500/40 text-rose-400">
            <Lock className="w-4 h-4" />
          </div>
          <div>
            <h1 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              Super Admin Security Center & Governance
              <span className="text-[10px] px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800">
                MASTER RBAC
              </span>
            </h1>
            <p className="text-slate-400 text-[11px]">
              Platform administration, account provisioning, perimeter firewall rules, and immutable audit logs
            </p>
          </div>
        </div>

        {/* Emergency Lockdown Toggle */}
        <div className="flex items-center gap-2">
          {isSuperAdmin && (
            <button
              onClick={handleEmergencyLockdownToggle}
              className={`px-3 py-1.5 rounded text-xs font-bold flex items-center gap-1.5 cursor-pointer transition border ${
                securityPolicy.emergency_lockdown_active
                  ? 'bg-rose-600 text-slate-950 border-rose-400 animate-pulse'
                  : 'bg-rose-950/80 hover:bg-rose-900 text-rose-200 border-rose-800'
              }`}
            >
              <Flame className="w-3.5 h-3.5" />
              <span>{securityPolicy.emergency_lockdown_active ? 'LOCKDOWN ACTIVE (DISENGAGE)' : 'Emergency Lab Lockdown'}</span>
            </button>
          )}
        </div>
      </div>

      {actionMessage && (
        <div className={`p-3 rounded border text-xs flex items-center gap-2 ${
          actionMessage.type === 'success'
            ? 'bg-emerald-950/80 border-emerald-600 text-emerald-200'
            : 'bg-rose-950/80 border-rose-600 text-rose-200'
        }`}>
          {actionMessage.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          ) : (
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          )}
          <span>{actionMessage.text}</span>
        </div>
      )}

      {/* Admin Navigation Tabs */}
      <div className="flex border-b border-slate-800 gap-2 pb-1 overflow-x-auto">
        {[
          { id: 'users', label: `User Management (${users.length})`, icon: UserCheck },
          { id: 'policies', label: 'Platform Security Policies', icon: Sliders },
          { id: 'firewall', label: `Perimeter Firewall Rules (${firewallRules.length})`, icon: Shield },
          { id: 'audit_logs', label: `Master Audit Logs (${auditLogs.length})`, icon: FileText },
        ].map(tab => {
          const Icon = tab.icon;
          const isActive = adminTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setAdminTab(tab.id as any)}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-t text-xs font-semibold cursor-pointer transition border-b-2 ${
                isActive
                  ? 'border-rose-400 text-rose-300 bg-slate-900/90'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* SUB-TAB 1: USER MANAGEMENT */}
      {adminTab === 'users' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="font-bold text-slate-200 text-sm flex items-center gap-2">
              <UserCheck className="w-4 h-4 text-rose-400" />
              Directory Accounts & RBAC Privilege Enforcement
            </h2>

            {isSuperAdmin && (
              <button
                onClick={() => setShowAddUser(true)}
                className="px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-slate-950 font-bold rounded flex items-center gap-1.5 cursor-pointer transition shadow-xs text-xs"
              >
                <UserPlus className="w-3.5 h-3.5" />
                <span>Provision User</span>
              </button>
            )}
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 border-b border-slate-800 text-slate-400">
                  <tr>
                    <th className="p-3">User</th>
                    <th className="p-3">Role</th>
                    <th className="p-3">Account State</th>
                    <th className="p-3">Login Status</th>
                    <th className="p-3">Exact Login Time</th>
                    <th className="p-3">Location &amp; GPS Lock</th>
                    <th className="p-3 text-right">Administrative Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {users.map(u => (
                    <tr key={u.user_id} className="hover:bg-slate-800/40 transition">
                      <td className="p-3">
                        <div className="font-bold text-slate-200">{u.username}</div>
                        <div className="text-[10px] text-slate-500">{u.email}</div>
                      </td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                          u.role === 'Super Admin'
                            ? 'bg-rose-950 text-rose-300 border-rose-800'
                            : u.role === 'Security Analyst'
                            ? 'bg-cyan-950 text-cyan-300 border-cyan-800'
                            : u.role === 'Auditor'
                            ? 'bg-purple-950 text-purple-300 border-purple-800'
                            : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                        }`}>
                          {u.role}
                        </span>
                      </td>
                      <td className="p-3">
                        {u.is_suspended ? (
                          <span className="text-rose-400 font-bold flex items-center gap-1">
                            <XCircle className="w-3.5 h-3.5" />
                            SUSPENDED
                          </span>
                        ) : (
                          <span className="text-emerald-400 font-bold flex items-center gap-1">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            ACTIVE
                          </span>
                        )}
                      </td>
                      <td className="p-3">
                        {u.login_enabled ? (
                          <span className="text-emerald-400 font-semibold">Enabled</span>
                        ) : (
                          <span className="text-slate-500">Disabled</span>
                        )}
                      </td>
                      <td className="p-3 text-[11px]">
                        {u.last_login_formatted_time ? (
                          <div>
                            <span className="text-cyan-300 font-semibold block">{u.last_login_formatted_time}</span>
                            <span className="text-[10px] text-slate-500 font-mono">{u.last_login?.slice(0, 19).replace('T', ' ')}</span>
                          </div>
                        ) : u.last_login ? (
                          <span className="text-slate-400">{u.last_login.slice(0, 19).replace('T', ' ')}</span>
                        ) : (
                          <span className="text-slate-600 italic">Never</span>
                        )}
                      </td>
                      <td className="p-3 text-[11px]">
                        {u.last_location ? (
                          <div className="flex items-center gap-1 text-emerald-300">
                            <MapPin className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                            <span className="font-mono text-[10px]">{u.last_location}</span>
                          </div>
                        ) : (
                          <span className="text-slate-600 italic">No GPS Lock</span>
                        )}
                      </td>
                      <td className="p-3 text-right space-x-1.5">
                        {isSuperAdmin && u.username !== 'admin' && (
                          <>
                            <button
                              onClick={() => handleSuspendToggle(u.user_id, u.is_suspended)}
                              className={`px-2 py-1 rounded text-[10px] font-bold cursor-pointer transition ${
                                u.is_suspended
                                  ? 'bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-700'
                                  : 'bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-700'
                              }`}
                            >
                              {u.is_suspended ? 'Restore' : 'Suspend'}
                            </button>

                            <button
                              onClick={() => handleLoginToggle(u.user_id, u.login_enabled)}
                              className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[10px] cursor-pointer transition"
                            >
                              {u.login_enabled ? 'Disable Login' : 'Enable Login'}
                            </button>

                            <button
                              onClick={() => handleRevokeSessions(u.user_id)}
                              className="px-2 py-1 bg-amber-950 hover:bg-amber-900 text-amber-300 border border-amber-800 rounded text-[10px] cursor-pointer transition"
                            >
                              Revoke Sessions
                            </button>
                          </>
                        )}
                        {u.username === 'admin' && (
                          <span className="text-slate-500 text-[10px]">Protected Root Identity</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* SUB-TAB 2: SECURITY POLICIES */}
      {adminTab === 'policies' && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
          <h2 className="font-bold text-slate-200 text-sm flex items-center gap-2 border-b border-slate-800 pb-3">
            <Sliders className="w-4 h-4 text-rose-400" />
            Global Platform Security Policies
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg space-y-3">
              <span className="text-slate-300 font-bold text-xs block">Zero-Trust Access Control</span>
              <div className="space-y-3 text-[11px]">
                <label className="flex items-center justify-between cursor-pointer">
                  <span className="text-slate-400">Multi-Factor Authentication (MFA) Enforced</span>
                  <input
                    type="checkbox"
                    checked={securityPolicy.mfa_enforced}
                    onChange={(e) => isSuperAdmin && store.updateSecurityPolicy({ mfa_enforced: e.target.checked }, currentUser!)}
                    className="rounded border-slate-700 bg-slate-900 text-rose-500"
                  />
                </label>

                <label className="flex items-center justify-between cursor-pointer">
                  <span className="text-slate-400">Auto-Isolate Endpoint on File Tamper</span>
                  <input
                    type="checkbox"
                    checked={securityPolicy.tamper_auto_isolate_endpoint}
                    onChange={(e) => isSuperAdmin && store.updateSecurityPolicy({ tamper_auto_isolate_endpoint: e.target.checked }, currentUser!)}
                    className="rounded border-slate-700 bg-slate-900 text-rose-500"
                  />
                </label>

                <label className="flex items-center justify-between cursor-pointer">
                  <span className="text-slate-400">Strict Zero-Trust Network Authorization</span>
                  <input
                    type="checkbox"
                    checked={securityPolicy.zero_trust_strict_mode}
                    onChange={(e) => isSuperAdmin && store.updateSecurityPolicy({ zero_trust_strict_mode: e.target.checked }, currentUser!)}
                    className="rounded border-slate-700 bg-slate-900 text-rose-500"
                  />
                </label>
              </div>
            </div>

            <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg space-y-3">
              <span className="text-slate-300 font-bold text-xs block">Session & Account Limits</span>
              <div className="space-y-3 text-[11px]">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Session Inactivity Timeout</span>
                  <span className="text-cyan-400 font-bold">{securityPolicy.session_timeout_minutes} Minutes</span>
                </div>

                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Max Failed Logins Before Auto-Lockout</span>
                  <span className="text-amber-400 font-bold">{securityPolicy.max_failed_logins_before_lockout} Attempts</span>
                </div>

                <div className="flex items-center justify-between pt-2 border-t border-slate-800">
                  <span className="text-slate-400">Emergency Lab Lockdown Status</span>
                  <span className={securityPolicy.emergency_lockdown_active ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                    {securityPolicy.emergency_lockdown_active ? 'ACTIVE (BLOCKING NON-ADMINS)' : 'NORMAL'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SUB-TAB 3: FIREWALL RULES */}
      {adminTab === 'firewall' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="font-bold text-slate-200 text-sm flex items-center gap-2">
              <Shield className="w-4 h-4 text-rose-400" />
              Perimeter Access Control & Packet Firewall Rules
            </h2>

            <button
              onClick={() => setShowAddFw(true)}
              className="px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-slate-950 font-bold rounded flex items-center gap-1.5 cursor-pointer transition shadow-xs text-xs"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add Rule</span>
            </button>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="p-3">Rule ID</th>
                  <th className="p-3">Direction</th>
                  <th className="p-3">Source</th>
                  <th className="p-3">Destination : Port</th>
                  <th className="p-3">Protocol</th>
                  <th className="p-3">Action</th>
                  <th className="p-3 text-right">Delete</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {firewallRules.map(r => (
                  <tr key={r.rule_id} className="hover:bg-slate-800/40 transition">
                    <td className="p-3 font-mono text-cyan-300">{r.rule_id}</td>
                    <td className="p-3">
                      <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-950 border border-slate-800 text-slate-300">
                        {r.direction}
                      </span>
                    </td>
                    <td className="p-3 text-slate-300 font-mono">{r.source}</td>
                    <td className="p-3 text-slate-300 font-mono">{r.destination}:{r.port}</td>
                    <td className="p-3 text-slate-400">{r.protocol}</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        r.action === 'ALLOW'
                          ? 'bg-emerald-950 text-emerald-300 border-emerald-700'
                          : r.action === 'BLOCK'
                          ? 'bg-rose-950 text-rose-300 border-rose-700'
                          : 'bg-amber-950 text-amber-300 border-amber-700'
                      }`}>
                        {r.action}
                      </span>
                    </td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => handleDeleteFirewallRule(r.rule_id)}
                        className="text-slate-500 hover:text-rose-400 cursor-pointer"
                        title="Delete rule"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SUB-TAB 4: MASTER AUDIT LOGS */}
      {adminTab === 'audit_logs' && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div>
              <h2 className="font-bold text-slate-200 text-sm flex items-center gap-2">
                <FileText className="w-4 h-4 text-purple-400" />
                Immutable Non-Repudiation Master Audit Trails ({auditLogs.length} Records)
              </h2>
              <p className="text-[11px] text-slate-400">
                Cryptographically tracked administrative, user, and security actions
              </p>
            </div>

            <div className="flex items-center gap-2">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
                <input
                  type="text"
                  value={auditSearch}
                  onChange={(e) => setAuditSearch(e.target.value)}
                  placeholder="Filter audit logs..."
                  className="bg-slate-950 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-purple-500 font-mono w-48"
                />
              </div>

              <button
                onClick={handleExportAuditLogsJson}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs flex items-center gap-1.5 cursor-pointer transition"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export JSON</span>
              </button>
            </div>
          </div>

          <div className="space-y-2 max-h-96 overflow-y-auto">
            {filteredAuditLogs.length === 0 ? (
              <div className="p-8 text-center text-slate-500 border border-dashed border-slate-800 rounded">
                No matching audit logs found.
              </div>
            ) : (
              filteredAuditLogs.map(log => (
                <div key={log.log_id} className="p-3 bg-slate-950 border border-slate-800 rounded flex items-center justify-between gap-3 text-xs">
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-slate-200">{log.action}</span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800 text-cyan-300">
                        {log.actor_username} ({log.actor_role})
                      </span>
                      <span className={`text-[10px] font-bold ${log.status === 'SUCCESS' ? 'text-emerald-400' : 'text-rose-400'}`}>
                        [{log.status}]
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400">{log.details}</div>
                  </div>

                  <div className="text-right text-[10px] text-slate-500 shrink-0">
                    <div>{log.timestamp.slice(0, 19).replace('T', ' ')}</div>
                    <div>IP: {log.ip_address}</div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Provision User Modal */}
      {showAddUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-xs p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-md w-full p-5 space-y-4 shadow-2xl">
            <h3 className="text-sm font-bold text-rose-400 flex items-center gap-2">
              <UserPlus className="w-4 h-4" />
              Provision New Platform Account
            </h3>

            <form onSubmit={handleCreateUser} className="space-y-3">
              <div>
                <label className="text-slate-400 block mb-1">Username</label>
                <input
                  type="text"
                  required
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  placeholder="e.g. alice_auditor"
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-200 font-mono"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Email</label>
                <input
                  type="email"
                  required
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  placeholder="alice@mas-csi.lab"
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-200 font-mono"
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-slate-400">Temporary Password</label>
                  <button
                    type="button"
                    onClick={() => setShowNewPassword(!showNewPassword)}
                    className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer font-mono"
                  >
                    {showNewPassword ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                    <span>{showNewPassword ? 'Hide' : 'View'}</span>
                  </button>
                </div>
                <div className="relative">
                  <input
                    type={showNewPassword ? 'text' : 'password'}
                    required
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="Enter password..."
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-200 font-mono pr-9"
                  />
                  <button
                    type="button"
                    onClick={() => setShowNewPassword(!showNewPassword)}
                    className="absolute right-2.5 top-2 text-slate-400 hover:text-slate-200 cursor-pointer"
                  >
                    {showNewPassword ? <EyeOff className="w-3.5 h-3.5 text-cyan-400" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Privilege Role</label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value as UserRole)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-200 font-mono text-xs"
                >
                  <option value="Employee">Employee (Real Lab & Document Vault)</option>
                  <option value="Security Analyst">Security Analyst (SOC, Agents, Forensics)</option>
                  <option value="Auditor">Auditor (Evidence Vault & Reports)</option>
                  <option value="Super Admin">Super Admin (Master Platform Governance)</option>
                </select>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddUser(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 bg-rose-600 hover:bg-rose-500 text-slate-950 font-bold rounded cursor-pointer"
                >
                  Create User
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add Firewall Rule Modal */}
      {showAddFw && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-xs p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-md w-full p-5 space-y-4 shadow-2xl">
            <h3 className="text-sm font-bold text-rose-400 flex items-center gap-2">
              <Shield className="w-4 h-4" />
              Configure Perimeter Firewall Rule
            </h3>

            <form onSubmit={handleAddFirewallRule} className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Direction</label>
                  <select
                    value={fwDirection}
                    onChange={(e) => setFwDirection(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-200 font-mono text-xs"
                  >
                    <option value="INBOUND">INBOUND</option>
                    <option value="OUTBOUND">OUTBOUND</option>
                  </select>
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Action</label>
                  <select
                    value={fwAction}
                    onChange={(e) => setFwAction(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-200 font-mono text-xs"
                  >
                    <option value="BLOCK">BLOCK</option>
                    <option value="ALLOW">ALLOW</option>
                    <option value="QUARANTINE">QUARANTINE</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Source IP / CIDR</label>
                <input
                  type="text"
                  required
                  value={fwSource}
                  onChange={(e) => setFwSource(e.target.value)}
                  placeholder="e.g. 192.168.1.0/24 or ANY"
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-200 font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Destination IP</label>
                  <input
                    type="text"
                    required
                    value={fwDest}
                    onChange={(e) => setFwDest(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-200 font-mono"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Port</label>
                  <input
                    type="text"
                    required
                    value={fwPort}
                    onChange={(e) => setFwPort(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-200 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Protocol</label>
                <select
                  value={fwProtocol}
                  onChange={(e) => setFwProtocol(e.target.value as any)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-200 font-mono text-xs"
                >
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                  <option value="ICMP">ICMP</option>
                  <option value="ANY">ANY</option>
                </select>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddFw(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 bg-rose-600 hover:bg-rose-500 text-slate-950 font-bold rounded cursor-pointer"
                >
                  Save Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
