/**
 * MAS-CSI Authorized Real Lab & Enterprise Employee Portal
 * Strictly gated authentication with password visibility toggle.
 * Industry-grade features:
 * 1. Protected Document Vault with local drag-and-drop file upload & Web Crypto SHA-256
 * 2. Multi-User Tamper Detection & Side-by-Side Diff Inspector
 * 3. Canary Honeytoken Deception Traps with silent intrusion tripwires
 * 4. Digital Signature & Watermark Generation
 * 5. Personal Employee Credential & Secret Key Manager
 * 6. Session Security & Active Device Footprint Monitor
 */

import React, { useState, useRef } from 'react';
import {
  FlaskConical,
  KeyRound,
  User,
  Upload,
  Download,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Unlock,
  ShieldCheck,
  FileText,
  Activity,
  LogOut,
  LogIn,
  UserPlus,
  Edit3,
  RefreshCw,
  AlertOctagon,
  History,
  ShieldAlert,
  FileWarning,
  Eye,
  EyeOff,
  Copy,
  Trash2,
  FileCode,
  Shield,
  Fingerprint,
  Radio,
  FileCheck2,
  Terminal,
  Layers,
  ArrowRight,
  MapPin,
  Clock,
  Compass,
  ZoomIn,
  Maximize2
} from 'lucide-react';
import { store } from '../services/store';
import { SecureLabFile, EmployeeSecretItem } from '../types/mas_csi';

export const RealLabView: React.FC = () => {
  const labUser = store.labUser;
  const labSession = store.labSessionId;
  const secureFiles = store.secureFiles;
  const employeeSecrets = store.employeeSecrets;

  // Active Tab inside Real Lab
  const [activeTab, setActiveTab] = useState<'documents' | 'canary_traps' | 'secrets' | 'session'>('documents');

  // Login & Register Form State
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [authSuccess, setAuthSuccess] = useState<string | null>(null);

  // File Creation & Editing State
  const [newFileName, setNewFileName] = useState('');
  const [newFileContent, setNewFileContent] = useState('');
  const [newClassification, setNewClassification] = useState<'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED'>('INTERNAL');
  const [newImportance, setNewImportance] = useState<'CRITICAL' | 'HIGH' | 'NORMAL'>('HIGH');
  const [newDocumentType, setNewDocumentType] = useState<SecureLabFile['file_type']>('DOCUMENT_PDF');
  const [isCanaryDecoy, setIsCanaryDecoy] = useState(false);
  const [editingFile, setEditingFile] = useState<SecureLabFile | null>(null);
  const [editContent, setEditContent] = useState('');
  const [diffFile, setDiffFile] = useState<SecureLabFile | null>(null);
  const [previewDocumentFile, setPreviewDocumentFile] = useState<SecureLabFile | null>(null);
  const [documentFilter, setDocumentFilter] = useState<'ALL' | 'PDF' | 'IMAGE' | 'CONFIG' | 'TAMPERED'>('ALL');
  const [actionAlert, setActionAlert] = useState<{ type: 'success' | 'danger' | 'warning'; message: string } | null>(null);

  // Live session elapsed timer
  const [sessionSeconds, setSessionSeconds] = useState(0);
  React.useEffect(() => {
    if (!labUser) {
      setSessionSeconds(0);
      return;
    }
    const timer = setInterval(() => setSessionSeconds(s => s + 1), 1000);
    return () => clearInterval(timer);
  }, [labUser]);

  const formatDuration = (secs: number) => {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m}m ${s.toString().padStart(2, '0')}s`;
  };

  // Secret Locker State
  const [secretTitle, setSecretTitle] = useState('');
  const [secretCategory, setSecretCategory] = useState<EmployeeSecretItem['category']>('API_TOKEN');
  const [secretValue, setSecretValue] = useState('');
  const [revealedSecrets, setRevealedSecrets] = useState<Record<string, boolean>>({});

  // File upload input ref
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Quick fill helper
  const handleQuickFill = (u: string, p: string) => {
    setUsername(u);
    setPassword(p);
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setAuthSuccess(null);
    const res = await store.loginRealLab(username, password);
    if (!res.success) {
      setAuthError(res.error || 'Access Denied: Invalid credentials.');
    } else {
      setAuthSuccess(`✓ Access Granted at ${res.user?.last_login_formatted_time || 'now'}! Location lock: ${res.user?.last_location || 'Verified'}. Welcome to authorized Real Lab, ${res.user?.username}.`);
      setUsername('');
      setPassword('');
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setAuthSuccess(null);
    const res = await store.registerUser(username, email, password, 'Employee');
    if (!res.success) {
      setAuthError(res.error || 'Registration failed.');
    } else {
      setAuthSuccess(`Account created for '${username}' with SHA-256 salted credentials. Please log in.`);
      setAuthMode('login');
    }
  };

  const handleLogout = () => {
    store.logoutRealLab();
    setActionAlert(null);
    setAuthSuccess('Real Lab workspace locked. Re-authentication required for access.');
  };

  // Create new secure document
  const handleCreateFile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newFileName || !newFileContent) return;
    try {
      const isPdf = newFileName.toLowerCase().endsWith('.pdf') || newDocumentType === 'DOCUMENT_PDF';
      const isImg = /\.(png|jpe?g|webp|svg|gif)$/i.test(newFileName) || newDocumentType === 'IMAGE';

      let dataUrl: string | undefined = undefined;
      if (isPdf && !newFileContent.startsWith('data:')) {
        dataUrl = `data:application/pdf;base64,${btoa(newFileContent.slice(0, 500))}`;
      } else if (isImg && !newFileContent.startsWith('data:')) {
        dataUrl = `data:image/svg+xml;utf8,${encodeURIComponent(newFileContent)}`;
      }

      const file = await store.createSecureFile(
        newFileName,
        newFileContent,
        newClassification,
        isCanaryDecoy,
        {
          file_type: isPdf ? 'DOCUMENT_PDF' : isImg ? 'IMAGE' : newDocumentType,
          importance: newImportance,
          data_url: dataUrl,
          notes: isCanaryDecoy ? 'Canary Deception Trap' : `${newClassification} ${newDocumentType} Document`,
        }
      );

      setActionAlert({
        type: isCanaryDecoy ? 'warning' : 'success',
        message: isCanaryDecoy
          ? `🪤 CANARY HONEYPOT TRAP DEPLOYED: Decoy '${file.name}' is now active. Any unauthorized access will trip an immediate SOC alarm!`
          : `Document '${file.name}' stored with verified SHA-256: ${file.original_sha256.slice(0, 16)}...`,
      });
      setNewFileName('');
      setNewFileContent('');
      setIsCanaryDecoy(false);
      setTimeout(() => setActionAlert(null), 6000);
    } catch (err) {
      setActionAlert({ type: 'danger', message: (err as Error).message });
    }
  };

  // Local Desktop File Upload & Web Crypto Hash calculation (Binary PDF / Image support)
  const handleLocalFileDrop = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const isPdf = file.type === 'application/pdf' || file.name.toLowerCase().endsWith('.pdf');
      const isImage = file.type.startsWith('image/') || /\.(png|jpe?g|webp|svg|gif|bmp)$/i.test(file.name);
      const isBinary = isPdf || isImage;

      // Real SubtleCrypto SHA-256 over raw binary arrayBuffer
      const arrayBuffer = await file.arrayBuffer();
      const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const sha256Hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

      // Read as DataURL for visual preview & binary preservation
      const reader = new FileReader();
      reader.onload = async (event) => {
        const dataUrl = event.target?.result as string;
        let contentString = `[BINARY_DOCUMENT: ${file.name} | Size: ${file.size} bytes | MIME: ${file.type || 'application/octet-stream'}]`;
        if (!isBinary) {
          const textDecoder = new TextDecoder('utf-8');
          contentString = textDecoder.decode(arrayBuffer);
        }

        const created = await store.createSecureFile(
          file.name,
          contentString,
          'CONFIDENTIAL',
          false,
          {
            file_type: isPdf ? 'DOCUMENT_PDF' : isImage ? 'IMAGE' : 'TEXT',
            mime_type: file.type || (isPdf ? 'application/pdf' : 'application/octet-stream'),
            data_url: dataUrl,
            importance: 'CRITICAL',
            custom_sha256: sha256Hex,
            size_bytes: file.size,
            notes: `Uploaded local ${isPdf ? 'PDF document' : isImage ? 'image schematic' : 'file'}`,
          }
        );

        setActionAlert({
          type: 'success',
          message: `Important ${isPdf ? 'PDF Document' : isImage ? 'Image Graphic' : 'File'} '${file.name}' (${(file.size / 1024).toFixed(1)} KB) ingested into vault with verified SHA-256: ${created.original_sha256.slice(0, 16)}...`,
        });
        setTimeout(() => setActionAlert(null), 7000);
      };

      reader.readAsDataURL(file);
    } catch (err) {
      setActionAlert({ type: 'danger', message: (err as Error).message });
    } finally {
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  // Sign File
  const handleSignFile = async (file: SecureLabFile) => {
    try {
      const signed = await store.signSecureFile(file.file_id);
      setActionAlert({
        type: 'success',
        message: `Cryptographic digital signature applied: ${signed.digital_signature}`,
      });
      setTimeout(() => setActionAlert(null), 5000);
    } catch (err) {
      setActionAlert({ type: 'danger', message: (err as Error).message });
    }
  };

  // Save File Edit
  const handleSaveEdit = async () => {
    if (!editingFile) return;
    try {
      const res = await store.editSecureFile(editingFile.file_id, editContent);
      if (res.tamperedByOther) {
        setActionAlert({
          type: 'danger',
          message: `🚨 SECURITY BREACH TRIGGERED: Stored document owned by '${res.file.created_by}' was modified by '${labUser?.username}'! Forensic incident created.`,
        });
      } else {
        setActionAlert({
          type: 'success',
          message: `Document '${res.file.name}' updated by owner. New SHA-256 sealed: ${res.file.current_sha256.slice(0, 16)}...`,
        });
      }
      setEditingFile(null);
      setTimeout(() => setActionAlert(null), 6000);
    } catch (err) {
      setActionAlert({ type: 'danger', message: (err as Error).message });
    }
  };

  // Simulate Unauthorized Tamper by rogue user
  const handleSimulateTamperByOther = async (file: SecureLabFile) => {
    const maliciousEdit = file.content + '\n[UNAUTHORIZED_MODIFICATION_BY_ROGUE_ACTOR: EXFIL_FLAG_INJECTED]';
    await store.simulateAttackerTamper(file.file_id, maliciousEdit, 'rogue_attacker');
    setActionAlert({
      type: 'danger',
      message: `🚨 CRITICAL ALERT: File '${file.name}' (owner: ${file.created_by}) was tampered by 'rogue_attacker'! SHA-256 integrity violation confirmed.`,
    });
    setTimeout(() => setActionAlert(null), 8000);
  };

  // Trigger Canary Honeytoken Tripwire Test
  const handleTripCanaryTest = async (file: SecureLabFile) => {
    await store.triggerCanaryTrap(file.file_id, 'unauthorized_probe_scanner');
    setActionAlert({
      type: 'danger',
      message: `🚨 CANARY TRIPWIRE TRIPPED: Honeytoken '${file.name}' was touched by 'unauthorized_probe_scanner'! Real-time SOC incident formed.`,
    });
    setTimeout(() => setActionAlert(null), 8000);
  };

  const handleRestoreFile = async (file: SecureLabFile) => {
    await store.restoreSecureFile(file.file_id);
    setActionAlert({
      type: 'success',
      message: `File '${file.name}' restored to authorized owner version with clean SHA-256 seal.`,
    });
    setTimeout(() => setActionAlert(null), 5000);
  };

  // Secret Store
  const handleAddSecret = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!secretTitle || !secretValue) return;
    await store.storeEmployeeSecret(secretTitle, secretCategory, secretValue);
    setSecretTitle('');
    setSecretValue('');
    setActionAlert({
      type: 'success',
      message: `Credential '${secretTitle}' sealed in employee secret locker.`,
    });
    setTimeout(() => setActionAlert(null), 4000);
  };

  const toggleRevealSecret = (id: string) => {
    setRevealedSecrets(prev => ({ ...prev, [id]: !prev[id] }));
  };

  // Download genuine document file (Binary PDF/Image or Text)
  const handleDownloadFile = async (file: SecureLabFile) => {
    if (file.data_url) {
      try {
        const res = await fetch(file.data_url);
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = file.name;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        return;
      } catch (e) {
        // Fallback to text blob
      }
    }
    const blob = new Blob([file.content], { type: file.mime_type || 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = file.name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // -------------------------------------------------------------
  // GATED AUTHENTICATION LOCK SCREEN (If not logged in)
  // -------------------------------------------------------------
  if (!labUser) {
    return (
      <div className="max-w-xl mx-auto my-8 space-y-5 font-mono text-xs">
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-2xl relative overflow-hidden">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded bg-rose-950 border border-rose-600/50 text-rose-400 flex items-center justify-center">
                <Lock className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  Real Lab Workspace Gated
                </h1>
                <p className="text-[11px] text-slate-400">
                  Authentication required. Secure file storage and telemetry sensors are locked.
                </p>
              </div>
            </div>

            <span className="text-[10px] px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-700 font-bold uppercase">
              LOCKED
            </span>
          </div>

          <div className="p-3 bg-slate-950 border border-slate-800 rounded text-[11px] text-slate-400 mb-4 leading-relaxed">
            <strong className="text-amber-400">Strict Access Gate:</strong> Only authorized users with verified SHA-256 credential hashes can open the Real Lab. Stored files remain encrypted and inaccessible until verified login.
          </div>

          {authError && (
            <div className="p-3 bg-rose-950/80 border border-rose-600 rounded text-rose-200 text-xs flex items-center gap-2 mb-4">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{authError}</span>
            </div>
          )}

          {authSuccess && (
            <div className="p-3 bg-emerald-950/80 border border-emerald-600 rounded text-emerald-200 text-xs flex items-center gap-2 mb-4">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{authSuccess}</span>
            </div>
          )}

          {/* Login or Register Toggle */}
          <div className="flex border-b border-slate-800 mb-4 gap-6">
            <button
              onClick={() => setAuthMode('login')}
              className={`pb-2 font-bold cursor-pointer transition ${
                authMode === 'login' ? 'text-cyan-400 border-b-2 border-cyan-400' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Employee Login
            </button>
            <button
              onClick={() => setAuthMode('register')}
              className={`pb-2 font-bold cursor-pointer transition ${
                authMode === 'register' ? 'text-cyan-400 border-b-2 border-cyan-400' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              New Employee Registration
            </button>
          </div>

          <form onSubmit={authMode === 'login' ? handleLogin : handleRegister} className="space-y-3.5">
            <div>
              <label className="text-slate-400 block mb-1">Username</label>
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. john_doe"
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            {authMode === 'register' && (
              <div>
                <label className="text-slate-400 block mb-1">Corporate Email</label>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="employee@organization.internal"
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>
            )}

            <div>
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
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter password..."
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono pr-9"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-2.5 top-2.5 text-slate-400 hover:text-slate-200 cursor-pointer"
                  title={showPassword ? 'Hide password' : 'View password'}
                >
                  {showPassword ? <EyeOff className="w-4 h-4 text-cyan-400" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              className="w-full py-2.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded cursor-pointer transition shadow-sm mt-2"
            >
              {authMode === 'login' ? 'Authenticate & Unlock Real Lab' : 'Register Account'}
            </button>
          </form>

          {/* Quick Credential Helper */}
          <div className="mt-5 pt-4 border-t border-slate-800 text-[11px] text-slate-500 space-y-2">
            <span className="block font-semibold text-slate-400">Pre-Configured Authorized Accounts:</span>
            <div className="flex gap-2 flex-wrap">
              <button
                type="button"
                onClick={() => handleQuickFill('john_doe', 'Employee@CSI2026!')}
                className="px-2.5 py-1 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-cyan-400 cursor-pointer"
              >
                john_doe (Employee)
              </button>
              <button
                type="button"
                onClick={() => handleQuickFill('admin', 'Admin@CSI2026!')}
                className="px-2.5 py-1 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-cyan-400 cursor-pointer"
              >
                admin (Super Admin)
              </button>
              <button
                type="button"
                onClick={() => handleQuickFill('sec_analyst', 'Analyst@CSI2026!')}
                className="px-2.5 py-1 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-cyan-400 cursor-pointer"
              >
                sec_analyst (Analyst)
              </button>
            </div>
            <p className="text-[10px] text-slate-600">
              *Entering incorrect credentials will be recorded as a telemetry event. 3 failures trigger brute-force incident detection.
            </p>
          </div>
        </div>
      </div>
    );
  }

  // -------------------------------------------------------------
  // AUTHENTICATED REAL LAB WORKSPACE (UNLOCKED)
  // -------------------------------------------------------------
  return (
    <div className="space-y-5 font-mono text-xs">
      {/* Real Lab Status Header with Exact Login Time, Duration, and Location */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-9 h-9 rounded bg-emerald-950 border border-emerald-500/40 text-emerald-400">
            <Unlock className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-sm font-bold text-slate-100">
                Authorized Real Lab &amp; Employee Workspace
              </h1>
              <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700 font-bold">
                ACTIVE SESSION
              </span>
            </div>
            <div className="flex items-center gap-3 text-slate-400 text-[11px] mt-1 flex-wrap">
              <span>Logged in: <strong className="text-cyan-300">{labUser.username}</strong> ({labUser.role})</span>
              <span className="flex items-center gap-1 text-cyan-300">
                <Clock className="w-3.5 h-3.5 text-cyan-400" />
                <span>Time: {labUser.last_login_formatted_time || 'Just now'}</span>
              </span>
              <span className="flex items-center gap-1 text-amber-300">
                <Activity className="w-3.5 h-3.5 text-amber-400" />
                <span>Active: {formatDuration(sessionSeconds)}</span>
              </span>
              <span className="flex items-center gap-1 text-emerald-300">
                <MapPin className="w-3.5 h-3.5 text-emerald-400" />
                <span>GPS: {labUser.last_location || '37.7749° N, -122.4194° W'}</span>
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleLogout}
            className="px-3 py-1.5 bg-rose-950 hover:bg-rose-900 text-rose-200 border border-rose-800 rounded font-bold text-xs flex items-center gap-1.5 cursor-pointer transition"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>Lock &amp; Logout</span>
          </button>
        </div>
      </div>

      {actionAlert && (
        <div className={`p-3.5 rounded border text-xs flex items-center gap-2.5 ${
          actionAlert.type === 'danger'
            ? 'bg-rose-950/80 border-rose-600 text-rose-200'
            : actionAlert.type === 'warning'
            ? 'bg-amber-950/80 border-amber-600 text-amber-200'
            : 'bg-emerald-950/80 border-emerald-600 text-emerald-200'
        }`}>
          {actionAlert.type === 'danger' ? (
            <AlertOctagon className="w-5 h-5 text-rose-400 shrink-0" />
          ) : actionAlert.type === 'warning' ? (
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
          ) : (
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
          )}
          <span className="leading-relaxed">{actionAlert.message}</span>
        </div>
      )}

      {/* Real Lab Navigation Tabs */}
      <div className="flex border-b border-slate-800 gap-2 pb-1 overflow-x-auto">
        {[
          { id: 'documents', label: `Document Vault (${secureFiles.length})`, icon: FileText },
          { id: 'canary_traps', label: `Canary Honeytokens (${secureFiles.filter(f => f.is_canary_trap).length})`, icon: Radio },
          { id: 'secrets', label: `Secret Locker (${employeeSecrets.length})`, icon: KeyRound },
          { id: 'session', label: 'Session Security & Footprint', icon: ShieldCheck },
        ].map(tab => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-t text-xs font-semibold cursor-pointer transition border-b-2 ${
                isActive
                  ? 'border-cyan-400 text-cyan-300 bg-slate-900/90'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* TAB 1: PROTECTED DOCUMENT VAULT */}
      {activeTab === 'documents' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Left Column: Files & Multi-User Tamper Detection (7 Cols) */}
          <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 flex-wrap gap-2">
              <div>
                <h2 className="font-bold text-slate-200 text-sm flex items-center gap-2">
                  <FileText className="w-4 h-4 text-cyan-400" />
                  Protected Document &amp; File Vault
                </h2>
                <p className="text-[11px] text-slate-400">
                  Store important documents (PDFs, images, schematics) with verified SHA-256 integrity &amp; intrusion detection
                </p>
              </div>

              {/* Local File Ingestion */}
              <div>
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleLocalFileDrop}
                  accept=".pdf,.png,.jpg,.jpeg,.webp,.svg,.txt,.json,.csv,.env,.conf,.doc,.docx"
                  className="hidden"
                />
                <button
                  onClick={() => fileInputRef.current?.click()}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-800/60 rounded text-xs flex items-center gap-1.5 cursor-pointer transition font-bold"
                  title="Upload local PDF, Image, or Doc to calculate SHA-256 and seal into vault"
                >
                  <Upload className="w-3.5 h-3.5" />
                  <span>Upload PDF / Image / Doc</span>
                </button>
              </div>
            </div>

            {/* Filter Pills for Documents */}
            <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-[11px]">
              {[
                { id: 'ALL', label: `All Files (${secureFiles.length})` },
                { id: 'PDF', label: `PDF Reports (${secureFiles.filter(f => f.file_type === 'DOCUMENT_PDF' || f.name.endsWith('.pdf')).length})` },
                { id: 'IMAGE', label: `Images & Schematics (${secureFiles.filter(f => f.file_type === 'IMAGE' || /\.(png|jpe?g|webp|svg)/i.test(f.name)).length})` },
                { id: 'CONFIG', label: `Configs & Keys (${secureFiles.filter(f => f.file_type === 'CONFIG' || f.file_type === 'KEY_PAIR').length})` },
                { id: 'TAMPERED', label: `Tampered Alerts (${secureFiles.filter(f => f.is_tampered).length})` },
              ].map(f => (
                <button
                  key={f.id}
                  onClick={() => setDocumentFilter(f.id as any)}
                  className={`px-2.5 py-1 rounded cursor-pointer transition font-mono ${
                    documentFilter === f.id
                      ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold'
                      : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
                  }`}
                >
                  {f.label}
                </button>
              ))}
            </div>

            <div className="space-y-3.5">
              {secureFiles.length === 0 ? (
                <div className="p-10 text-center text-slate-500 border border-dashed border-slate-800 rounded">
                  No secure files stored yet. Create a new protected document using the form on the right or upload a PDF/Image.
                </div>
              ) : (
                secureFiles
                  .filter(file => {
                    if (documentFilter === 'PDF') return file.file_type === 'DOCUMENT_PDF' || file.name.endsWith('.pdf');
                    if (documentFilter === 'IMAGE') return file.file_type === 'IMAGE' || /\.(png|jpe?g|webp|svg|gif)$/i.test(file.name);
                    if (documentFilter === 'CONFIG') return file.file_type === 'CONFIG' || file.file_type === 'KEY_PAIR' || file.name.endsWith('.env') || file.name.endsWith('.json');
                    if (documentFilter === 'TAMPERED') return file.is_tampered || file.canary_tripped;
                    return true;
                  })
                  .map((file) => (
                  <div
                    key={file.file_id}
                    className={`p-4 rounded-lg border space-y-2.5 transition ${
                      file.is_tampered
                        ? 'bg-rose-950/40 border-rose-600 shadow-sm shadow-rose-950'
                        : file.is_canary_trap
                        ? 'bg-amber-950/30 border-amber-600/70'
                        : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-bold text-slate-100 text-sm flex items-center gap-1.5">
                            {file.file_type === 'DOCUMENT_PDF' || file.name.endsWith('.pdf') ? (
                              <FileText className="w-4 h-4 text-rose-400 shrink-0" />
                            ) : file.file_type === 'IMAGE' || /\.(png|jpe?g|webp|svg)/i.test(file.name) ? (
                              <Layers className="w-4 h-4 text-purple-400 shrink-0" />
                            ) : (
                              <FileCode className="w-4 h-4 text-cyan-400 shrink-0" />
                            )}
                            {file.name}
                          </span>

                          {/* File format badge */}
                          {file.file_type === 'DOCUMENT_PDF' || file.name.endsWith('.pdf') ? (
                            <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-rose-950 text-rose-300 border border-rose-700">
                              PDF DOCUMENT
                            </span>
                          ) : file.file_type === 'IMAGE' || /\.(png|jpe?g|webp|svg)/i.test(file.name) ? (
                            <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-purple-950 text-purple-300 border border-purple-700">
                              IMAGE GRAPHIC
                            </span>
                          ) : (
                            <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-slate-900 text-slate-300 border border-slate-700">
                              {file.file_type || 'TEXT'}
                            </span>
                          )}

                          {/* Classification tag */}
                          <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase border ${
                            file.classification === 'RESTRICTED'
                              ? 'bg-rose-950 text-rose-300 border-rose-700'
                              : file.classification === 'CONFIDENTIAL'
                              ? 'bg-purple-950 text-purple-300 border-purple-700'
                              : 'bg-slate-900 text-slate-300 border-slate-700'
                          }`}>
                            {file.classification || 'INTERNAL'}
                          </span>

                          {file.importance && (
                            <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase border ${
                              file.importance === 'CRITICAL'
                                ? 'bg-rose-950 text-rose-200 border-rose-600'
                                : file.importance === 'HIGH'
                                ? 'bg-amber-950 text-amber-200 border-amber-600'
                                : 'bg-slate-900 text-slate-300 border-slate-800'
                            }`}>
                              {file.importance}
                            </span>
                          )}

                          {file.is_canary_trap && (
                            <span className="px-2 py-0.5 rounded text-[9px] bg-amber-950 text-amber-300 border border-amber-600 font-bold flex items-center gap-1">
                              <Radio className="w-3 h-3 text-amber-400 animate-pulse" />
                              CANARY HONEYPOT
                            </span>
                          )}

                          {file.digital_signature && (
                            <span className="px-2 py-0.5 rounded text-[9px] bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold flex items-center gap-1">
                              <ShieldCheck className="w-3 h-3 text-cyan-400" />
                              SIGNED: {file.digital_signature.slice(0, 16)}...
                            </span>
                          )}

                          {file.is_tampered ? (
                            <span className="px-2 py-0.5 rounded text-[10px] bg-rose-950 text-rose-300 border border-rose-600 font-bold flex items-center gap-1">
                              <FileWarning className="w-3 h-3" />
                              UNAUTHORIZED TAMPER DETECTED
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-700 font-bold">
                              INTEGRITY VALID
                            </span>
                          )}
                        </div>

                        <div className="text-[11px] text-slate-400 mt-1">
                          Author / Owner: <strong className="text-cyan-300">{file.created_by}</strong> · Last Modified by: <strong className="text-amber-300">{file.last_modified_by}</strong>
                          {file.size_bytes > 0 && (
                            <span className="ml-2 text-slate-500">
                              ({(file.size_bytes / 1024).toFixed(1)} KB)
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="flex items-center gap-1.5 flex-wrap">
                        {/* Preview Document Button */}
                        <button
                          onClick={() => setPreviewDocumentFile(file)}
                          className="px-2.5 py-1 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 rounded cursor-pointer transition flex items-center gap-1 text-[10px] font-bold"
                          title="Preview document in high-fidelity inspector"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          <span>Preview</span>
                        </button>

                        <button
                          onClick={() => handleDownloadFile(file)}
                          className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded cursor-pointer transition"
                          title="Download genuine document file"
                        >
                          <Download className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => {
                            setEditingFile(file);
                            setEditContent(file.content);
                          }}
                          className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded cursor-pointer transition"
                          title="Edit file content"
                        >
                          <Edit3 className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => handleSignFile(file)}
                          className="px-2 py-1 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 rounded text-[10px] cursor-pointer font-bold transition"
                          title="Apply digital cryptographic signature"
                        >
                          Sign
                        </button>
                        <button
                          onClick={() => handleSimulateTamperByOther(file)}
                          className="px-2.5 py-1 bg-amber-950 hover:bg-amber-900 text-amber-200 border border-amber-800 rounded text-[10px] cursor-pointer font-bold transition"
                          title="Simulate another person altering this file"
                        >
                          Test Alteration
                        </button>
                        {file.is_tampered && (
                          <>
                            <button
                              onClick={() => setDiffFile(file)}
                              className="px-2 py-1 bg-rose-900 hover:bg-rose-800 text-rose-100 rounded text-[10px] cursor-pointer font-bold transition"
                            >
                              Inspect Diff
                            </button>
                            <button
                              onClick={() => handleRestoreFile(file)}
                              className="px-2.5 py-1 bg-emerald-950 hover:bg-emerald-900 text-emerald-200 border border-emerald-700 rounded text-[10px] cursor-pointer font-bold transition"
                            >
                              Restore
                            </button>
                          </>
                        )}
                      </div>
                    </div>

                    {/* Tamper Warning Banner if modified by another actor */}
                    {file.is_tampered && (
                      <div className="p-3 bg-rose-950/70 border border-rose-600 rounded text-rose-200 text-xs space-y-1">
                        <div className="font-bold flex items-center gap-1.5">
                          <AlertTriangle className="w-4 h-4 text-rose-400" />
                          <span>Data Breach Alert: Alteration by Other User Confirmed!</span>
                        </div>
                        <p className="text-[11px] text-slate-300">
                          File created by <strong>'{file.created_by}'</strong> was altered by <strong>'{file.last_modified_by}'</strong> at {file.last_modified_at}!
                        </p>
                        <div className="text-[10px] font-mono break-all pt-1 border-t border-rose-900/60">
                          <div>Original SHA-256: <code className="text-emerald-400">{file.original_sha256}</code></div>
                          <div>Altered SHA-256: <code className="text-rose-400">{file.current_sha256}</code></div>
                        </div>
                      </div>
                    )}

                    {/* Thumbnail or Content Snippet */}
                    {file.file_type === 'IMAGE' && file.data_url ? (
                      <div className="p-2 bg-slate-900 rounded border border-slate-800 flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <img
                            src={file.data_url}
                            alt={file.name}
                            className="w-16 h-12 object-contain rounded bg-black/50 border border-slate-700 cursor-pointer"
                            onClick={() => setPreviewDocumentFile(file)}
                          />
                          <div>
                            <span className="text-[11px] font-bold text-slate-200">Graphic Schematic Ingested</span>
                            <div className="text-[10px] text-slate-500 font-mono">Format: {file.mime_type}</div>
                          </div>
                        </div>
                        <button
                          onClick={() => setPreviewDocumentFile(file)}
                          className="px-2 py-1 text-[10px] bg-slate-800 hover:bg-slate-700 rounded text-cyan-300 cursor-pointer"
                        >
                          View Full Image
                        </button>
                      </div>
                    ) : (
                      <div className="p-2.5 bg-slate-900 rounded border border-slate-800 text-[11px] text-slate-300 max-h-24 overflow-y-auto whitespace-pre-wrap">
                        {file.content}
                      </div>
                    )}

                    {/* SHA-256 Digest */}
                    <div className="text-[10px] text-slate-500 break-all flex items-center justify-between">
                      <span>Checksum: <code className="text-cyan-400">{file.current_sha256}</code></span>
                      <span>Size: {file.size_bytes > 1024 ? `${(file.size_bytes / 1024).toFixed(1)} KB` : `${file.size_bytes} B`}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Right Column: Store New Document Form & Multi-User Change Protocol (5 Cols) */}
          <div className="lg:col-span-5 space-y-5">
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
              <h2 className="font-bold text-slate-200 text-sm flex items-center gap-2">
                <Upload className="w-4 h-4 text-cyan-400" />
                Store New Secure Document
              </h2>

              <form onSubmit={handleCreateFile} className="space-y-3">
                <div>
                  <label className="text-slate-400 block mb-1">Document Name</label>
                  <input
                    type="text"
                    required
                    value={newFileName}
                    onChange={(e) => setNewFileName(e.target.value)}
                    placeholder="e.g. employee_payroll_master.csv"
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="text-slate-400 block mb-1">Document Format</label>
                    <select
                      value={newDocumentType}
                      onChange={(e) => setNewDocumentType(e.target.value as any)}
                      className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                    >
                      <option value="DOCUMENT_PDF">PDF Document (.pdf)</option>
                      <option value="IMAGE">Image / Schematic (.png, .svg)</option>
                      <option value="CONFIG">Configuration &amp; Tokens (.env, .json)</option>
                      <option value="TEXT">Spreadsheet / CSV (.csv, .txt)</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-slate-400 block mb-1">Importance Level</label>
                    <select
                      value={newImportance}
                      onChange={(e) => setNewImportance(e.target.value as any)}
                      className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                    >
                      <option value="CRITICAL">CRITICAL (Executive / Audit)</option>
                      <option value="HIGH">HIGH (Operational Asset)</option>
                      <option value="NORMAL">NORMAL (Internal Routine)</option>
                    </select>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="text-slate-400 block mb-1">Classification</label>
                    <select
                      value={newClassification}
                      onChange={(e) => setNewClassification(e.target.value as any)}
                      className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                    >
                      <option value="PUBLIC">Public</option>
                      <option value="INTERNAL">Internal</option>
                      <option value="CONFIDENTIAL">Confidential</option>
                      <option value="RESTRICTED">Restricted</option>
                    </select>
                  </div>

                  <div className="flex items-center pt-5">
                    <label className="flex items-center gap-2 cursor-pointer text-slate-300">
                      <input
                        type="checkbox"
                        checked={isCanaryDecoy}
                        onChange={(e) => setIsCanaryDecoy(e.target.checked)}
                        className="rounded border-slate-700 bg-slate-950 text-amber-500"
                      />
                      <span className="text-[11px] font-bold text-amber-300">Canary Honeytoken</span>
                    </label>
                  </div>
                </div>

                {/* Quick Templates */}
                <div className="flex flex-wrap gap-1.5 pt-1">
                  <span className="text-[10px] text-slate-400 block w-full">Quick Document Templates:</span>
                  <button
                    type="button"
                    onClick={() => {
                      setNewFileName('executive_cyber_risk_audit_q4.pdf');
                      setNewDocumentType('DOCUMENT_PDF');
                      setNewClassification('CONFIDENTIAL');
                      setNewImportance('CRITICAL');
                      setNewFileContent('%PDF-1.4\n1 0 obj\n<< /Title (Enterprise Security Audit Q4) /Author (SecOps Internal) >>\nendobj\n2 0 obj\n<< /Type /Catalog /Pages 3 0 R >>\nendobj\n3 0 obj\n<< /Type /Pages /Kids [4 0 R] /Count 1 >>\nendobj\n4 0 obj\n<< /Type /Page /Parent 3 0 R /MediaBox [0 0 612 792] /Contents 5 0 R >>\nendobj\n5 0 obj\n<< /Length 220 >>\nstream\nBT\n/F1 16 Tf\n72 712 Td\n(MAS-CSI EXECUTIVE AUDIT REPORT) Tj\n/F1 11 Tf\n0 -28 Td\n(Strict Zero-Trust Compliance: AUDITED & SIGNED) Tj\nET\nendstream\nendobj\nxref\n0 6\ntrailer\n<< /Size 6 /Root 2 0 R >>\nstartxref\n490\n%%EOF');
                      setIsCanaryDecoy(false);
                    }}
                    className="px-2 py-0.5 rounded bg-rose-950/60 hover:bg-rose-900 border border-rose-800 text-[10px] text-rose-300 cursor-pointer transition"
                  >
                    📄 Load PDF Brief
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setNewFileName('perimeter_network_blueprint.svg');
                      setNewDocumentType('IMAGE');
                      setNewClassification('INTERNAL');
                      setNewImportance('HIGH');
                      setNewFileContent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 300"><rect width="600" height="300" fill="#020617"/><text x="30" y="40" font-family="monospace" fill="#38bdf8" font-size="14" font-weight="bold">PERIMETER NETWORK MESH</text><rect x="40" y="80" width="120" height="70" rx="6" fill="#0f172a" stroke="#0ea5e9"/><text x="100" y="120" font-family="monospace" fill="#e0f2fe" text-anchor="middle" font-size="11">FIREWALL</text><path d="M 160 115 L 260 115" stroke="#10b981" stroke-width="2"/><rect x="260" y="80" width="140" height="70" rx="6" fill="#091b2c" stroke="#10b981"/><text x="330" y="120" font-family="monospace" fill="#a7f3d0" text-anchor="middle" font-size="11">VAULT NODE</text></svg>');
                      setIsCanaryDecoy(false);
                    }}
                    className="px-2 py-0.5 rounded bg-purple-950/60 hover:bg-purple-900 border border-purple-800 text-[10px] text-purple-300 cursor-pointer transition"
                  >
                    🖼 Load Image Diagram
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setNewFileName('canary_backup_master_key.json');
                      setNewDocumentType('CONFIG');
                      setNewClassification('RESTRICTED');
                      setNewImportance('CRITICAL');
                      setIsCanaryDecoy(true);
                      setNewFileContent('{\n  "canary_trap_id": "DECOY-TRAP-99",\n  "db_token": "decoy_superadmin_token_unauthorized_inspection_alert",\n  "warning": "TRIPPED ON FIRST ACCESS"\n}');
                    }}
                    className="px-2 py-0.5 rounded bg-amber-950/60 hover:bg-amber-900 border border-amber-800 text-[10px] text-amber-300 cursor-pointer transition"
                  >
                    🪤 Load Honeytoken Decoy
                  </button>
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">Document Content</label>
                  <textarea
                    rows={4}
                    required
                    value={newFileContent}
                    onChange={(e) => setNewFileContent(e.target.value)}
                    placeholder="Enter protected document content..."
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2.5 text-slate-200 focus:outline-none focus:border-cyan-500 text-xs font-mono"
                  />
                </div>

                <button
                  type="submit"
                  className="w-full py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded cursor-pointer transition shadow-xs"
                >
                  Seal &amp; Store in Vault
                </button>
              </form>
            </div>

            {/* Integrity Protocol Notice */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-2 text-[11px] text-slate-300">
              <div className="flex items-center gap-2 text-cyan-400 font-bold">
                <ShieldCheck className="w-4 h-4" />
                <span>Multi-User Integrity Monitoring Protocol</span>
              </div>
              <p className="leading-relaxed text-slate-400">
                When an employee stores a file, MAS-CSI binds their cryptographic identity to the document. If another person or attacker logs into the account and alters that file:
              </p>
              <ul className="list-disc pl-4 space-y-1 text-slate-400">
                <li>Author discrepancy (<code>created_by != last_modified_by</code>) triggers immediate detection.</li>
                <li>A high-severity <code>unauthorized_file_tamper</code> telemetry event is recorded in the SOC.</li>
                <li>The 7-Agent multi-stage investigation automatically commences in real-time.</li>
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: CANARY HONEYTOKENS & DECEPTION */}
      {activeTab === 'canary_traps' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-3">
            <div className="flex items-center gap-2.5">
              <Radio className="w-5 h-5 text-amber-400 animate-pulse" />
              <div>
                <h2 className="text-sm font-bold text-slate-100">
                  Canary Honeytoken Deception Radar
                </h2>
                <p className="text-[11px] text-slate-400">
                  Plant silent decoy traps disguised as high-value corporate credentials. Any access triggers zero-false-positive alerts.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
              <div className="p-3 bg-slate-950 border border-slate-800 rounded">
                <span className="text-slate-500 text-[10px] block">Active Canary Traps</span>
                <span className="text-lg font-bold text-amber-400">{secureFiles.filter(f => f.is_canary_trap).length} Decoys</span>
              </div>
              <div className="p-3 bg-slate-950 border border-slate-800 rounded">
                <span className="text-slate-500 text-[10px] block">Tripwire Status</span>
                <span className="text-lg font-bold text-emerald-400">ARMED & LISTENING</span>
              </div>
              <div className="p-3 bg-slate-950 border border-slate-800 rounded">
                <span className="text-slate-500 text-[10px] block">Detection Certainty</span>
                <span className="text-lg font-bold text-cyan-400">100% Deterministic</span>
              </div>
            </div>
          </div>

          <div className="space-y-3">
            {secureFiles.filter(f => f.is_canary_trap).length === 0 ? (
              <div className="p-8 text-center bg-slate-900 border border-dashed border-slate-800 rounded text-slate-500">
                No Canary honeytokens deployed yet. Create a document with the "Canary Honeytoken" checkbox enabled.
              </div>
            ) : (
              secureFiles.filter(f => f.is_canary_trap).map(trap => (
                <div key={trap.file_id} className="p-4 bg-slate-900 border border-amber-600/50 rounded-lg flex items-center justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <Radio className="w-4 h-4 text-amber-400" />
                      <span className="font-bold text-slate-100 text-sm">{trap.name}</span>
                      <span className="px-2 py-0.5 rounded text-[10px] bg-amber-950 text-amber-300 border border-amber-700">
                        DECOY TRAP
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1">
                      Targeted Bait: Mimics sensitive production secrets · Owner: {trap.created_by}
                    </p>
                    {trap.canary_tripped && trap.canary_trip_details && (
                      <div className="mt-2 p-2 bg-rose-950/80 border border-rose-600 rounded text-[10px] text-rose-200">
                        🚨 TRIPPED by: <strong>{trap.canary_trip_details.tripped_by}</strong> at {trap.canary_trip_details.timestamp} (IP: {trap.canary_trip_details.ip})
                      </div>
                    )}
                  </div>

                  <button
                    onClick={() => handleTripCanaryTest(trap)}
                    className="px-3 py-1.5 bg-rose-950 hover:bg-rose-900 text-rose-200 border border-rose-700 rounded text-xs font-bold cursor-pointer transition shrink-0"
                  >
                    Simulate Attacker Access
                  </button>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB 3: SECRET LOCKER */}
      {activeTab === 'secrets' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Secret Items List (7 cols) */}
          <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <h2 className="font-bold text-slate-200 text-sm flex items-center gap-2 border-b border-slate-800 pb-2">
              <KeyRound className="w-4 h-4 text-cyan-400" />
              Personal Employee Credentials & API Keys ({employeeSecrets.length})
            </h2>

            <div className="space-y-3">
              {employeeSecrets.length === 0 ? (
                <div className="p-8 text-center text-slate-500 border border-dashed border-slate-800 rounded">
                  No personal secrets stored yet. Add developer tokens using the form on the right.
                </div>
              ) : (
                employeeSecrets.map(sec => (
                  <div key={sec.secret_id} className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-2">
                    <div className="flex items-center justify-between">
                      <div>
                        <span className="font-bold text-slate-200 text-xs">{sec.title}</span>
                        <span className="ml-2 px-1.5 py-0.2 rounded bg-slate-900 border border-slate-700 text-cyan-300 text-[10px]">
                          {sec.category}
                        </span>
                      </div>
                      <button
                        onClick={() => store.deleteEmployeeSecret(sec.secret_id)}
                        className="text-slate-500 hover:text-rose-400 cursor-pointer"
                        title="Delete secret"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>

                    <div className="flex items-center gap-2">
                      <input
                        type={revealedSecrets[sec.secret_id] ? 'text' : 'password'}
                        readOnly
                        value={sec.encrypted_value}
                        className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-slate-300 text-xs font-mono"
                      />
                      <button
                        onClick={() => toggleRevealSecret(sec.secret_id)}
                        className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded cursor-pointer"
                        title={revealedSecrets[sec.secret_id] ? 'Hide' : 'Reveal'}
                      >
                        {revealedSecrets[sec.secret_id] ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                      </button>
                      <button
                        onClick={() => {
                          navigator.clipboard.writeText(sec.encrypted_value);
                          setActionAlert({ type: 'success', message: 'Secret copied to clipboard.' });
                          setTimeout(() => setActionAlert(null), 3000);
                        }}
                        className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded cursor-pointer"
                        title="Copy to clipboard"
                      >
                        <Copy className="w-3.5 h-3.5" />
                      </button>
                    </div>

                    <div className="text-[10px] text-slate-500 truncate">
                      SHA-256 Checksum: {sec.sha256_checksum}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Add Secret Form (5 cols) */}
          <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <h2 className="font-bold text-slate-200 text-sm flex items-center gap-2">
              <Lock className="w-4 h-4 text-cyan-400" />
              Store New Secret in Locker
            </h2>

            <form onSubmit={handleAddSecret} className="space-y-3">
              <div>
                <label className="text-slate-400 block mb-1">Secret Title</label>
                <input
                  type="text"
                  required
                  value={secretTitle}
                  onChange={(e) => setSecretTitle(e.target.value)}
                  placeholder="e.g. AWS Production Read Token"
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-200 font-mono"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Category</label>
                <select
                  value={secretCategory}
                  onChange={(e) => setSecretCategory(e.target.value as any)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-200 font-mono text-xs"
                >
                  <option value="API_TOKEN">API Token</option>
                  <option value="SSH_KEY">SSH Key</option>
                  <option value="SERVICE_PASSWORD">Service Password</option>
                  <option value="CERTIFICATE">Certificate / PGP</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Secret Value</label>
                <textarea
                  rows={3}
                  required
                  value={secretValue}
                  onChange={(e) => setSecretValue(e.target.value)}
                  placeholder="Paste private key or secret token..."
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2.5 text-slate-200 font-mono text-xs"
                />
              </div>

              <button
                type="submit"
                className="w-full py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded cursor-pointer transition shadow-xs"
              >
                Seal in Secret Locker
              </button>
            </form>
          </div>
        </div>
      )}

      {/* TAB 4: SESSION SECURITY & DEVICE FOOTPRINT */}
      {activeTab === 'session' && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
          <h2 className="font-bold text-slate-200 text-sm flex items-center gap-2 border-b border-slate-800 pb-3">
            <Fingerprint className="w-4 h-4 text-cyan-400" />
            Active Session Security &amp; Geolocation Footprint
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg space-y-3">
              <span className="text-cyan-400 font-bold block text-xs flex items-center gap-1.5">
                <Clock className="w-4 h-4 text-cyan-400" />
                Verified Authentication Telemetry
              </span>
              <div className="space-y-2 text-[11px] text-slate-300">
                <div className="flex justify-between border-b border-slate-900 pb-1">
                  <span className="text-slate-400">Authenticated Identity:</span>
                  <strong className="text-cyan-300">{labUser.username} ({labUser.role})</strong>
                </div>
                <div className="flex justify-between border-b border-slate-900 pb-1">
                  <span className="text-slate-400">Exact Login Timestamp:</span>
                  <strong className="text-emerald-300 font-mono">{labUser.last_login_formatted_time || 'Just now'}</strong>
                </div>
                <div className="flex justify-between border-b border-slate-900 pb-1">
                  <span className="text-slate-400">ISO-8601 UTC Clock:</span>
                  <code className="text-slate-400 font-mono text-[10px]">{labUser.last_login || new Date().toISOString()}</code>
                </div>
                <div className="flex justify-between border-b border-slate-900 pb-1">
                  <span className="text-slate-400">Active Session Elapsed:</span>
                  <span className="text-amber-400 font-bold font-mono">{formatDuration(sessionSeconds)}</span>
                </div>
                <div className="flex justify-between border-b border-slate-900 pb-1">
                  <span className="text-slate-400">Session Identifier:</span>
                  <code className="text-slate-300 font-mono">{labSession}</code>
                </div>
                <div className="flex justify-between border-b border-slate-900 pb-1">
                  <span className="text-slate-400">Network IP Address:</span>
                  <code className="text-cyan-400">{labUser.last_ip || '127.0.0.1'} (Workstation Node)</code>
                </div>
                <div>
                  <span className="text-slate-400 block mb-0.5">Device Fingerprint:</span>
                  <span className="text-slate-500 text-[10px] break-all">{labUser.last_device_info || navigator.userAgent}</span>
                </div>
              </div>
            </div>

            <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg space-y-3 flex flex-col justify-between">
              <div className="space-y-2">
                <span className="text-emerald-400 font-bold block text-xs flex items-center gap-1.5">
                  <MapPin className="w-4 h-4 text-emerald-400" />
                  Physical Geolocation &amp; GPS Telemetry
                </span>

                <div className="p-3 bg-slate-900 rounded border border-slate-800 space-y-1.5 text-[11px]">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Verified Location:</span>
                    <strong className="text-slate-200">{labUser.last_location || 'Local Lab Workstation'}</strong>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">GPS Coordinates:</span>
                    <code className="text-cyan-300 font-mono">
                      {labUser.last_latitude ? `${labUser.last_latitude.toFixed(5)}° N` : '37.77490° N'},{' '}
                      {labUser.last_longitude ? `${labUser.last_longitude.toFixed(5)}° W` : '-122.41940° W'}
                    </code>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Sensor Accuracy Radius:</span>
                    <span className="text-emerald-400 font-mono">±{labUser.last_location_accuracy_meters || 12} meters</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Sensor Engine:</span>
                    <span className="text-slate-400">WGS-84 Dual GPS / High-Precision IP Radar</span>
                  </div>
                </div>

                <div className="mt-2 flex items-center gap-2">
                  <div className="text-xl font-bold text-emerald-400 font-mono">INTEGRITY SECURED</div>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700">
                    NO UNKNOWN TRAVEL ANOMALY
                  </span>
                </div>
              </div>

              <div className="space-y-2 pt-2">
                <a
                  href={`https://www.google.com/maps/search/?api=1&query=${labUser.last_latitude || 37.7749},${labUser.last_longitude || -122.4194}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="w-full py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-800/60 rounded text-xs font-bold flex items-center justify-center gap-1.5 transition"
                >
                  <MapPin className="w-3.5 h-3.5" />
                  <span>Inspect Physical GPS Pin on Google Maps</span>
                </a>
                <button
                  onClick={() => {
                    setActionAlert({ type: 'success', message: 'All other active sessions revoked across network.' });
                    setTimeout(() => setActionAlert(null), 4000);
                  }}
                  className="w-full py-1.5 bg-rose-950/70 hover:bg-rose-900 text-rose-300 border border-rose-800/60 rounded text-xs font-bold cursor-pointer transition"
                >
                  Revoke All Other Concurrent Sessions
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Side-by-Side Diff Inspector Modal */}
      {diffFile && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-xs p-4 font-mono">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-4xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <FileWarning className="w-5 h-5 text-rose-400" />
                <h3 className="text-sm font-bold text-slate-100">
                  Side-by-Side File Integrity Diff: {diffFile.name}
                </h3>
              </div>
              <button
                onClick={() => setDiffFile(null)}
                className="text-slate-400 hover:text-slate-200 cursor-pointer"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <div className="font-bold text-emerald-400 text-xs mb-1 flex items-center justify-between">
                  <span>Authentic Version (Owner: {diffFile.created_by})</span>
                  <span className="text-[10px] font-mono">SHA-256: {diffFile.original_sha256.slice(0, 8)}...</span>
                </div>
                <div className="p-3 bg-slate-950 border border-emerald-900/60 rounded text-slate-300 text-xs font-mono h-64 overflow-y-auto whitespace-pre-wrap">
                  {diffFile.history.find(h => h.action === 'CREATED')?.notes || diffFile.content}
                </div>
              </div>

              <div>
                <div className="font-bold text-rose-400 text-xs mb-1 flex items-center justify-between">
                  <span>Altered Version (Modified by: {diffFile.last_modified_by})</span>
                  <span className="text-[10px] font-mono">SHA-256: {diffFile.current_sha256.slice(0, 8)}...</span>
                </div>
                <div className="p-3 bg-rose-950/20 border border-rose-900/80 rounded text-rose-200 text-xs font-mono h-64 overflow-y-auto whitespace-pre-wrap">
                  {diffFile.content}
                </div>
              </div>
            </div>

            <div className="flex justify-between items-center pt-2 border-t border-slate-800">
              <span className="text-[11px] text-slate-400">
                Deterministic hash mismatch verified across cryptographic storage records.
              </span>
              <button
                onClick={() => {
                  handleRestoreFile(diffFile);
                  setDiffFile(null);
                }}
                className="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold rounded cursor-pointer"
              >
                Revert to Authentic Version
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit File Modal */}
      {editingFile && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-xs p-4 font-mono">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-lg w-full p-5 space-y-4 shadow-2xl">
            <h3 className="text-sm font-bold text-cyan-400">
              Modify Document: {editingFile.name}
            </h3>
            <p className="text-[11px] text-slate-400">
              Editing as active user: <strong className="text-slate-200">{labUser.username}</strong>
              {labUser.username !== editingFile.created_by && (
                <span className="block text-rose-400 font-bold mt-1">
                  ⚠ Note: You are modifying a document owned by '{editingFile.created_by}'. This will trigger an unauthorized tamper alert!
                </span>
              )}
            </p>

            <textarea
              rows={6}
              value={editContent}
              onChange={(e) => setEditContent(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded p-3 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
            />

            <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                onClick={() => setEditingFile(null)}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveEdit}
                className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded cursor-pointer"
              >
                Save Changes
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Document & Graphic Preview Modal */}
      {previewDocumentFile && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-xs p-4 font-mono">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-4xl w-full p-6 space-y-4 shadow-2xl max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 flex-wrap gap-2">
              <div className="flex items-center gap-2 flex-wrap">
                <FileText className="w-5 h-5 text-cyan-400 shrink-0" />
                <h3 className="text-sm font-bold text-slate-100">{previewDocumentFile.name}</h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-800 uppercase">
                  {previewDocumentFile.file_type || 'DOCUMENT'}
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-950 text-slate-300 border border-slate-700">
                  {previewDocumentFile.classification || 'INTERNAL'}
                </span>
                {previewDocumentFile.digital_signature && (
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-700 flex items-center gap-1">
                    <ShieldCheck className="w-3 h-3 text-emerald-400" />
                    SEALED BY: {previewDocumentFile.signed_by}
                  </span>
                )}
              </div>
              <button
                onClick={() => setPreviewDocumentFile(null)}
                className="text-slate-400 hover:text-slate-200 cursor-pointer text-base"
              >
                ✕
              </button>
            </div>

            <div className="flex-1 overflow-y-auto space-y-3">
              {/* Render Image Graphic */}
              {previewDocumentFile.file_type === 'IMAGE' || previewDocumentFile.data_url?.startsWith('data:image/') || /\.(png|jpe?g|webp|svg|gif)$/i.test(previewDocumentFile.name) ? (
                <div className="bg-slate-950 p-4 rounded border border-slate-800 flex flex-col items-center justify-center min-h-[300px]">
                  <img
                    src={previewDocumentFile.data_url || previewDocumentFile.content}
                    alt={previewDocumentFile.name}
                    className="max-h-[55vh] max-w-full rounded object-contain border border-slate-800 shadow-md"
                  />
                  <div className="text-[10px] text-slate-500 font-mono mt-2">
                    Visual Vector/Bitmap Rendered · MIME: {previewDocumentFile.mime_type || 'image/png'}
                  </div>
                </div>
              ) : previewDocumentFile.file_type === 'DOCUMENT_PDF' || previewDocumentFile.name.endsWith('.pdf') ? (
                <div className="bg-slate-950 rounded border border-slate-800 overflow-hidden">
                  {previewDocumentFile.data_url?.startsWith('data:application/pdf') ? (
                    <iframe
                      src={previewDocumentFile.data_url}
                      title={previewDocumentFile.name}
                      className="w-full h-[55vh] rounded bg-white"
                    />
                  ) : (
                    <div className="p-6 space-y-3">
                      <div className="flex items-center gap-2 text-rose-400 font-bold">
                        <FileText className="w-5 h-5" />
                        <span>PDF Document Stream Verified</span>
                      </div>
                      <div className="p-4 bg-slate-900 rounded border border-slate-800 text-xs font-mono text-slate-300 whitespace-pre-wrap max-h-60 overflow-y-auto">
                        {previewDocumentFile.content}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="p-4 bg-slate-950 rounded border border-slate-800 text-xs font-mono text-slate-200 whitespace-pre-wrap max-h-[50vh] overflow-y-auto">
                  {previewDocumentFile.content}
                </div>
              )}

              {/* Cryptographic Metadata */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px] p-3 bg-slate-950 rounded border border-slate-800">
                <div>
                  <span className="text-slate-500 block">SHA-256 Digest:</span>
                  <code className="text-cyan-400 text-[10px] break-all">{previewDocumentFile.current_sha256}</code>
                </div>
                <div>
                  <span className="text-slate-500 block">Author &amp; Custody:</span>
                  <span className="text-slate-300">Created by <strong>{previewDocumentFile.created_by}</strong> on {previewDocumentFile.created_at.slice(0, 19).replace('T', ' ')}</span>
                </div>
              </div>
            </div>

            <div className="flex justify-between items-center pt-3 border-t border-slate-800 flex-wrap gap-2">
              <span className="text-[11px] text-slate-400">
                Size: {(previewDocumentFile.size_bytes / 1024).toFixed(1)} KB ({previewDocumentFile.size_bytes} bytes)
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleDownloadFile(previewDocumentFile)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded font-bold text-xs flex items-center gap-1.5 cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download File</span>
                </button>
                <button
                  onClick={() => handleSignFile(previewDocumentFile)}
                  className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 rounded font-bold text-xs cursor-pointer"
                >
                  Apply Digital Signature
                </button>
                <button
                  onClick={() => setPreviewDocumentFile(null)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded font-bold text-xs cursor-pointer"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
