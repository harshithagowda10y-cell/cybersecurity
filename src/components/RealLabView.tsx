/**
 * MAS-CSI Authorized Real Lab & Enterprise Employee Portal
 * Multi-Factor Authentication (MFA) with Secondary TOTP Verification Step
 * High-Precision Geolocation & Microsecond Timestamp Telemetry
 * File Integrity Monitoring (FIM) Service with Automated Notifications & One-Click Revert
 * Storage for Important Documents (PDFs, Images, Schematics, Configurations)
 */

import React, { useState, useRef, useEffect } from 'react';
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
  ArrowLeft,
  MapPin,
  Clock,
  Compass,
  ZoomIn,
  Maximize2,
  QrCode,
  Check,
  RotateCcw,
  Sliders,
  ExternalLink,
  BellRing,
  Mail
} from 'lucide-react';
import { store } from '../services/store';
import { SecureLabFile, EmployeeSecretItem, FileIntegrityNotification } from '../types/mas_csi';
import { getCurrentTotp, verifyTotpToken, generateQrMatrix } from '../services/totp';
import { useLoginGeolocation, formatExactTimestamp, GeolocationMetadata } from '../hooks/useLoginGeolocation';
import { EmailInboxModal } from './EmailInboxModal';

export const RealLabView: React.FC = () => {
  const labUser = store.labUser;
  const labSession = store.labSessionId;
  const secureFiles = store.secureFiles;
  const employeeSecrets = store.employeeSecrets;
  const fileNotifications = store.fileIntegrityNotifications;

  // Active compartmentalized tab inside Real Lab
  const [activeTab, setActiveTab] = useState<'documents' | 'fim_sentinel' | 'telemetry' | 'canary_traps' | 'secrets'>('documents');

  // Gated Login & 2FA State
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [loginStep, setLoginStep] = useState<1 | 2>(1);
  const [username, setUsername] = useState('john_doe');
  const [email, setEmail] = useState('jdoe@organization.internal');
  const [password, setPassword] = useState('Employee@CSI2026!');
  const [regConfirmPassword, setRegConfirmPassword] = useState('Employee@CSI2026!');
  const [showPassword, setShowPassword] = useState(false);
  const [simulateOutsideOrg, setSimulateOutsideOrg] = useState(false);

  // Email OTP state
  const [targetUserEmail, setTargetUserEmail] = useState<string>('jdoe@organization.internal');
  const [latestDispatchedOtp, setLatestDispatchedOtp] = useState<string | null>(null);
  const [showEmailInbox, setShowEmailInbox] = useState(false);

  // TOTP Step 2 state for Real Lab login
  const [totpSecret, setTotpSecret] = useState('GEZDGNBVGY3TQOJQ');
  const [totpInput, setTotpInput] = useState('');
  const [totpStatus, setTotpStatus] = useState(getCurrentTotp('GEZDGNBVGY3TQOJQ'));
  const [copiedSecret, setCopiedSecret] = useState(false);

  // Geolocation Hook
  const { captureTelemetry, lastTelemetry, loading: geoLoading } = useLoginGeolocation();
  const [currentTelemetry, setCurrentTelemetry] = useState<GeolocationMetadata | null>(null);

  const [authError, setAuthError] = useState<string | null>(null);
  const [authSuccess, setAuthSuccess] = useState<string | null>(null);

  // File Creation & Editing State
  const [newFileName, setNewFileName] = useState('');
  const [newFileContent, setNewFileContent] = useState('');
  const [newClassification, setNewClassification] = useState<'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED'>('CONFIDENTIAL');
  const [newImportance, setNewImportance] = useState<'CRITICAL' | 'HIGH' | 'NORMAL'>('HIGH');
  const [newDocumentType, setNewDocumentType] = useState<SecureLabFile['file_type']>('DOCUMENT_PDF');
  const [isCanaryDecoy, setIsCanaryDecoy] = useState(false);
  const [editingFile, setEditingFile] = useState<SecureLabFile | null>(null);
  const [editContent, setEditContent] = useState('');
  const [diffFile, setDiffFile] = useState<SecureLabFile | null>(null);
  const [previewDocumentFile, setPreviewDocumentFile] = useState<SecureLabFile | null>(null);
  const [documentFilter, setDocumentFilter] = useState<'ALL' | 'PDF' | 'IMAGE' | 'CONFIG' | 'TAMPERED'>('ALL');
  const [actionAlert, setActionAlert] = useState<{ type: 'success' | 'danger' | 'warning'; message: string } | null>(null);

  // Live session elapsed duration timer
  const [sessionSeconds, setSessionSeconds] = useState(0);
  useEffect(() => {
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

  // TOTP rolling 30s countdown interval
  useEffect(() => {
    const interval = setInterval(() => {
      setTotpStatus(getCurrentTotp(totpSecret));
    }, 1000);
    return () => clearInterval(interval);
  }, [totpSecret]);

  // Telemetry init
  useEffect(() => {
    captureTelemetry(simulateOutsideOrg).then(t => setCurrentTelemetry(t));
  }, [simulateOutsideOrg, captureTelemetry]);

  // Quick fill helper
  const handleQuickFill = (u: string, p: string, s: string = 'GEZDGNBVGY3TQOJQ') => {
    setUsername(u);
    setPassword(p);
    setTotpSecret(s);
    setLoginStep(1);
  };

  // Proceed from Step 1 to Step 2 (TOTP & Email OTP)
  const handleProceedToTotp = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setAuthSuccess(null);

    const user = store.users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!user) {
      setAuthError(`Access Denied: Unregistered Identity '${username}'. You must be registered first in the directory before you can request an OTP or access the lab. Click 'Register New Account' below.`);
      return;
    }

    if (user.is_suspended) {
      setAuthError('Access Denied: Account is administratively SUSPENDED by SOC Super Admin.');
      return;
    }

    const telemetry = await captureTelemetry(simulateOutsideOrg);
    setCurrentTelemetry(telemetry);

    // Dispatch 6-digit OTP code directly to user's registered email
    const otpRes = await store.requestOtpToEmail(user.username, telemetry);
    setTargetUserEmail(user.email);
    if (otpRes.otp_code) {
      setLatestDispatchedOtp(otpRes.otp_code);
    }
    setTotpSecret(user.totp_secret || totpSecret);

    setAuthSuccess(`✓ 6-Digit OTP code dispatched to registered email: ${user.email}`);
    setLoginStep(2);
  };

  // Resend fresh OTP to user's registered email
  const handleResendOtp = async () => {
    setAuthError(null);
    setAuthSuccess(null);
    const telemetry = currentTelemetry || (await captureTelemetry(simulateOutsideOrg));
    const otpRes = await store.requestOtpToEmail(username, telemetry);
    if (otpRes.success) {
      setLatestDispatchedOtp(otpRes.otp_code || null);
      setAuthSuccess(`✓ Fresh OTP passcode dispatched to registered email: ${targetUserEmail}`);
    } else {
      setAuthError(otpRes.error || 'Failed to resend OTP code.');
    }
  };

  // Step 2: Verify TOTP / Email OTP and Complete Real Lab Unlock
  const handleVerifyTotpLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setAuthSuccess(null);

    const user = store.users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!user) {
      setAuthError('Identity not found. You must be registered first.');
      return;
    }

    const isValidTotp = verifyTotpToken(totpInput, user.totp_secret || totpSecret);
    const isValidDispatchedEmailOtp = latestDispatchedOtp && totpInput === latestDispatchedOtp;
    const isBypass = totpInput === '994102';

    if (!isValidTotp && !isValidDispatchedEmailOtp && !isBypass) {
      setAuthError(`Invalid or expired OTP passcode. Please check the email sent to ${targetUserEmail} or click 'View Email Inbox'.`);
      return;
    }

    const telemetry = currentTelemetry || (await captureTelemetry(simulateOutsideOrg));
    const res = await store.loginRealLab(username, password, {
      simulateOutsideOrg,
      locationMeta: telemetry,
    });

    if (!res.success) {
      setAuthError(res.error || 'Access Denied: Real Lab authentication failed.');
    } else {
      const outsideNotice = res.outsideOrgAlert
        ? ' 🚨 [HIGH ALERT: Unlocked from outside corporate geofence. Automated SOC incident created.]'
        : ' ✓ Verified within corporate perimeter.';
      setAuthSuccess(
        `✓ Access Granted at ${telemetry.exact_time_formatted}! Location: ${res.user?.last_location}.${outsideNotice} Welcome to authorized Real Lab, ${res.user?.username}.`
      );
      setTotpInput('');
      setLoginStep(1);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setAuthSuccess(null);

    if (password !== regConfirmPassword) {
      setAuthError('Password and Confirm Password do not match.');
      return;
    }
    if (password.length < 8) {
      setAuthError('Password must be at least 8 characters long for zero-trust security.');
      return;
    }
    if (!email.includes('@') || !email.includes('.')) {
      setAuthError('Please provide a valid corporate or personal email address.');
      return;
    }

    const res = await store.registerUser(username, email, password, 'Employee');
    if (!res.success) {
      setAuthError(res.error || 'Registration failed.');
      return;
    }

    setAuthSuccess(`✓ Account registered successfully for '${username}'! Onboarding welcome email sent to ${email}. When logging in, your 2FA OTP codes will be sent to this email. Please sign in below.`);
    setTargetUserEmail(email);
    setAuthMode('login');
    setLoginStep(1);
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
          : `Important document '${file.name}' stored with verified SHA-256: ${file.original_sha256.slice(0, 16)}...`,
      });
      setNewFileName('');
      setNewFileContent('');
      setIsCanaryDecoy(false);
      setTimeout(() => setActionAlert(null), 6000);
    } catch (err) {
      setActionAlert({ type: 'danger', message: (err as Error).message });
    }
  };

  // Local Desktop File Upload & SubtleCrypto Hash calculation (Binary PDF / Image support)
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

  // Save File Edit & Tamper Check
  const handleSaveEdit = async () => {
    if (!editingFile) return;
    try {
      const res = await store.editSecureFile(editingFile.file_id, editContent);
      if (res.tamperedByOther) {
        setActionAlert({
          type: 'danger',
          message: `🚨 SECURITY BREACH TRIGGERED: Stored document owned by '${res.file.created_by}' was modified by '${labUser?.username}'! Automated notification sent to Admin and Owner '${res.file.created_by}'.`,
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
    const maliciousEdit = (file.original_content || file.content) + '\n[UNAUTHORIZED_MODIFICATION_BY_ROGUE_ACTOR: EXFIL_PAYLOAD_INSERTED]';
    await store.simulateAttackerTamper(file.file_id, maliciousEdit, 'rogue_attacker');
    setActionAlert({
      type: 'danger',
      message: `🚨 CRITICAL ALERT: File '${file.name}' (owner: ${file.created_by}) was tampered by 'rogue_attacker'! Automated notification dispatched to Admin & Owner. You can revert this file in FIM Sentinel.`,
    });
    setTimeout(() => setActionAlert(null), 8000);
  };

  // Revert File to Original State
  const handleRevertFile = async (file: SecureLabFile) => {
    await store.restoreSecureFile(file.file_id, labUser?.username);
    setActionAlert({
      type: 'success',
      message: `✓ REVERTED: Document '${file.name}' restored back to pristine data originally stored by '${file.created_by}'. Genesis SHA-256 seal verified.`,
    });
    setTimeout(() => setActionAlert(null), 6000);
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
      } catch {
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

  const qrMatrix = generateQrMatrix(`otpauth://totp/MAS-CSI:${username}?secret=${totpSecret}&issuer=MAS-CSI-Lab`);

  // -------------------------------------------------------------
  // GATED AUTHENTICATION LOCK SCREEN (With 2-Step TOTP & Geolocation)
  // -------------------------------------------------------------
  if (!labUser) {
    return (
      <div className="max-w-2xl mx-auto my-6 space-y-4 font-mono text-xs">
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-2xl relative overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between mb-4 border-b border-slate-800 pb-3 flex-wrap gap-2">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded bg-rose-950 border border-rose-600/50 text-rose-400 flex items-center justify-center shrink-0">
                <Lock className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <span>Real Lab Workspace Gated</span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-normal">
                    {authMode === 'register' ? 'New Registration' : `Step ${loginStep} of 2`}
                  </span>
                </h1>
                <p className="text-[11px] text-slate-400">
                  {authMode === 'register'
                    ? 'Directory Enrollment: Register employee identity & enroll destination email'
                    : loginStep === 1
                    ? 'Step 1: Enter registered employee credentials & capture verified geolocation'
                    : 'Step 2: Secondary verification via 6-digit OTP dispatched to registered email'}
                </p>
              </div>
            </div>

            <span className="text-[10px] px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-700 font-bold uppercase">
              LOCKED
            </span>
          </div>

          {/* Auth Mode Switcher Tabs */}
          <div className="flex border-b border-slate-800 gap-2 pb-1 mb-4">
            <button
              type="button"
              onClick={() => { setAuthMode('login'); setAuthError(null); }}
              className={`px-3.5 py-1.5 rounded-t text-xs font-bold cursor-pointer transition border-b-2 ${
                authMode === 'login'
                  ? 'border-cyan-400 text-cyan-300 bg-slate-900/90'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Sign In (Registered User)
            </button>
            <button
              type="button"
              onClick={() => { setAuthMode('register'); setAuthError(null); }}
              className={`px-3.5 py-1.5 rounded-t text-xs font-bold cursor-pointer transition border-b-2 flex items-center gap-1.5 ${
                authMode === 'register'
                  ? 'border-emerald-400 text-emerald-300 bg-slate-900/90'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <UserPlus className="w-3.5 h-3.5 text-emerald-400" />
              <span>Register New Account</span>
            </button>
          </div>

          {/* Step Progress Indicator (Login Mode) */}
          {authMode === 'login' && (
            <div className="flex items-center gap-2 text-[11px] mb-4">
              <div
                onClick={() => setLoginStep(1)}
                className={`flex-1 py-1.5 px-3 rounded flex items-center justify-between cursor-pointer border ${
                  loginStep === 1
                    ? 'bg-cyan-950/80 border-cyan-500 text-cyan-300 font-bold'
                    : 'bg-slate-950 border-slate-800 text-slate-400'
                }`}
              >
                <span>1. Registered Credentials</span>
                {loginStep === 2 && <Check className="w-3.5 h-3.5 text-emerald-400" />}
              </div>
              <ArrowRight className="w-3.5 h-3.5 text-slate-600 shrink-0" />
              <div
                className={`flex-1 py-1.5 px-3 rounded flex items-center justify-between border ${
                  loginStep === 2
                    ? 'bg-cyan-950/80 border-cyan-500 text-cyan-300 font-bold'
                    : 'bg-slate-950 border-slate-800 text-slate-500'
                }`}
              >
                <span>2. Email OTP &amp; 2FA Verification</span>
                <KeyRound className="w-3.5 h-3.5 text-cyan-400" />
              </div>
            </div>
          )}

          {/* Feedback Banners */}
          {authError && (
            <div className="p-3 bg-rose-950/80 border border-rose-600 rounded text-rose-200 text-xs flex items-center justify-between gap-2 mb-4">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{authError}</span>
              </div>
              {authError.includes('Unregistered Identity') && (
                <button
                  type="button"
                  onClick={() => { setAuthMode('register'); setAuthError(null); }}
                  className="px-2.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold rounded text-[11px] shrink-0 cursor-pointer"
                >
                  Register Now →
                </button>
              )}
            </div>
          )}

          {authSuccess && (
            <div className="p-3 bg-emerald-950/80 border border-emerald-600 rounded text-emerald-200 text-xs flex items-center gap-2 mb-4">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{authSuccess}</span>
            </div>
          )}

          {/* ================= REGISTRATION FORM (MUST BE REGISTERED FIRST) ================= */}
          {authMode === 'register' && (
            <form onSubmit={handleRegister} className="bg-slate-950 border border-slate-800 rounded-lg p-5 space-y-4">
              <div className="border-b border-slate-800 pb-3 flex items-center justify-between flex-wrap gap-2">
                <div>
                  <h3 className="font-bold text-emerald-400 text-sm flex items-center gap-2">
                    <UserPlus className="w-4 h-4" />
                    Directory Registration &amp; Email Enrollment
                  </h3>
                  <p className="text-[11px] text-slate-400">
                    Important: You must be registered first in the directory before you can request an OTP or access the Real Lab environment.
                  </p>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-bold uppercase">
                  Directory Enrollment
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-slate-300 block mb-1">Username / Identity Handle</label>
                  <input
                    type="text"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="e.g. harshitha_gowda"
                    className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-emerald-500 font-mono text-xs"
                  />
                </div>

                <div>
                  <label className="text-slate-300 block mb-1">
                    Registered Email Address (OTP Dispatch Channel)
                  </label>
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="e.g. harshithagowda10y@gmail.com"
                    className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-emerald-500 font-mono text-xs"
                  />
                  <span className="text-[10px] text-cyan-400 mt-1 block">
                    ✉ All 2FA OTP codes and security alerts will be delivered to this email.
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-slate-300 block mb-1">Password (Min 8 chars)</label>
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Create password..."
                    className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-emerald-500 font-mono text-xs"
                  />
                </div>

                <div>
                  <label className="text-slate-300 block mb-1">Confirm Password</label>
                  <input
                    type="password"
                    required
                    value={regConfirmPassword}
                    onChange={(e) => setRegConfirmPassword(e.target.value)}
                    placeholder="Confirm password..."
                    className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-emerald-500 font-mono text-xs"
                  />
                </div>
              </div>

              <div className="flex items-center justify-between pt-2 border-t border-slate-900">
                <button
                  type="button"
                  onClick={() => setAuthMode('login')}
                  className="text-slate-400 hover:text-slate-200 text-xs cursor-pointer"
                >
                  ← Already registered? Switch to Sign In
                </button>

                <button
                  type="submit"
                  className="py-2.5 px-6 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold rounded cursor-pointer transition shadow-md flex items-center gap-2"
                >
                  <UserPlus className="w-4 h-4 stroke-[2.5]" />
                  <span>Complete Registration &amp; Send Welcome Email</span>
                </button>
              </div>
            </form>
          )}

          {/* ================= STEP 1: CREDENTIALS & TELEMETRY ================= */}
          {authMode === 'login' && loginStep === 1 && (
            <form onSubmit={handleProceedToTotp} className="space-y-4">
              <div>
                <label className="text-slate-400 block mb-1">Username / Identity</label>
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="e.g. john_doe"
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

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
                  >
                    {showPassword ? <EyeOff className="w-4 h-4 text-cyan-400" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Live Geolocation Telemetry Sensor */}
              <div className="p-3 bg-slate-950 border border-slate-800 rounded space-y-2">
                <div className="flex items-center justify-between text-[11px]">
                  <div className="flex items-center gap-1.5 text-slate-300 font-semibold">
                    <Compass className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Login Geolocation Telemetry Sensor:</span>
                  </div>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                    GPS Locked (High Accuracy)
                  </span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[10px] text-slate-400">
                  <div className="flex items-center gap-1.5">
                    <MapPin className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    <span>{currentTelemetry?.city || 'San Francisco Lab HQ'}</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    <span>{currentTelemetry?.exact_time_formatted || formatExactTimestamp().formatted}</span>
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-900 flex items-center justify-between">
                  <label className="flex items-center gap-2 cursor-pointer text-[10px] text-amber-300 hover:text-amber-200">
                    <input
                      type="checkbox"
                      checked={simulateOutsideOrg}
                      onChange={(e) => setSimulateOutsideOrg(e.target.checked)}
                      className="accent-amber-500 cursor-pointer"
                    />
                    <span>Simulate Remote / Outside-Organization Access (Geofence Breach)</span>
                  </label>
                  {simulateOutsideOrg && (
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-bold uppercase">
                      🚨 Outside Org Alert
                    </span>
                  )}
                </div>
              </div>

              <div className="flex items-center justify-between pt-1">
                <span className="text-[10px] text-slate-500">
                  Step 1 of 2: Verifies credentials &amp; dispatches OTP to your registered email.
                </span>
                <button
                  type="submit"
                  className="py-2.5 px-6 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded cursor-pointer transition shadow-sm flex items-center gap-2"
                >
                  <span>Proceed to 2FA Step</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>

              {/* Pre-configured Authorized Accounts Helper */}
              <div className="mt-4 pt-3 border-t border-slate-800/80 text-[11px] text-slate-500 space-y-2">
                <span className="block font-semibold text-slate-400">Quick Credentials Helper:</span>
                <div className="flex gap-2 flex-wrap">
                  <button
                    type="button"
                    onClick={() => handleQuickFill('john_doe', 'Employee@CSI2026!', 'GEZDGNBVGY3TQOJQ')}
                    className="px-2.5 py-1 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-cyan-400 cursor-pointer"
                  >
                    john_doe (Employee)
                  </button>
                  <button
                    type="button"
                    onClick={() => handleQuickFill('admin', 'Admin@CSI2026!', 'JBSWY3DPEHPK3PXP')}
                    className="px-2.5 py-1 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-cyan-400 cursor-pointer"
                  >
                    admin (Super Admin)
                  </button>
                  {username && username !== 'john_doe' && username !== 'admin' && (
                    <span className="px-2.5 py-1 bg-emerald-950/60 border border-emerald-800 rounded text-emerald-400">
                      Active: {username}
                    </span>
                  )}
                </div>
              </div>
            </form>
          )}

          {/* ================= STEP 2: EMAIL OTP & TOTP VERIFICATION ================= */}
          {authMode === 'login' && loginStep === 2 && (
            <div className="space-y-4">
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-2">
                    <KeyRound className="w-5 h-5 text-cyan-400" />
                    <div>
                      <h3 className="font-bold text-slate-100 text-sm">
                        Secondary Verification: Email OTP &amp; 2FA Gate
                      </h3>
                      <p className="text-[10px] text-slate-400">
                        Enter the 6-digit passcode delivered to your registered email or authenticator app
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => setLoginStep(1)}
                    className="text-[10px] text-slate-400 hover:text-slate-200 flex items-center gap-1 cursor-pointer"
                  >
                    <ArrowLeft className="w-3.5 h-3.5" />
                    <span>Back to Step 1</span>
                  </button>
                </div>

                {/* DISPATCHED EMAIL OTP BANNER & INBOX VIEWER */}
                <div className="p-3.5 bg-cyan-950/70 border border-cyan-500/70 rounded-lg flex items-center justify-between gap-3 flex-wrap">
                  <div className="flex items-center gap-2.5">
                    <div className="w-8 h-8 rounded bg-cyan-900/60 border border-cyan-500 text-cyan-300 flex items-center justify-center shrink-0">
                      <Mail className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="font-bold text-slate-100 text-xs flex items-center gap-1.5 flex-wrap">
                        <span>OTP Code Sent to Registered Email:</span>
                        <span className="text-cyan-300 font-mono underline font-bold">{targetUserEmail}</span>
                      </div>
                      <p className="text-[10px] text-slate-400 mt-0.5">
                        Check your registered inbox or click 'View Email Inbox' to inspect the delivered email with your 6-digit code.
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setShowEmailInbox(true)}
                      className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded text-xs flex items-center gap-1.5 cursor-pointer transition shadow-md"
                    >
                      <Mail className="w-3.5 h-3.5" />
                      <span>View Email Inbox</span>
                    </button>

                    <button
                      type="button"
                      onClick={handleResendOtp}
                      className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs flex items-center gap-1 cursor-pointer transition"
                      title="Resend fresh OTP to your registered email"
                    >
                      <RefreshCw className="w-3 h-3" />
                      <span>Resend</span>
                    </button>
                  </div>
                </div>

                {/* LIVE DELIVERED EMAIL PREVIEW CARD */}
                <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3 space-y-2">
                  <div className="flex items-center justify-between text-[11px] border-b border-slate-800 pb-1.5">
                    <span className="text-slate-400 flex items-center gap-1">
                      <Mail className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Delivered Email Preview (To: <strong className="text-cyan-300">{targetUserEmail}</strong>)</span>
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                      DELIVERED
                    </span>
                  </div>

                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800 flex items-center justify-between flex-wrap gap-2">
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block font-bold">
                        Subject: [MAS-CSI 2FA Code] One-Time Passcode
                      </span>
                      <div className="text-xl font-extrabold text-cyan-300 font-mono tracking-widest mt-0.5">
                        {latestDispatchedOtp || totpStatus.code}
                      </div>
                      <span className="text-[9px] text-slate-500 block">
                        Valid for 5 minutes · Dispatched to {targetUserEmail}
                      </span>
                    </div>

                    <button
                      type="button"
                      onClick={() => setTotpInput(latestDispatchedOtp || totpStatus.code)}
                      className="px-3 py-1.5 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-700 font-bold rounded text-xs cursor-pointer transition flex items-center gap-1.5"
                    >
                      <Check className="w-3.5 h-3.5" />
                      <span>Auto-Fill Code</span>
                    </button>
                  </div>
                </div>

                {/* Live TOTP Authenticator Generator Card */}
                <div className="grid grid-cols-1 md:grid-cols-12 gap-4 bg-slate-900/90 border border-cyan-500/30 rounded-lg p-3">
                  <div className="md:col-span-4 flex flex-col items-center justify-center border-r border-slate-800/80 pr-2">
                    <div className="p-1.5 bg-slate-950 border border-cyan-500/40 rounded shadow-inner">
                      <div className="grid grid-cols-17 gap-0.5 bg-black p-1 rounded">
                        {qrMatrix.map((row, rIdx) =>
                          row.map((val, cIdx) => (
                            <div
                              key={`${rIdx}-${cIdx}`}
                              className={`w-1.5 h-1.5 ${val ? 'bg-cyan-400' : 'bg-slate-950'}`}
                            />
                          ))
                        )}
                      </div>
                    </div>
                    <span className="text-[9px] text-slate-500 mt-1 font-mono flex items-center gap-1">
                      <QrCode className="w-3 h-3 text-cyan-400" />
                      <span>Authenticator QR</span>
                    </span>
                  </div>

                  <div className="md:col-span-8 space-y-2 flex flex-col justify-center">
                    <div className="flex items-center justify-between">
                      <div>
                        <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-bold">
                          Live TOTP Code (Rolling 30s)
                        </span>
                        <div className="text-xl font-extrabold tracking-widest text-cyan-300 font-mono mt-0.5">
                          {totpStatus.code.slice(0, 3)}-{totpStatus.code.slice(3, 6)}
                        </div>
                      </div>

                      <div className="text-right">
                        <div className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-400">
                          <RefreshCw className="w-3 h-3 animate-spin" style={{ animationDuration: '6s' }} />
                          <span className="font-bold">{totpStatus.secondsRemaining}s</span>
                        </div>
                        <span className="text-[9px] text-slate-500 block">30s window</span>
                      </div>
                    </div>

                    <div className="w-full bg-slate-950 h-1.5 rounded-full overflow-hidden border border-slate-800">
                      <div
                        className={`h-full transition-all duration-1000 ${
                          totpStatus.secondsRemaining < 7 ? 'bg-rose-500' : 'bg-cyan-500'
                        }`}
                        style={{ width: `${(totpStatus.secondsRemaining / 30) * 100}%` }}
                      />
                    </div>
                  </div>
                </div>

                {/* Code Verification Input Form */}
                <form onSubmit={handleVerifyTotpLogin} className="space-y-3 pt-1">
                  <div>
                    <label className="text-slate-300 block mb-1.5 text-xs font-semibold">
                      Enter 6-Digit Passcode
                    </label>
                    <div className="relative max-w-xs">
                      <input
                        type="text"
                        maxLength={6}
                        required
                        autoFocus
                        value={totpInput}
                        onChange={(e) => setTotpInput(e.target.value.replace(/\D/g, ''))}
                        placeholder="e.g. 582914"
                        className="w-full bg-slate-900 border border-cyan-500/60 rounded px-3 py-2 text-xl tracking-widest text-cyan-300 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-400"
                      />
                    </div>
                    <span className="text-[10px] text-slate-500 mt-1 block">
                      Accepts code sent to <code>{targetUserEmail}</code>, rolling authenticator code, or test bypass: <code>994102</code>
                    </span>
                  </div>

                  {/* Session Telemetry Readout */}
                  <div className="p-3 bg-slate-900/60 border border-slate-800 rounded text-[11px] space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Authenticated Identity:</span>
                      <span className="font-bold text-slate-200">{username}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Exact Timestamp:</span>
                      <span className="text-cyan-300 font-mono">
                        {currentTelemetry ? currentTelemetry.exact_time_formatted : formatExactTimestamp().formatted}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Geographic Location:</span>
                      <span className={simulateOutsideOrg ? 'text-rose-400 font-bold' : 'text-emerald-400'}>
                        {simulateOutsideOrg ? '🚨 Outside Corporate Geofence' : (currentTelemetry?.city || 'San Francisco Lab HQ')}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center justify-between pt-2">
                    <button
                      type="button"
                      onClick={() => setLoginStep(1)}
                      className="py-2 px-4 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded font-semibold cursor-pointer transition"
                    >
                      ← Back
                    </button>

                    <button
                      type="submit"
                      className="py-2.5 px-6 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold rounded cursor-pointer transition shadow-md flex items-center gap-2"
                    >
                      <ShieldCheck className="w-4 h-4 stroke-[2.5]" />
                      <span>Verify 2FA &amp; Unlock Real Lab</span>
                    </button>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>

        {/* Corporate Secure Webmail Modal for Real Lab */}
        <EmailInboxModal
          isOpen={showEmailInbox}
          onClose={() => setShowEmailInbox(false)}
          filterEmail={targetUserEmail}
          filterUsername={username}
          onAutoFillOtp={(code) => {
            setTotpInput(code);
            setShowEmailInbox(false);
          }}
        />
      </div>
    );
  }

  // -------------------------------------------------------------
  // AUTHENTICATED REAL LAB WORKSPACE (UNLOCKED & UNCONGESTED SECTIONS)
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
                Authorized Real Lab &amp; Secure Document Vault
              </h1>
              <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700 font-bold">
                ACTIVE 2FA SESSION
              </span>
              {labUser.is_outside_organization && (
                <span className="text-[10px] px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-700 font-bold flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3 text-rose-400" />
                  OUTSIDE GEOFENCE
                </span>
              )}
            </div>
            <div className="flex items-center gap-3 text-slate-400 text-[11px] mt-1 flex-wrap">
              <span>User: <strong className="text-cyan-300">{labUser.username}</strong> ({labUser.role})</span>
              <span className="flex items-center gap-1 text-cyan-300">
                <Clock className="w-3.5 h-3.5 text-cyan-400" />
                <span>Exact Time: {labUser.last_login_formatted_time || 'Live'}</span>
              </span>
              <span className="flex items-center gap-1 text-amber-300">
                <Activity className="w-3.5 h-3.5 text-amber-400" />
                <span>Active: {formatDuration(sessionSeconds)}</span>
              </span>
              <span className="flex items-center gap-1 text-emerald-300">
                <MapPin className="w-3.5 h-3.5 text-emerald-400" />
                <span>GPS: {labUser.last_location || 'San Francisco Lab HQ'}</span>
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

      {/* Real Lab Separate Navigation Tabs (Distinct, Non-congested sections) */}
      <div className="flex border-b border-slate-800 gap-2 pb-1 overflow-x-auto">
        {[
          { id: 'documents', label: `1. Document & Media Vault (${secureFiles.length})`, icon: FileText },
          { id: 'fim_sentinel', label: `2. FIM Sentinel & Revert Station (${secureFiles.filter(f => f.is_tampered).length} alerts)`, icon: ShieldAlert },
          { id: 'telemetry', label: '3. Geolocation & Geofence Telemetry', icon: Compass },
          { id: 'canary_traps', label: `4. Canary Honeytokens (${secureFiles.filter(f => f.is_canary_trap).length})`, icon: Radio },
          { id: 'secrets', label: `5. Secret Locker (${employeeSecrets.length})`, icon: KeyRound },
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

      {/* ================= SECTION 1: PROTECTED DOCUMENT & MEDIA VAULT ================= */}
      {activeTab === 'documents' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Files List Column (7 Cols) */}
          <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 flex-wrap gap-2">
              <div>
                <h2 className="font-bold text-slate-200 text-sm flex items-center gap-2">
                  <FileText className="w-4 h-4 text-cyan-400" />
                  Confidential Document &amp; Media Storage
                </h2>
                <p className="text-[11px] text-slate-400">
                  Store PDF reports, network diagrams, and confidential files with verified SHA-256 seals
                </p>
              </div>

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
                  title="Upload local PDF, Image, or Doc to seal with SHA-256"
                >
                  <Upload className="w-3.5 h-3.5" />
                  <span>Upload PDF / Image / Doc</span>
                </button>
              </div>
            </div>

            {/* Filter Pills */}
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
                  No secure files stored yet. Create a document or upload a PDF/Image.
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

                            <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-slate-900 text-slate-300 border border-slate-700">
                              {file.classification || 'INTERNAL'}
                            </span>

                            {file.is_tampered ? (
                              <span className="px-2 py-0.5 rounded text-[10px] bg-rose-950 text-rose-300 border border-rose-600 font-bold flex items-center gap-1">
                                <FileWarning className="w-3 h-3" />
                                HASH DRIFT DETECTED
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-700 font-bold">
                                SHA-256 VERIFIED
                              </span>
                            )}
                          </div>

                          <div className="text-[11px] text-slate-400 mt-1">
                            Owner: <strong className="text-cyan-300">{file.created_by}</strong> · Last Modified by: <strong className="text-amber-300">{file.last_modified_by}</strong>
                            {file.size_bytes > 0 && (
                              <span className="ml-2 text-slate-500">
                                ({(file.size_bytes / 1024).toFixed(1)} KB)
                              </span>
                            )}
                          </div>
                        </div>

                        {/* Document Action Buttons */}
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <button
                            onClick={() => setPreviewDocumentFile(file)}
                            className="px-2.5 py-1 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 rounded cursor-pointer transition flex items-center gap-1 text-[10px] font-bold"
                          >
                            <Eye className="w-3.5 h-3.5" />
                            <span>Preview</span>
                          </button>
                          <button
                            onClick={() => handleDownloadFile(file)}
                            className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded cursor-pointer transition"
                            title="Download document"
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
                            onClick={() => handleSimulateTamperByOther(file)}
                            className="px-2 py-1 bg-amber-950 hover:bg-amber-900 text-amber-200 border border-amber-800 rounded text-[10px] cursor-pointer font-bold transition"
                            title="Simulate attacker modifying file"
                          >
                            Test Tamper
                          </button>
                          {file.is_tampered && (
                            <button
                              onClick={() => handleRevertFile(file)}
                              className="px-2.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-slate-950 rounded text-[10px] cursor-pointer font-bold transition flex items-center gap-1"
                              title="Revert back to the data employee stored first"
                            >
                              <RotateCcw className="w-3 h-3" />
                              <span>Revert File</span>
                            </button>
                          )}
                        </div>
                      </div>

                      {/* Checksum Bar */}
                      <div className="text-[10px] bg-slate-900 p-2 rounded border border-slate-800 flex items-center justify-between font-mono">
                        <div className="truncate">
                          <span className="text-slate-500">SHA-256: </span>
                          <span className={file.is_tampered ? 'text-rose-400 font-bold' : 'text-cyan-400'}>
                            {file.current_sha256}
                          </span>
                        </div>
                      </div>
                    </div>
                  ))
              )}
            </div>
          </div>

          {/* Right Column: New Document Storage Form (5 Cols) */}
          <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <h2 className="font-bold text-slate-200 text-sm flex items-center gap-2 border-b border-slate-800 pb-3">
              <Upload className="w-4 h-4 text-cyan-400" />
              Store New Document or File
            </h2>

            <form onSubmit={handleCreateFile} className="space-y-3.5">
              <div>
                <label className="text-slate-400 block mb-1">File Name (with extension)</label>
                <input
                  type="text"
                  required
                  value={newFileName}
                  onChange={(e) => setNewFileName(e.target.value)}
                  placeholder="e.g. security_architecture_diagram.pdf"
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Document Format</label>
                  <select
                    value={newDocumentType}
                    onChange={(e) => setNewDocumentType(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value="DOCUMENT_PDF">PDF Document</option>
                    <option value="IMAGE">Image / Schematic</option>
                    <option value="TEXT">Confidential Text</option>
                    <option value="CONFIG">Configuration (.conf/.json)</option>
                    <option value="SOURCE_CODE">Source Code</option>
                  </select>
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">Classification</label>
                  <select
                    value={newClassification}
                    onChange={(e) => setNewClassification(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                    <option value="RESTRICTED">RESTRICTED</option>
                    <option value="INTERNAL">INTERNAL</option>
                    <option value="PUBLIC">PUBLIC</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">File Content / Data Payload</label>
                <textarea
                  rows={5}
                  required
                  value={newFileContent}
                  onChange={(e) => setNewFileContent(e.target.value)}
                  placeholder="Enter document text, SVG markup, or configuration parameters..."
                  className="w-full bg-slate-950 border border-slate-800 rounded p-3 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>

              <button
                type="submit"
                className="w-full py-2.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded cursor-pointer transition shadow-xs flex items-center justify-center gap-2"
              >
                <ShieldCheck className="w-4 h-4 stroke-[2.5]" />
                <span>Store Document &amp; Lock Genesis Hash</span>
              </button>
            </form>
          </div>
        </div>
      )}

      {/* ================= SECTION 2: FILE INTEGRITY MONITORING (FIM) & REVERT STATION ================= */}
      {activeTab === 'fim_sentinel' && (
        <div className="space-y-5">
          {/* FIM Telemetry Summary Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
              <span className="text-slate-400 text-[10px] uppercase font-bold block">Monitored Documents</span>
              <div className="text-xl font-bold text-slate-100 font-mono mt-1">{secureFiles.length}</div>
              <span className="text-[10px] text-cyan-400 mt-1 block">SHA-256 Genesis Locked</span>
            </div>

            <div className="p-4 bg-slate-900 border border-rose-900/50 rounded-lg">
              <span className="text-rose-400 text-[10px] uppercase font-bold block">Active Hash Drifts</span>
              <div className="text-xl font-bold text-rose-400 font-mono mt-1">
                {secureFiles.filter(f => f.is_tampered).length}
              </div>
              <span className="text-[10px] text-slate-400 mt-1 block">Requires Owner/Admin Revert</span>
            </div>

            <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
              <span className="text-slate-400 text-[10px] uppercase font-bold block">Integrity Notifications</span>
              <div className="text-xl font-bold text-amber-400 font-mono mt-1">{fileNotifications.length}</div>
              <span className="text-[10px] text-amber-300 mt-1 block">Dispatched to Admin &amp; Owner</span>
            </div>

            <div className="p-4 bg-slate-900 border border-emerald-900/50 rounded-lg">
              <span className="text-emerald-400 text-[10px] uppercase font-bold block">Revert Guarantee</span>
              <div className="text-xl font-bold text-emerald-400 font-mono mt-1">100%</div>
              <span className="text-[10px] text-slate-400 mt-1 block">Deterministic Rollback</span>
            </div>
          </div>

          {/* Automated Notification Feed (Alerts to Admin & Employee) */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <BellRing className="w-4 h-4 text-amber-400" />
                <h3 className="font-bold text-slate-200 text-sm">
                  Automated Integrity Notifications Feed (Admin &amp; Employee Channel)
                </h3>
              </div>
              <span className="text-[10px] px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">
                Live Alert Stream
              </span>
            </div>

            {fileNotifications.length === 0 ? (
              <div className="p-6 text-center text-slate-500 border border-dashed border-slate-800 rounded">
                ✓ No integrity violations detected. All documents match genesis checksums.
              </div>
            ) : (
              <div className="space-y-3">
                {fileNotifications.map((notif) => {
                  const targetFile = secureFiles.find(f => f.file_id === notif.file_id);
                  return (
                    <div
                      key={notif.notification_id}
                      className={`p-3.5 rounded border space-y-2 ${
                        notif.status === 'REVERTED'
                          ? 'bg-emerald-950/20 border-emerald-800/80'
                          : 'bg-rose-950/30 border-rose-600'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2 flex-wrap">
                        <div className="flex items-center gap-2">
                          <AlertTriangle className={`w-4 h-4 ${notif.status === 'REVERTED' ? 'text-emerald-400' : 'text-rose-400'}`} />
                          <strong className="text-slate-100 text-xs">{notif.file_name}</strong>
                          <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                            notif.status === 'REVERTED' ? 'bg-emerald-950 text-emerald-300' : 'bg-rose-950 text-rose-300'
                          }`}>
                            {notif.status}
                          </span>
                        </div>
                        <span className="text-[10px] text-slate-500">{notif.timestamp.slice(0, 19).replace('T', ' ')}</span>
                      </div>

                      <p className="text-[11px] text-slate-300 leading-relaxed">{notif.message}</p>

                      <div className="flex items-center justify-between text-[10px] pt-1 border-t border-slate-800/80">
                        <div className="text-slate-400">
                          Owner: <strong className="text-cyan-300">{notif.original_owner}</strong> · Altered by: <strong className="text-amber-300">{notif.tampered_by}</strong>
                        </div>

                        {notif.can_revert && targetFile && (
                          <button
                            onClick={() => handleRevertFile(targetFile)}
                            className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold rounded cursor-pointer transition flex items-center gap-1.5"
                          >
                            <RotateCcw className="w-3 h-3" />
                            <span>Revert File to Genesis State</span>
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Full Monitored Files Integrity Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <h3 className="font-bold text-slate-200 text-sm flex items-center gap-2 border-b border-slate-800 pb-3">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              Document Integrity Status &amp; Revert Station
            </h3>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 text-[10px] uppercase">
                    <th className="p-2.5">Document</th>
                    <th className="p-2.5">Owner</th>
                    <th className="p-2.5">Genesis SHA-256</th>
                    <th className="p-2.5">Current SHA-256</th>
                    <th className="p-2.5">Status</th>
                    <th className="p-2.5 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 text-[11px]">
                  {secureFiles.map((f) => (
                    <tr key={f.file_id} className="hover:bg-slate-800/40">
                      <td className="p-2.5 font-bold text-slate-200">{f.name}</td>
                      <td className="p-2.5 text-cyan-300">{f.created_by}</td>
                      <td className="p-2.5 font-mono text-[10px] text-slate-400">{f.original_sha256.slice(0, 16)}...</td>
                      <td className="p-2.5 font-mono text-[10px]">
                        <span className={f.is_tampered ? 'text-rose-400 font-bold' : 'text-slate-400'}>
                          {f.current_sha256.slice(0, 16)}...
                        </span>
                      </td>
                      <td className="p-2.5">
                        {f.is_tampered ? (
                          <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-rose-950 text-rose-300 border border-rose-700">
                            DRIFT DETECTED
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-700">
                            VERIFIED CLEAN
                          </span>
                        )}
                      </td>
                      <td className="p-2.5 text-right space-x-1.5">
                        {f.is_tampered ? (
                          <>
                            <button
                              onClick={() => setDiffFile(f)}
                              className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded text-[10px] cursor-pointer"
                            >
                              Inspect Diff
                            </button>
                            <button
                              onClick={() => handleRevertFile(f)}
                              className="px-2.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold rounded text-[10px] cursor-pointer"
                            >
                              Revert File
                            </button>
                          </>
                        ) : (
                          <button
                            onClick={() => handleSimulateTamperByOther(f)}
                            className="px-2 py-1 bg-amber-950 hover:bg-amber-900 text-amber-200 border border-amber-800 rounded text-[10px] cursor-pointer"
                          >
                            Simulate Tamper
                          </button>
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

      {/* ================= SECTION 3: GEOLOCATION & SESSION TELEMETRY ================= */}
      {activeTab === 'telemetry' && (
        <div className="grid grid-cols-1 md:grid-cols-12 gap-5">
          <div className="md:col-span-6 bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <h3 className="font-bold text-slate-200 text-sm flex items-center gap-2 border-b border-slate-800 pb-3">
              <Clock className="w-4 h-4 text-cyan-400" />
              Exact Login Timing &amp; Session Telemetry
            </h3>

            <div className="p-4 bg-slate-950 border border-slate-800 rounded space-y-3">
              <div className="flex justify-between items-center text-xs">
                <span className="text-slate-400">Exact Local Login Time:</span>
                <span className="text-cyan-300 font-bold">{labUser.last_login_formatted_time || 'Just now'}</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-slate-400">ISO 8601 UTC Timestamp:</span>
                <span className="text-slate-300 font-mono text-[10px]">{labUser.last_login || new Date().toISOString()}</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-slate-400">Active Session Elapsed:</span>
                <span className="text-amber-400 font-bold">{formatDuration(sessionSeconds)}</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-slate-400">Session ID Token:</span>
                <span className="text-slate-300 font-mono text-[10px]">{labSession}</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-slate-400">Workstation Device:</span>
                <span className="text-slate-300 text-[10px]">{labUser.last_device_info || 'Authorized Lab Workstation'}</span>
              </div>
            </div>
          </div>

          <div className="md:col-span-6 bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <h3 className="font-bold text-slate-200 text-sm flex items-center gap-2 border-b border-slate-800 pb-3">
              <MapPin className="w-4 h-4 text-emerald-400" />
              Physical Geofence &amp; Perimeter Lock
            </h3>

            <div className="p-4 bg-slate-950 border border-slate-800 rounded space-y-3">
              <div className="flex justify-between items-center text-xs">
                <span className="text-slate-400">Recorded Coordinates:</span>
                <span className="text-emerald-300 font-mono font-bold">
                  {labUser.last_latitude ? `${labUser.last_latitude.toFixed(4)}° N, ${labUser.last_longitude?.toFixed(4)}° W` : '37.7749° N, -122.4194° W'}
                </span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-slate-400">Location Label:</span>
                <span className="text-slate-200">{labUser.last_location || 'San Francisco Lab HQ'}</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-slate-400">Geofence Compliance:</span>
                <span className={labUser.is_outside_organization ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                  {labUser.is_outside_organization ? '🚨 OUTSIDE CORP PERIMETER' : '✓ VERIFIED CORP CAMPUS'}
                </span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-slate-400">Sensor Engine:</span>
                <span className="text-slate-400">WGS-84 Browser GPS / Precision Network Lock</span>
              </div>
            </div>

            <a
              href={`https://www.google.com/maps/search/?api=1&query=${labUser.last_latitude || 37.7749},${labUser.last_longitude || -122.4194}`}
              target="_blank"
              rel="noopener noreferrer"
              className="w-full py-2 bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-800/60 rounded text-xs font-bold flex items-center justify-center gap-2 transition"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              <span>Open Physical Coordinates in Google Maps</span>
            </a>
          </div>
        </div>
      )}

      {/* ================= SECTION 4: CANARY DECEPTION TRAPS ================= */}
      {activeTab === 'canary_traps' && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h2 className="font-bold text-slate-200 text-sm flex items-center gap-2">
                <Radio className="w-4 h-4 text-amber-400" />
                Canary Honeytoken Deception Traps
              </h2>
              <p className="text-[11px] text-slate-400">
                Silent decoy files with tripwires. Any unauthorized touch triggers an immediate SOC alarm.
              </p>
            </div>
            <button
              onClick={() => {
                store.createSecureFile(
                  'prod_db_credentials_backup.canary.json',
                  JSON.stringify({ host: 'db.prod.internal', user: 'root', pass: 'CANARY_TRIPWIRE_FLAG' }),
                  'RESTRICTED',
                  true,
                  { importance: 'CRITICAL', notes: 'Automated honeytoken planted' }
                );
                setActionAlert({ type: 'warning', message: 'Canary honeytoken planted in lab directory.' });
              }}
              className="px-3 py-1.5 bg-amber-950 hover:bg-amber-900 text-amber-200 border border-amber-700 rounded text-xs font-bold cursor-pointer"
            >
              + Plant Canary Trap
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {secureFiles.filter(f => f.is_canary_trap).map(trap => (
              <div key={trap.file_id} className="p-4 bg-slate-950 border border-amber-900/60 rounded-lg space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-100">{trap.name}</span>
                  <span className="text-[9px] px-2 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800 font-bold">
                    SILENT TRIPWIRE
                  </span>
                </div>
                <p className="text-[11px] text-slate-400">{trap.notes}</p>
                <div className="text-[10px] text-slate-500 font-mono">SHA-256: {trap.original_sha256.slice(0, 20)}...</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ================= SECTION 5: SECRET LOCKER ================= */}
      {activeTab === 'secrets' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <h2 className="font-bold text-slate-200 text-sm flex items-center gap-2 border-b border-slate-800 pb-3">
              <KeyRound className="w-4 h-4 text-cyan-400" />
              Employee Confidential Secret Locker
            </h2>

            <div className="space-y-3">
              {employeeSecrets.length === 0 ? (
                <div className="p-6 text-center text-slate-500 border border-dashed border-slate-800 rounded">
                  No secrets stored yet.
                </div>
              ) : (
                employeeSecrets.map(sec => (
                  <div key={sec.secret_id} className="p-3 bg-slate-950 border border-slate-800 rounded flex items-center justify-between">
                    <div>
                      <strong className="text-slate-200 text-xs">{sec.title}</strong>
                      <span className="ml-2 text-[10px] text-cyan-400 uppercase bg-slate-900 px-1.5 py-0.2 rounded border border-slate-800">
                        {sec.category}
                      </span>
                      <div className="text-[11px] font-mono mt-1 text-slate-400">
                        {revealedSecrets[sec.secret_id] ? sec.encrypted_value : '••••••••••••••••••••••••'}
                      </div>
                    </div>
                    <button
                      onClick={() => toggleRevealSecret(sec.secret_id)}
                      className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded cursor-pointer"
                    >
                      {revealedSecrets[sec.secret_id] ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <h3 className="font-bold text-slate-200 text-sm border-b border-slate-800 pb-3">
              Add Personal Secret / API Key
            </h3>
            <form onSubmit={handleAddSecret} className="space-y-3">
              <div>
                <label className="text-slate-400 block mb-1">Title</label>
                <input
                  type="text"
                  required
                  value={secretTitle}
                  onChange={(e) => setSecretTitle(e.target.value)}
                  placeholder="e.g. AWS Production Access Token"
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Secret Value</label>
                <input
                  type="password"
                  required
                  value={secretValue}
                  onChange={(e) => setSecretValue(e.target.value)}
                  placeholder="Enter secret token or key..."
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <button
                type="submit"
                className="w-full py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded cursor-pointer transition shadow-xs"
              >
                Seal Secret in Locker
              </button>
            </form>
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
                  {diffFile.original_content || diffFile.content}
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
                  handleRevertFile(diffFile);
                  setDiffFile(null);
                }}
                className="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold rounded cursor-pointer flex items-center gap-1.5"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Revert to Authentic Version</span>
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
