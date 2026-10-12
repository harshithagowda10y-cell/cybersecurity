/**
 * MAS-CSI Persona & Role Authentication Portal
 * Multi-Factor Authentication (MFA) Portal with Secondary TOTP Verification Step
 * Captures real Geolocation API coordinates, exact millisecond timestamps, and enforces geofencing.
 */

import React, { useState, useEffect } from 'react';
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
  Clock,
  QrCode,
  RefreshCw,
  Copy,
  Check,
  Compass,
  Radio,
  ArrowLeft,
  ShieldCheck,
  Mail,
  UserPlus,
  Send
} from 'lucide-react';
import { store } from '../services/store';
import { UserRole } from '../types/mas_csi';
import { getCurrentTotp, verifyTotpToken, generateQrMatrix } from '../services/totp';
import { useLoginGeolocation, formatExactTimestamp, GeolocationMetadata } from '../hooks/useLoginGeolocation';
import { EmailInboxModal } from './EmailInboxModal';

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
  // Mode: 'login' | 'register'
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');

  // Step 1: Credentials & Role -> Step 2: Secondary TOTP 2FA Verification
  const [authStep, setAuthStep] = useState<1 | 2>(1);

  const [selectedRole, setSelectedRole] = useState<UserRole>('Super Admin');
  const [usernameInput, setUsernameInput] = useState('admin');
  const [passwordInput, setPasswordInput] = useState('Admin@CSI2026!');
  const [adminSecurityToken, setAdminSecurityToken] = useState('ADM-KEY-9941-SEC');
  const [showPassword, setShowPassword] = useState(false);
  const [simulateOutsideOrg, setSimulateOutsideOrg] = useState(false);

  // Registration Fields
  const [regUsername, setRegUsername] = useState('harshitha_gowda');
  const [regEmail, setRegEmail] = useState('harshithagowda10y@gmail.com');
  const [regPassword, setRegPassword] = useState('SecurePass@2026!');
  const [regConfirmPassword, setRegConfirmPassword] = useState('SecurePass@2026!');
  const [regRole, setRegRole] = useState<UserRole>('Employee');

  // Email OTP state
  const [targetUserEmail, setTargetUserEmail] = useState<string>('superadmin@mas-csi.lab');
  const [latestDispatchedOtp, setLatestDispatchedOtp] = useState<string | null>(null);
  const [showEmailInbox, setShowEmailInbox] = useState(false);

  // TOTP Step 2 state
  const [totpSecret, setTotpSecret] = useState('JBSWY3DPEHPK3PXP');
  const [totpInput, setTotpInput] = useState('');
  const [totpStatus, setTotpStatus] = useState(getCurrentTotp('JBSWY3DPEHPK3PXP'));
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [showQrCode, setShowQrCode] = useState(true);

  // Telemetry Hook
  const { captureTelemetry, lastTelemetry, loading: geoLoading } = useLoginGeolocation();
  const [currentTelemetry, setCurrentTelemetry] = useState<GeolocationMetadata | null>(null);

  const [authError, setAuthError] = useState<string | null>(null);
  const [authSuccess, setAuthSuccess] = useState<string | null>(null);

  // Live countdown timer for TOTP rolling codes (30s RFC 6238 window)
  useEffect(() => {
    const interval = setInterval(() => {
      setTotpStatus(getCurrentTotp(totpSecret));
    }, 1000);
    return () => clearInterval(interval);
  }, [totpSecret]);

  // Capture telemetry upon modal open
  useEffect(() => {
    if (isOpen) {
      captureTelemetry(simulateOutsideOrg).then(t => setCurrentTelemetry(t));
    }
  }, [isOpen, simulateOutsideOrg, captureTelemetry]);

  if (!isOpen) return null;

  const roleProfiles = [
    {
      role: 'Super Admin' as UserRole,
      defaultUser: 'admin',
      defaultPass: 'Admin@CSI2026!',
      secret: 'JBSWY3DPEHPK3PXP',
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
      secret: 'HXDMVJECJJWSRB3H',
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
      secret: 'MZXW633PN5XW6MZX',
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
      secret: 'GEZDGNBVGY3TQOJQ',
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
    setTotpSecret(r.secret);
    setAuthError(null);
    setAuthSuccess(null);
  };

  // Handle User Registration
  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setAuthSuccess(null);

    if (regPassword !== regConfirmPassword) {
      setAuthError('Password and Confirm Password do not match.');
      return;
    }
    if (regPassword.length < 8) {
      setAuthError('Password must be at least 8 characters long for zero-trust security.');
      return;
    }
    if (!regEmail.includes('@') || !regEmail.includes('.')) {
      setAuthError('Please provide a valid corporate or personal email address.');
      return;
    }

    const res = await store.registerUser(regUsername, regEmail, regPassword, regRole);
    if (!res.success) {
      setAuthError(res.error || 'Registration failed.');
      return;
    }

    setAuthSuccess(`✓ Account registered successfully for '${regUsername}'! Welcome onboarding email sent to ${regEmail}. When logging in, your 2FA OTP codes will be sent to this email. Please log in below.`);
    setUsernameInput(regUsername);
    setPasswordInput(regPassword);
    setSelectedRole(regRole);
    setTargetUserEmail(regEmail);
    setAuthMode('login');
    setAuthStep(1);
  };

  // Step 1 Validation -> Dispatch OTP to Email -> Proceed to Step 2
  const handleProceedToMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setAuthSuccess(null);

    const user = store.users.find(u => u.username.toLowerCase() === usernameInput.toLowerCase());
    if (!user) {
      setAuthError(`Access Denied: Unregistered Identity '${usernameInput}'. You must be registered first in the directory before you can request an OTP or access the lab. Click 'Register New Account' below.`);
      return;
    }

    if (user.is_suspended) {
      setAuthError('Account is administratively SUSPENDED by Super Admin.');
      return;
    }

    if (selectedRole === 'Super Admin' && !adminSecurityToken.startsWith('ADM-KEY')) {
      setAuthError('Invalid Admin Security Token format. Expected ADM-KEY-XXXX-SEC.');
      return;
    }

    // Refresh telemetry for active parameters
    const telemetry = await captureTelemetry(simulateOutsideOrg);
    setCurrentTelemetry(telemetry);

    // Dispatch 6-digit OTP code directly to user's registered email
    const otpRes = await store.requestOtpToEmail(user.username, telemetry);
    setTargetUserEmail(user.email);
    if (otpRes.otp_code) {
      setLatestDispatchedOtp(otpRes.otp_code);
    }

    setAuthSuccess(`✓ 6-Digit OTP code dispatched to registered email: ${user.email}`);
    // Proceed to Step 2: 2FA challenge
    setAuthStep(2);
  };

  // Resend fresh OTP code to user's registered email
  const handleResendOtp = async () => {
    setAuthError(null);
    setAuthSuccess(null);
    const telemetry = currentTelemetry || (await captureTelemetry(simulateOutsideOrg));
    const otpRes = await store.requestOtpToEmail(usernameInput, telemetry);
    if (otpRes.success) {
      setLatestDispatchedOtp(otpRes.otp_code || null);
      setAuthSuccess(`✓ Fresh OTP passcode sent to your registered email: ${targetUserEmail}`);
    } else {
      setAuthError(otpRes.error || 'Failed to resend OTP code.');
    }
  };

  // Step 2: Verify OTP Code & Complete Authentication
  const handleVerifyTotp = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setAuthSuccess(null);

    const user = store.users.find(u => u.username.toLowerCase() === usernameInput.toLowerCase());
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
    const res = await store.loginUser(usernameInput, passwordInput, {
      simulateOutsideOrg,
      locationMeta: telemetry,
    });

    if (!res.success) {
      setAuthError(res.error || 'Authentication rejected by security policy.');
      return;
    }

    const outsideMsg = res.outsideOrgAlert
      ? ' ⚠️ [ALERT: Logged in outside corporate geofence - High severity SOC incident created]'
      : ' ✓ Verified within authorized corporate perimeter.';

    setAuthSuccess(
      `✓ 2FA Verified! Authenticated as ${user.username} (${user.role}) at ${telemetry.exact_time_formatted}. Location Lock: ${user.last_location}.${outsideMsg} Launching workspace...`
    );

    setTimeout(() => {
      onSelectRole(user.role);
      onClose();
    }, 1200);
  };

  const handleCopySecret = () => {
    navigator.clipboard.writeText(totpSecret);
    setCopiedSecret(true);
    setTimeout(() => setCopiedSecret(false), 2500);
  };

  const handleQuickFillCurrentTotp = () => {
    setTotpInput(totpStatus.code);
  };

  const qrMatrix = generateQrMatrix(`otpauth://totp/MAS-CSI:${usernameInput}?secret=${totpSecret}&issuer=MAS-CSI-Lab`);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-xs p-4 font-mono text-xs">
      <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-3xl w-full p-6 text-slate-100 shadow-2xl relative space-y-4 max-h-[92vh] overflow-y-auto">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-slate-200 cursor-pointer p-1"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded bg-cyan-950 border border-cyan-500/40 text-cyan-400">
              <UserCheck className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                MAS-CSI Persona &amp; Multi-Factor Authentication
                <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-700">
                  {authMode === 'register' ? 'New Registration' : `Step ${authStep} of 2`}
                </span>
              </h2>
              <p className="text-[11px] text-slate-400">
                {authMode === 'register'
                  ? 'Register new user account and enroll registered email for 2FA OTP codes'
                  : authStep === 1
                  ? 'Step 1: Select registered persona & verify credentials with location telemetry'
                  : 'Step 2: Secondary verification using 6-Digit OTP dispatched to registered email'}
              </p>
            </div>
          </div>
        </div>

        {/* Auth Mode Switcher Tabs */}
        <div className="flex border-b border-slate-800 gap-2 pb-1">
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
                  You must be registered first in the directory before you can request an OTP or access the lab.
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
                  value={regUsername}
                  onChange={(e) => setRegUsername(e.target.value)}
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
                  value={regEmail}
                  onChange={(e) => setRegEmail(e.target.value)}
                  placeholder="e.g. harshithagowda10y@gmail.com"
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-emerald-500 font-mono text-xs"
                />
                <span className="text-[10px] text-cyan-400 mt-1 block">
                  ✉ All 2FA OTP codes and security alerts will be delivered to this email.
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="text-slate-300 block mb-1">Security Role / Clearance</label>
                <select
                  value={regRole}
                  onChange={(e) => setRegRole(e.target.value as any)}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-emerald-500 font-mono text-xs"
                >
                  <option value="Employee">Employee (Real Lab &amp; Vault)</option>
                  <option value="Security Analyst">Security Analyst (SOC)</option>
                  <option value="Auditor">Compliance Auditor</option>
                  <option value="Super Admin">Super Administrator</option>
                </select>
              </div>

              <div>
                <label className="text-slate-300 block mb-1">Password (Min 8 chars)</label>
                <input
                  type="password"
                  required
                  value={regPassword}
                  onChange={(e) => setRegPassword(e.target.value)}
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

        {/* Step Progress Indicator (Login Mode) */}
        {authMode === 'login' && (
          <div className="flex items-center gap-2 text-[11px]">
            <div
              onClick={() => setAuthStep(1)}
              className={`flex-1 py-1.5 px-3 rounded flex items-center justify-between cursor-pointer border ${
                authStep === 1
                  ? 'bg-cyan-950/80 border-cyan-500 text-cyan-300 font-bold'
                  : 'bg-slate-950 border-slate-800 text-slate-400'
              }`}
            >
              <span>1. Role &amp; Registered Credentials</span>
              {authStep === 2 && <Check className="w-3.5 h-3.5 text-emerald-400" />}
            </div>
            <ArrowRight className="w-3.5 h-3.5 text-slate-600 shrink-0" />
            <div
              className={`flex-1 py-1.5 px-3 rounded flex items-center justify-between border ${
                authStep === 2
                  ? 'bg-cyan-950/80 border-cyan-500 text-cyan-300 font-bold'
                  : 'bg-slate-950 border-slate-800 text-slate-500'
              }`}
            >
              <span>2. Email OTP &amp; 2FA Verification</span>
              <KeyRound className="w-3.5 h-3.5 text-cyan-400" />
            </div>
          </div>
        )}

        {authError && (
          <div className="p-3 bg-rose-950/80 border border-rose-600 rounded text-rose-200 text-xs flex items-center justify-between gap-2">
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
          <div className="p-3 bg-emerald-950/80 border border-emerald-600 rounded text-emerald-200 text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{authSuccess}</span>
          </div>
        )}

        {/* ================= STEP 1: CREDENTIALS & ROLE SELECTION ================= */}
        {authMode === 'login' && authStep === 1 && (
          <div className="space-y-4">
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

              <div className="flex flex-wrap gap-1.5 text-[10px]">
                {activeProfile.capabilities.map((cap, idx) => (
                  <span key={idx} className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                    ✓ {cap}
                  </span>
                ))}
              </div>

              <form onSubmit={handleProceedToMfa} className="space-y-3 pt-2">
                <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
                  <div className={selectedRole === 'Super Admin' ? 'md:col-span-4' : 'md:col-span-6'}>
                    <label className="text-slate-400 block mb-1">Username</label>
                    <input
                      type="text"
                      required
                      value={usernameInput}
                      onChange={(e) => setUsernameInput(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                    />
                  </div>

                  <div className={selectedRole === 'Super Admin' ? 'md:col-span-4' : 'md:col-span-6'}>
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

                {/* Geolocation Hook Telemetry Readout */}
                <div className="p-3 bg-slate-900 border border-slate-800 rounded space-y-2">
                  <div className="flex items-center justify-between text-[11px]">
                    <div className="flex items-center gap-1.5 text-slate-300 font-semibold">
                      <Compass className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Live Geolocation Telemetry Sensor:</span>
                    </div>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                      GPS Locked (High Accuracy)
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[10px] text-slate-400 pt-1">
                    <div className="flex items-center gap-1.5">
                      <MapPin className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      <span>
                        Coords: {currentTelemetry ? `${currentTelemetry.latitude.toFixed(4)}° N, ${currentTelemetry.longitude.toFixed(4)}° W` : '37.7749° N, -122.4194° W'}
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                      <span>Exact Time: {currentTelemetry ? currentTelemetry.exact_time_formatted : formatExactTimestamp().formatted}</span>
                    </div>
                  </div>

                  {/* Geofence Testing Toggle (Simulate Outside-Organization Login) */}
                  <div className="pt-2 border-t border-slate-800 flex items-center justify-between">
                    <label className="flex items-center gap-2 cursor-pointer text-[10px] text-amber-300 hover:text-amber-200">
                      <input
                        type="checkbox"
                        checked={simulateOutsideOrg}
                        onChange={(e) => setSimulateOutsideOrg(e.target.checked)}
                        className="accent-amber-500 cursor-pointer"
                      />
                      <span>Simulate Outside-of-Organization Login (Triggers Admin SOC Security Alert)</span>
                    </label>
                    {simulateOutsideOrg && (
                      <span className="text-[9px] px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-bold uppercase">
                        🚨 Geofence Breach Active
                      </span>
                    )}
                  </div>
                </div>

                <div className="flex items-center justify-between pt-2">
                  <span className="text-[10px] text-slate-500">
                    Step 1 of 2: Primary credential check. Next: TOTP 2FA Generator.
                  </span>
                  <button
                    type="submit"
                    className="py-2 px-6 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded cursor-pointer transition shadow-xs flex items-center gap-2"
                  >
                    <span>Proceed to 2FA Step</span>
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* ================= STEP 2: TIME-BASED ONE-TIME PASSWORD (TOTP) VERIFICATION ================= */}
        {authStep === 2 && (
          <div className="space-y-4">
            <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <KeyRound className="w-5 h-5 text-cyan-400" />
                  <div>
                    <h3 className="font-bold text-slate-100 text-sm">
                      Secondary Verification: TOTP Authenticator Generator
                    </h3>
                    <p className="text-[10px] text-slate-400">
                      RFC 6238 Time-based One-Time Password with live 30-second rolling window
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setAuthStep(1)}
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
                      Check your registered inbox or click 'View Email' to inspect the delivered email with your 6-digit code.
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

              {/* Live Rolling TOTP Authenticator Generator Card */}
              <div className="grid grid-cols-1 md:grid-cols-12 gap-4 bg-slate-900/90 border border-cyan-500/30 rounded-lg p-4">
                {/* QR Code representation */}
                <div className="md:col-span-4 flex flex-col items-center justify-center border-r border-slate-800/80 pr-2">
                  <div className="p-2 bg-slate-950 border border-cyan-500/40 rounded shadow-inner">
                    <div className="grid grid-cols-17 gap-0.5 bg-black p-1.5 rounded">
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
                  <span className="text-[9px] text-slate-500 mt-2 font-mono flex items-center gap-1">
                    <QrCode className="w-3 h-3 text-cyan-400" />
                    <span>Authenticator QR Matrix</span>
                  </span>
                </div>

                {/* Live Code & Rolling Countdown */}
                <div className="md:col-span-8 space-y-3 flex flex-col justify-center">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-bold">
                        Live TOTP Code (Simulated Authenticator App)
                      </span>
                      <div className="text-2xl font-extrabold tracking-widest text-cyan-300 font-mono mt-1 flex items-center gap-2">
                        <span>{totpStatus.code.slice(0, 3)}</span>
                        <span className="text-slate-500">-</span>
                        <span>{totpStatus.code.slice(3, 6)}</span>
                      </div>
                    </div>

                    {/* Circular / Counter Visual Timer */}
                    <div className="text-right">
                      <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-400">
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" style={{ animationDuration: '6s' }} />
                        <span className="font-bold">{totpStatus.secondsRemaining}s</span>
                      </div>
                      <span className="text-[9px] text-slate-500 block mt-1">Rolling 30s window</span>
                    </div>
                  </div>

                  {/* Progress bar of time remaining in current 30s window */}
                  <div className="w-full bg-slate-950 h-1.5 rounded-full overflow-hidden border border-slate-800">
                    <div
                      className={`h-full transition-all duration-1000 ${
                        totpStatus.secondsRemaining < 7 ? 'bg-rose-500' : 'bg-cyan-500'
                      }`}
                      style={{ width: `${(totpStatus.secondsRemaining / 30) * 100}%` }}
                    />
                  </div>

                  {/* Secret Key & Quick Actions */}
                  <div className="flex items-center justify-between pt-1 gap-2 flex-wrap">
                    <div className="text-[10px] text-slate-400 font-mono">
                      Secret: <code className="text-slate-200 bg-slate-950 px-1 py-0.5 rounded border border-slate-800">{totpSecret}</code>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={handleCopySecret}
                        className="text-[10px] text-slate-400 hover:text-slate-200 flex items-center gap-1 px-2 py-1 rounded bg-slate-950 border border-slate-800 cursor-pointer"
                      >
                        {copiedSecret ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedSecret ? 'Copied' : 'Copy Key'}</span>
                      </button>
                      <button
                        type="button"
                        onClick={handleQuickFillCurrentTotp}
                        className="text-[10px] font-bold text-cyan-400 hover:text-cyan-300 flex items-center gap-1 px-2 py-1 rounded bg-cyan-950 border border-cyan-700 cursor-pointer"
                      >
                        <span>Auto-Fill Code</span>
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {/* Code Verification Input Form */}
              <form onSubmit={handleVerifyTotp} className="space-y-4 pt-1">
                <div>
                  <label className="text-slate-300 block mb-1.5 text-xs font-semibold">
                    Enter 6-Digit TOTP Passcode
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
                    Accepts live 6-digit rolling code, auto-filled code, or testing bypass code: <code>994102</code>
                  </span>
                </div>

                {/* Session Security Telemetry Preview */}
                <div className="p-3 bg-slate-900/60 border border-slate-800 rounded text-[11px] space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Authenticated Identity:</span>
                    <span className="font-bold text-slate-200">{usernameInput} ({selectedRole})</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Exact Timestamp (Microsecond precision):</span>
                    <span className="text-cyan-300 font-mono">
                      {currentTelemetry ? currentTelemetry.exact_time_formatted : formatExactTimestamp().formatted}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Geographic Location:</span>
                    <span className={simulateOutsideOrg ? 'text-rose-400 font-bold' : 'text-emerald-400'}>
                      {simulateOutsideOrg
                        ? '🚨 Remote Hub (Outside Corporate Geofence)'
                        : (currentTelemetry?.city || 'San Francisco Lab HQ')}
                    </span>
                  </div>
                </div>

                <div className="flex items-center justify-between pt-2">
                  <button
                    type="button"
                    onClick={() => setAuthStep(1)}
                    className="py-2 px-4 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded font-semibold cursor-pointer transition"
                  >
                    ← Back
                  </button>

                  <button
                    type="submit"
                    className="py-2.5 px-6 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold rounded cursor-pointer transition shadow-md flex items-center gap-2"
                  >
                    <ShieldCheck className="w-4 h-4 stroke-[2.5]" />
                    <span>Verify 2FA &amp; Launch Workspace</span>
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Corporate Secure Webmail & OTP Email Viewer */}
        <EmailInboxModal
          isOpen={showEmailInbox}
          onClose={() => setShowEmailInbox(false)}
          filterEmail={targetUserEmail}
          filterUsername={usernameInput}
          onAutoFillOtp={(code) => {
            setTotpInput(code);
            setShowEmailInbox(false);
          }}
        />
      </div>
    </div>
  );
};
