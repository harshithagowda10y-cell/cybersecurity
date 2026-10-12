/**
 * MAS-CSI Corporate Secure Webmail & OTP Dispatch Inbox Modal
 * Allows employees and administrators to inspect security emails delivered to their
 * registered email address (e.g., OTP passcodes, registration confirmations, security alerts).
 */

import React, { useState } from 'react';
import {
  Mail,
  X,
  Clock,
  MapPin,
  ShieldCheck,
  KeyRound,
  Check,
  Copy,
  ExternalLink,
  RefreshCw,
  Search,
  AlertTriangle,
  UserCheck,
  Sparkles,
  Inbox
} from 'lucide-react';
import { store } from '../services/store';
import { DispatchedEmail } from '../types/mas_csi';

interface EmailInboxModalProps {
  isOpen: boolean;
  onClose: () => void;
  filterEmail?: string;
  filterUsername?: string;
  onAutoFillOtp?: (code: string) => void;
}

export const EmailInboxModal: React.FC<EmailInboxModalProps> = ({
  isOpen,
  onClose,
  filterEmail,
  filterUsername,
  onAutoFillOtp,
}) => {
  const dispatchedEmails = store.dispatchedEmails;
  const users = store.users;

  // Selected email filter: 'ALL' or specific email address
  const [selectedRecipient, setSelectedRecipient] = useState<string>(filterEmail || 'ALL');
  const [selectedEmailId, setSelectedEmailId] = useState<string | null>(null);
  const [copiedCode, setCopiedCode] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  if (!isOpen) return null;

  // Filter emails
  const filteredEmails = dispatchedEmails.filter(email => {
    if (selectedRecipient !== 'ALL' && email.to_email.toLowerCase() !== selectedRecipient.toLowerCase()) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        email.subject.toLowerCase().includes(q) ||
        email.to_email.toLowerCase().includes(q) ||
        email.to_username.toLowerCase().includes(q) ||
        (email.otp_code && email.otp_code.includes(q))
      );
    }
    return true;
  });

  // Active email to view details of
  const activeEmail = (selectedEmailId ? dispatchedEmails.find(e => e.email_id === selectedEmailId) : null) || filteredEmails[0];

  const handleCopyCode = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedCode(code);
    if (onAutoFillOtp) {
      onAutoFillOtp(code);
    }
    setTimeout(() => setCopiedCode(null), 2500);
  };

  const handleSelectEmail = (e: DispatchedEmail) => {
    setSelectedEmailId(e.email_id);
    store.markEmailAsRead(e.email_id);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-xs p-4 font-mono text-xs">
      <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-4xl w-full p-5 text-slate-100 shadow-2xl relative space-y-4 max-h-[92vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded bg-cyan-950 border border-cyan-500/50 text-cyan-400 flex items-center justify-center">
              <Mail className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <span>Corporate Secure Webmail &amp; OTP Dispatcher</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                  {dispatchedEmails.length} Delivered
                </span>
              </h2>
              <p className="text-[11px] text-slate-400">
                Official dispatch inbox for user-registered emails (OTPs, MFA passcodes, security alerts)
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 cursor-pointer p-1"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Filter & Search Bar */}
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-slate-400 text-[11px]">Recipient Address:</span>
            <select
              value={selectedRecipient}
              onChange={(e) => setSelectedRecipient(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Registered Inboxes ({dispatchedEmails.length})</option>
              {Array.from(new Set(dispatchedEmails.map(e => e.to_email))).map(email => (
                <option key={email} value={email}>
                  {email} ({dispatchedEmails.filter(e => e.to_email === email).length})
                </option>
              ))}
            </select>
          </div>

          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search OTP, subject, or email..."
              className="bg-slate-950 border border-slate-800 rounded pl-8 pr-3 py-1 text-slate-200 text-xs focus:outline-none focus:border-cyan-500 w-56 font-mono"
            />
          </div>
        </div>

        {/* Two-Pane Inbox Layout */}
        <div className="grid grid-cols-1 md:grid-cols-12 gap-4 flex-1 overflow-hidden min-h-[350px]">
          {/* Left: Email List (5 Cols) */}
          <div className="md:col-span-5 bg-slate-950 border border-slate-800 rounded-lg overflow-y-auto divide-y divide-slate-800/80 max-h-[500px]">
            {filteredEmails.length === 0 ? (
              <div className="p-8 text-center text-slate-500 space-y-2">
                <Inbox className="w-8 h-8 mx-auto text-slate-600 stroke-[1.5]" />
                <p>No dispatched emails found for selected filter.</p>
              </div>
            ) : (
              filteredEmails.map((email) => {
                const isSelected = activeEmail?.email_id === email.email_id;
                return (
                  <button
                    key={email.email_id}
                    onClick={() => handleSelectEmail(email)}
                    className={`w-full text-left p-3 transition cursor-pointer flex flex-col gap-1 ${
                      isSelected
                        ? 'bg-slate-900 border-l-2 border-cyan-400'
                        : 'hover:bg-slate-900/50'
                    }`}
                  >
                    <div className="flex items-center justify-between text-[10px] w-full">
                      <span className="font-bold text-cyan-300 truncate max-w-[180px]">
                        {email.to_email}
                      </span>
                      <span className="text-slate-500">{email.timestamp.slice(11, 19)}</span>
                    </div>

                    <div className="text-xs font-semibold text-slate-200 truncate w-full flex items-center gap-1.5">
                      {email.email_type === 'OTP_VERIFICATION' ? (
                        <KeyRound className="w-3 h-3 text-amber-400 shrink-0" />
                      ) : (
                        <UserCheck className="w-3 h-3 text-emerald-400 shrink-0" />
                      )}
                      <span className="truncate">{email.subject}</span>
                    </div>

                    <div className="flex items-center justify-between text-[10px] text-slate-400 mt-0.5">
                      <span className="text-slate-500">To: {email.to_username}</span>
                      {email.otp_code && (
                        <span className="px-1.5 py-0.2 rounded bg-amber-950 text-amber-300 font-bold border border-amber-800">
                          OTP: {email.otp_code}
                        </span>
                      )}
                    </div>
                  </button>
                );
              })
            )}
          </div>

          {/* Right: Email Detail View (7 Cols) */}
          <div className="md:col-span-7 bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-4 overflow-y-auto max-h-[500px]">
            {activeEmail ? (
              <div className="space-y-4">
                {/* Email Metadata Header */}
                <div className="border-b border-slate-800 pb-3 space-y-2">
                  <div className="flex items-start justify-between gap-2">
                    <h3 className="font-bold text-slate-100 text-sm">{activeEmail.subject}</h3>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 shrink-0 font-bold">
                      VERIFIED DISPATCH
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-1 text-[11px] text-slate-400 bg-slate-900/60 p-2.5 rounded border border-slate-800/80">
                    <div>
                      <span className="text-slate-500">From: </span>
                      <span className="text-slate-200">{activeEmail.from_address}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">To: </span>
                      <strong className="text-cyan-300">{activeEmail.to_email}</strong>
                    </div>
                    <div>
                      <span className="text-slate-500">Dispatched: </span>
                      <span className="text-slate-300">{activeEmail.formatted_time}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Expires: </span>
                      <span className="text-amber-300 font-bold">{activeEmail.expires_at}</span>
                    </div>
                  </div>
                </div>

                {/* Big OTP Highlight Card (If email contains OTP) */}
                {activeEmail.otp_code && (
                  <div className="p-4 bg-slate-900 border border-cyan-500/50 rounded-lg text-center space-y-3 shadow-lg">
                    <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">
                      Your 6-Digit One-Time Passcode (OTP)
                    </span>

                    <div className="text-3xl font-extrabold tracking-widest text-cyan-300 font-mono py-1 flex items-center justify-center gap-2">
                      <span>{activeEmail.otp_code.slice(0, 3)}</span>
                      <span className="text-slate-600">-</span>
                      <span>{activeEmail.otp_code.slice(3, 6)}</span>
                    </div>

                    <div className="flex items-center justify-center gap-2">
                      <button
                        onClick={() => handleCopyCode(activeEmail.otp_code!)}
                        className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded cursor-pointer transition flex items-center gap-1.5 shadow-sm text-xs"
                      >
                        {copiedCode === activeEmail.otp_code ? (
                          <>
                            <Check className="w-3.5 h-3.5 stroke-[2.5]" />
                            <span>Passcode Copied &amp; Auto-Filled!</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5" />
                            <span>Copy &amp; Auto-Fill Passcode</span>
                          </>
                        )}
                      </button>
                    </div>

                    <p className="text-[10px] text-slate-400">
                      Enter this code in your 2FA verification prompt to unlock your workspace.
                    </p>
                  </div>
                )}

                {/* Email Body Content */}
                <div className="p-3.5 bg-slate-900/40 border border-slate-800 rounded text-slate-300 text-xs whitespace-pre-wrap leading-relaxed">
                  {activeEmail.body_text}
                </div>

                {/* Telemetry Footprint */}
                {activeEmail.location_label && (
                  <div className="flex items-center gap-2 text-[10px] text-slate-400 bg-slate-900/60 p-2 rounded border border-slate-800">
                    <MapPin className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    <span>Originating Geolocation: {activeEmail.location_label}</span>
                  </div>
                )}
              </div>
            ) : (
              <div className="p-12 text-center text-slate-500">
                Select an email from the left pane to view details.
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between pt-2 border-t border-slate-800 text-[11px] text-slate-400">
          <span>Security Protocol: Zero-Trust Mail Gateway v2.4 (Simulated RFC 5322)</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold rounded cursor-pointer"
          >
            Close Inbox
          </button>
        </div>
      </div>
    </div>
  );
};
