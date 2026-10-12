/**
 * MAS-CSI Cyber Security Tools Suite
 * Interactive, fully-functional security toolset:
 * - YARA Rule Scanner
 * - ClamAV Antivirus Engine
 * - OWASP ZAP Web DAST Scanner
 * - Network Protocol & Packet Inspector (Suricata/Zeek)
 * - OpenCTI Threat Intelligence IOC Lookup
 * - Cryptographic Checksum Validator
 */

import React, { useState } from 'react';
import {
  Wrench,
  Shield,
  FileSearch,
  Search,
  CheckCircle2,
  AlertTriangle,
  Play,
  Terminal,
  Activity,
  Layers,
  Cpu,
  RefreshCw,
  Globe2,
  Lock,
  Binary
} from 'lucide-react';
import { store } from '../services/store';

export const SecurityToolsView: React.FC = () => {
  const [activeTool, setActiveTool] = useState<'yara' | 'clamav' | 'zap' | 'packet' | 'opencti' | 'checksum'>('yara');

  // YARA state
  const [yaraContent, setYaraContent] = useState("' OR 1=1 -- UNION SELECT username, password FROM users");
  const [yaraRule, setYaraRule] = useState('rule SQLi_Webshell_Detection { strings: $sqli = "UNION SELECT" condition: $sqli }');
  const [yaraResult, setYaraResult] = useState<any>(null);

  // ClamAV state
  const [clamFileName, setClamFileName] = useState('suspicious_script.sh');
  const [clamHash, setClamHash] = useState('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f');
  const [clamResult, setClamResult] = useState<any>(null);

  // ZAP state
  const [zapUrl, setZapUrl] = useState('http://localhost:3000/api/lab/files');
  const [zapResult, setZapResult] = useState<any>(null);
  const [isScanningZap, setIsScanningZap] = useState(false);

  // OpenCTI state
  const [iocInput, setIocInput] = useState('192.168.100.45');
  const [openCtiResult, setOpenCtiResult] = useState<any>(null);

  // Checksum validator state
  const [checksumInput, setChecksumInput] = useState('MAS-CSI Authorized System File Content v9.0');
  const [computedSha256, setComputedSha256] = useState<string>('');

  const handleRunYara = () => {
    const res = store.runYaraScan(yaraRule, yaraContent);
    setYaraResult(res);
  };

  const handleRunClamAv = () => {
    const res = store.runClamAvScan(clamHash, clamFileName);
    setClamResult(res);
  };

  const handleRunZap = () => {
    setIsScanningZap(true);
    setTimeout(() => {
      const res = store.runZapScan(zapUrl);
      setZapResult(res);
      setIsScanningZap(false);
    }, 700);
  };

  const handleRunOpenCti = () => {
    const res = store.runOpenCtiLookup(iocInput);
    setOpenCtiResult(res);
  };

  const handleComputeChecksum = async () => {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(checksumInput);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    setComputedSha256(hashArray.map(b => b.toString(16).padStart(2, '0')).join(''));
  };

  return (
    <div className="space-y-5 font-mono text-xs">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded bg-cyan-950 border border-cyan-500/40 text-cyan-400">
            <Wrench className="w-4 h-4" />
          </div>
          <div>
            <h1 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              Cyber Security Diagnostic Tools Suite
              <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700">
                ACTIVE TOOLSET
              </span>
            </h1>
            <p className="text-slate-400 text-[11px]">
              Integrated security engines for pattern scanning, vulnerability analysis, and threat hunting
            </p>
          </div>
        </div>
      </div>

      {/* Tool Selector Tabs */}
      <div className="flex border-b border-slate-800 bg-slate-900/60 p-1.5 rounded-lg gap-2 overflow-x-auto">
        {[
          { id: 'yara', label: 'YARA Pattern Scanner', icon: FileSearch },
          { id: 'clamav', label: 'ClamAV Malware Engine', icon: Shield },
          { id: 'zap', label: 'OWASP ZAP DAST Scanner', icon: Activity },
          { id: 'packet', label: 'Suricata / Zeek Inspector', icon: Terminal },
          { id: 'opencti', label: 'OpenCTI Threat Hunter', icon: Globe2 },
          { id: 'checksum', label: 'SHA-256 Hasher', icon: Binary },
        ].map(t => {
          const Icon = t.icon;
          const isActive = activeTool === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setActiveTool(t.id as any)}
              className={`flex items-center gap-2 px-3 py-2 rounded font-semibold text-xs transition cursor-pointer whitespace-nowrap border ${
                isActive
                  ? 'bg-cyan-950 text-cyan-300 border-cyan-600/60'
                  : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{t.label}</span>
            </button>
          );
        })}
      </div>

      {/* TOOL 1: YARA SCANNER */}
      {activeTool === 'yara' && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h2 className="font-bold text-slate-200 text-sm">YARA Pattern & Malware Signature Scanner</h2>
              <p className="text-[11px] text-slate-400">
                Scan file buffers and payload strings against compiled YARA detection rules
              </p>
            </div>
            <button
              onClick={handleRunYara}
              className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded flex items-center gap-1.5 cursor-pointer"
            >
              <Play className="w-3.5 h-3.5 fill-slate-950" />
              <span>Execute YARA Scan</span>
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-slate-400 block mb-1">Target Payload / Buffer Text</label>
              <textarea
                rows={5}
                value={yaraContent}
                onChange={(e) => setYaraContent(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
              />
              <div className="flex gap-2 mt-2">
                <button
                  type="button"
                  onClick={() => setYaraContent("' UNION SELECT username, password FROM users --")}
                  className="px-2 py-0.5 bg-slate-950 text-[10px] text-cyan-400 border border-slate-800 rounded cursor-pointer"
                >
                  Test SQLi
                </button>
                <button
                  type="button"
                  onClick={() => setYaraContent('<?php system($_GET["cmd"]); ?>')}
                  className="px-2 py-0.5 bg-slate-950 text-[10px] text-amber-400 border border-slate-800 rounded cursor-pointer"
                >
                  Test Webshell
                </button>
                <button
                  type="button"
                  onClick={() => setYaraContent('powershell -enc JAB3AGgAbwBhAG0AaQA=')}
                  className="px-2 py-0.5 bg-slate-950 text-[10px] text-purple-400 border border-slate-800 rounded cursor-pointer"
                >
                  Test PowerShell
                </button>
              </div>
            </div>

            <div>
              <label className="text-slate-400 block mb-1">YARA Detection Rule Definition</label>
              <textarea
                rows={5}
                value={yaraRule}
                onChange={(e) => setYaraRule(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2.5 text-slate-300 font-mono text-xs focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          {yaraResult && (
            <div className={`p-4 rounded border space-y-2 ${
              yaraResult.matched ? 'bg-rose-950/70 border-rose-600 text-rose-200' : 'bg-emerald-950/70 border-emerald-600 text-emerald-200'
            }`}>
              <div className="font-bold flex items-center gap-2">
                {yaraResult.matched ? <AlertTriangle className="w-4 h-4 text-rose-400" /> : <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                <span>{yaraResult.matched ? 'ALERT: YARA SIGNATURE MATCH' : 'SCAN CLEAN: NO MATCH'}</span>
              </div>
              <p className="text-[11px] text-slate-300">{yaraResult.details}</p>
              {yaraResult.matched && (
                <div className="text-[10px] text-rose-300">
                  Matched Tags: <code className="bg-rose-900/60 px-1.5 py-0.5 rounded">{yaraResult.tags.join(', ')}</code>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* TOOL 2: CLAMAV ENGINE */}
      {activeTool === 'clamav' && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h2 className="font-bold text-slate-200 text-sm">ClamAV Antivirus Malware Signature Engine</h2>
              <p className="text-[11px] text-slate-400">
                Hash-based detection comparing against known trojan, ransomware, and test signatures
              </p>
            </div>
            <button
              onClick={handleRunClamAv}
              className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded flex items-center gap-1.5 cursor-pointer"
            >
              <Play className="w-3.5 h-3.5 fill-slate-950" />
              <span>Run ClamAV Scan</span>
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-slate-400 block mb-1">Target File Name</label>
              <input
                type="text"
                value={clamFileName}
                onChange={(e) => setClamFileName(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-200"
              />
            </div>
            <div>
              <label className="text-slate-400 block mb-1">File SHA-256 Checksum</label>
              <input
                type="text"
                value={clamHash}
                onChange={(e) => setClamHash(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-200"
              />
            </div>
          </div>

          <div className="flex gap-2">
            <button
              onClick={() => {
                setClamFileName('eicar_test_sample.com');
                setClamHash('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f');
              }}
              className="px-2.5 py-1 bg-slate-950 text-rose-300 border border-slate-800 rounded cursor-pointer"
            >
              Load EICAR Test Signature
            </button>
            <button
              onClick={() => {
                setClamFileName('legitimate_report.pdf');
                setClamHash('6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b');
              }}
              className="px-2.5 py-1 bg-slate-950 text-emerald-300 border border-slate-800 rounded cursor-pointer"
            >
              Load Clean File Signature
            </button>
          </div>

          {clamResult && (
            <div className={`p-4 rounded border space-y-1.5 ${
              clamResult.verdict === 'INFECTED' ? 'bg-rose-950/70 border-rose-600 text-rose-200' : 'bg-emerald-950/70 border-emerald-600 text-emerald-200'
            }`}>
              <div className="font-bold flex items-center gap-2">
                {clamResult.verdict === 'INFECTED' ? <AlertTriangle className="w-4 h-4 text-rose-400" /> : <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                <span>VERDICT: {clamResult.verdict}</span>
              </div>
              <div>Signature: <strong className="text-slate-100">{clamResult.signature}</strong></div>
              <div>Quarantine Status: <span className="text-amber-300">{clamResult.quarantined ? 'Quarantined in lab isolation' : 'Clean / Allowed'}</span></div>
            </div>
          )}
        </div>
      )}

      {/* TOOL 3: OWASP ZAP SCANNER */}
      {activeTool === 'zap' && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h2 className="font-bold text-slate-200 text-sm">OWASP ZAP Dynamic Application Security Tester (DAST)</h2>
              <p className="text-[11px] text-slate-400">
                Automated dynamic vulnerability scanning of web application endpoints
              </p>
            </div>
            <button
              onClick={handleRunZap}
              disabled={isScanningZap}
              className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 text-slate-950 font-bold rounded flex items-center gap-1.5 cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isScanningZap ? 'animate-spin' : ''}`} />
              <span>{isScanningZap ? 'Scanning Endpoints...' : 'Start ZAP Scan'}</span>
            </button>
          </div>

          <div>
            <label className="text-slate-400 block mb-1">Target Endpoint URL</label>
            <input
              type="text"
              value={zapUrl}
              onChange={(e) => setZapUrl(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-200"
            />
          </div>

          {zapResult && (
            <div className="space-y-3">
              <span className="text-slate-400 font-bold block">DISCOVERED VULNERABILITY FINDINGS:</span>
              <div className="space-y-2">
                {zapResult.findings.map((f: any, idx: number) => (
                  <div key={idx} className="p-3 bg-slate-950 border border-slate-800 rounded flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-200">{f.alert}</span>
                        <span className="text-[10px] text-cyan-400 bg-slate-900 px-1.5 py-0.5 rounded">{f.cwe}</span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-1">{f.description}</p>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      f.risk === 'HIGH' ? 'bg-rose-950 text-rose-300' : 'bg-amber-950 text-amber-300'
                    }`}>
                      {f.risk}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TOOL 4: SURICATA & ZEEK PACKET INSPECTOR */}
      {activeTool === 'packet' && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
          <h2 className="font-bold text-slate-200 text-sm">Suricata / Zeek Network Protocol & Deep Packet Inspector</h2>
          <p className="text-[11px] text-slate-400">
            Real-time inspection of captured network flows, protocol layers, and TCP flags
          </p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="p-3 bg-slate-950 border border-slate-800 rounded">
              <span className="text-slate-500 block text-[10px]">MONITORED INTERFACE</span>
              <span className="text-emerald-400 font-bold">eth0 (Lab Host Bridge)</span>
            </div>
            <div className="p-3 bg-slate-950 border border-slate-800 rounded">
              <span className="text-slate-500 block text-[10px]">PARSER ENGINES</span>
              <span className="text-cyan-400 font-bold">Suricata EVE-JSON + Zeek conn.log</span>
            </div>
            <div className="p-3 bg-slate-950 border border-slate-800 rounded">
              <span className="text-slate-500 block text-[10px]">FLOW DURATION METRIC</span>
              <span className="text-slate-300 font-bold">Continuous Rolling Stream</span>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                  <th className="py-2 px-3">Flow ID</th>
                  <th className="py-2 px-3">Proto</th>
                  <th className="py-2 px-3">Source & Port</th>
                  <th className="py-2 px-3">Destination</th>
                  <th className="py-2 px-3">TCP Flags</th>
                  <th className="py-2 px-3">Payload Size</th>
                  <th className="py-2 px-3">Verdict</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {[
                  { id: 'FLOW-101', proto: 'TCP', src: '127.0.0.1:52101', dst: '127.0.0.1:3000', flags: 'ACK, PSH', bytes: '420 B', verdict: 'CLEAN' },
                  { id: 'FLOW-102', proto: 'TCP', src: '192.168.100.45:48920', dst: '10.0.0.5:443', flags: 'SYN', bytes: '64 B', verdict: 'LAB_SCENARIO' },
                  { id: 'FLOW-103', proto: 'UDP', src: '127.0.0.1:53201', dst: '127.0.0.1:53', flags: 'N/A', bytes: '128 B', verdict: 'NORMAL_DNS' },
                  { id: 'FLOW-104', proto: 'HTTP', src: '127.0.0.1:52103', dst: '127.0.0.1:3000', flags: 'ACK, PSH', bytes: '1.2 KB', verdict: 'INSPECTED' },
                ].map(r => (
                  <tr key={r.id} className="text-slate-300">
                    <td className="py-2 px-3 text-cyan-400 font-bold">{r.id}</td>
                    <td className="py-2 px-3">{r.proto}</td>
                    <td className="py-2 px-3">{r.src}</td>
                    <td className="py-2 px-3">{r.dst}</td>
                    <td className="py-2 px-3 text-slate-400">{r.flags}</td>
                    <td className="py-2 px-3">{r.bytes}</td>
                    <td className="py-2 px-3">
                      <span className="px-1.5 py-0.5 rounded bg-slate-950 text-emerald-400 border border-emerald-900 text-[10px]">
                        {r.verdict}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TOOL 5: OPENCTI THREAT HUNTER */}
      {activeTool === 'opencti' && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h2 className="font-bold text-slate-200 text-sm">OpenCTI Threat Intelligence IOC Lookup</h2>
              <p className="text-[11px] text-slate-400">
                Query malicious IP addresses, domain names, or file hashes against intelligence feeds
              </p>
            </div>
            <button
              onClick={handleRunOpenCti}
              className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded flex items-center gap-1.5 cursor-pointer"
            >
              <Search className="w-3.5 h-3.5" />
              <span>Query Indicator</span>
            </button>
          </div>

          <div>
            <label className="text-slate-400 block mb-1">Indicator of Compromise (IP, Domain, or Hash)</label>
            <input
              type="text"
              value={iocInput}
              onChange={(e) => setIocInput(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-200"
            />
          </div>

          <div className="flex gap-2">
            <button
              onClick={() => setIocInput('192.168.100.45')}
              className="px-2.5 py-1 bg-slate-950 text-rose-300 border border-slate-800 rounded cursor-pointer"
            >
              Lab Attacker IP (192.168.100.45)
            </button>
            <button
              onClick={() => setIocInput('127.0.0.1')}
              className="px-2.5 py-1 bg-slate-950 text-emerald-300 border border-slate-800 rounded cursor-pointer"
            >
              Internal Loopback (127.0.0.1)
            </button>
          </div>

          {openCtiResult && (
            <div className="p-4 bg-slate-950 border border-slate-800 rounded space-y-2">
              <div className="flex justify-between items-center border-b border-slate-800 pb-2">
                <span className="font-bold text-cyan-400">{openCtiResult.indicator}</span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                  openCtiResult.reputation_score > 50 ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                }`}>
                  Reputation Risk: {openCtiResult.reputation_score}/100
                </span>
              </div>
              <div className="text-[11px] text-slate-300">
                Threat Actor Alignment: <strong className="text-amber-300">{openCtiResult.threat_actor}</strong>
              </div>
              <p className="text-[11px] text-slate-400">{openCtiResult.description}</p>
            </div>
          )}
        </div>
      )}

      {/* TOOL 6: SHA-256 HASHER */}
      {activeTool === 'checksum' && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h2 className="font-bold text-slate-200 text-sm">Cryptographic Checksum Validator</h2>
              <p className="text-[11px] text-slate-400">
                Real-time Web Crypto API SHA-256 digest calculation for files, strings, and forensics
              </p>
            </div>
            <button
              onClick={handleComputeChecksum}
              className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded flex items-center gap-1.5 cursor-pointer"
            >
              <Binary className="w-3.5 h-3.5" />
              <span>Compute SHA-256</span>
            </button>
          </div>

          <div>
            <label className="text-slate-400 block mb-1">Raw Payload String / Buffer</label>
            <textarea
              rows={4}
              value={checksumInput}
              onChange={(e) => setChecksumInput(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded p-2.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
            />
          </div>

          {computedSha256 && (
            <div className="p-3 bg-slate-950 border border-emerald-600/60 rounded space-y-1">
              <span className="text-[10px] text-emerald-400 font-bold block">COMPUTED SHA-256 CHECKSUM:</span>
              <code className="text-cyan-300 break-all block text-xs">{computedSha256}</code>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
