/**
 * MAS-CSI Complete Zip Export Modal
 * Allows one-click downloading of the entire MAS-CSI-v9-FULL repository.
 */

import React, { useState } from 'react';
import { Download, CheckCircle2, FolderArchive, Terminal, FileCode2, BookOpen, X, Loader2 } from 'lucide-react';
import { generateAndDownloadProjectZip } from '../services/zipExporter';

interface ZipExportModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const ZipExportModal: React.FC<ZipExportModalProps> = ({ isOpen, onClose }) => {
  const [isExporting, setIsExporting] = useState(false);
  const [progress, setProgress] = useState(0);
  const [statusText, setStatusText] = useState('');
  const [downloadComplete, setDownloadComplete] = useState(false);

  if (!isOpen) return null;

  const handleDownload = async () => {
    try {
      setIsExporting(true);
      setDownloadComplete(false);
      setProgress(10);
      setStatusText('Bundling Python backend and agent modules...');

      await generateAndDownloadProjectZip((percent, file) => {
        setProgress(percent);
        setStatusText(file);
      });

      setIsExporting(false);
      setDownloadComplete(true);
      setStatusText('Archive MAS-CSI-v9-FULL.zip created and download triggered.');
    } catch (err) {
      console.error('ZIP generation error:', err);
      setIsExporting(false);
      setStatusText('Failed to generate archive: ' + (err as Error).message);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-xs p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-2xl w-full p-6 text-slate-100 shadow-2xl relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-slate-200 cursor-pointer"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3 mb-4">
          <div className="p-2.5 rounded bg-cyan-950 border border-cyan-500/40 text-cyan-400">
            <FolderArchive className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-lg font-bold font-mono tracking-tight text-slate-100">
              Download Full Project Archive (.ZIP)
            </h2>
            <p className="text-xs text-slate-400">
              Complete standalone source code for MAS-CSI v9.0 Full Architecture
            </p>
          </div>
        </div>

        <div className="space-y-3.5 my-5 text-xs text-slate-300">
          <p className="leading-relaxed">
            This archive packages the entire executable repository so you can extract, inspect, and run it locally:
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
            <div className="p-3 bg-slate-950 border border-slate-800 rounded">
              <div className="flex items-center gap-2 font-mono font-semibold text-cyan-300 mb-1">
                <FileCode2 className="w-4 h-4 text-cyan-400" />
                <span>backend/app/ & tests/</span>
              </div>
              <p className="text-[11px] text-slate-400">
                FastAPI REST & WebSocket server, deterministic detector, stateful correlator, 7-agent pipeline, SHA-256 evidence vault, pytest suite.
              </p>
            </div>

            <div className="p-3 bg-slate-950 border border-slate-800 rounded">
              <div className="flex items-center gap-2 font-mono font-semibold text-cyan-300 mb-1">
                <Terminal className="w-4 h-4 text-emerald-400" />
                <span>lab_webapp/ & scripts/</span>
              </div>
              <p className="text-[11px] text-slate-400">
                Authorized employee Real Lab portal, batch automation scripts (`run_all_windows.bat`, `run_backend.bat`, `run_frontend.bat`).
              </p>
            </div>

            <div className="p-3 bg-slate-950 border border-slate-800 rounded">
              <div className="flex items-center gap-2 font-mono font-semibold text-cyan-300 mb-1">
                <FolderArchive className="w-4 h-4 text-amber-400" />
                <span>integrations/</span>
              </div>
              <p className="text-[11px] text-slate-400">
                Wazuh, Suricata, Zeek, ClamAV, YARA, OWASP ZAP, and OpenCTI adapters reporting real operational states.
              </p>
            </div>

            <div className="p-3 bg-slate-950 border border-slate-800 rounded">
              <div className="flex items-center gap-2 font-mono font-semibold text-cyan-300 mb-1">
                <BookOpen className="w-4 h-4 text-purple-400" />
                <span>docs/ Suite (9 Files)</span>
              </div>
              <p className="text-[11px] text-slate-400">
                FEATURE_MAP, FINAL_VERIFICATION, ACCURACY_AND_VALIDATION, GENAI_AGENTIC_AI, REAL_DETECTION_RUNBOOK, INSTALLATION, and TESTING.
              </p>
            </div>
          </div>

          {/* Quick Execution Runbook */}
          <div className="p-3 bg-slate-950/80 border border-slate-800 rounded font-mono text-[11px]">
            <span className="text-slate-400">Quick run on your local machine:</span>
            <div className="mt-1 text-emerald-400">
              $ unzip MAS-CSI-v9-FULL.zip<br />
              $ cd MAS-CSI-v9-FULL/scripts &amp;&amp; ./run_all_windows.bat
            </div>
          </div>

          {/* Progress bar when exporting */}
          {isExporting && (
            <div className="space-y-1.5 pt-2">
              <div className="flex justify-between text-[11px] font-mono text-cyan-300">
                <span>{statusText}</span>
                <span>{progress}%</span>
              </div>
              <div className="w-full bg-slate-950 h-2 rounded overflow-hidden border border-slate-700">
                <div
                  className="bg-cyan-500 h-full transition-all duration-200"
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
          )}

          {downloadComplete && (
            <div className="flex items-center gap-2 p-2.5 bg-emerald-950/60 border border-emerald-600/50 rounded text-emerald-300 text-xs">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>MAS-CSI-v9-FULL.zip successfully downloaded to your device!</span>
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded text-xs font-mono text-slate-300 hover:bg-slate-800 cursor-pointer"
          >
            Close
          </button>
          <button
            onClick={handleDownload}
            disabled={isExporting}
            className="flex items-center gap-2 px-5 py-2 rounded bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-700 text-slate-950 font-mono font-bold text-xs transition cursor-pointer"
          >
            {isExporting ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Packing ZIP...</span>
              </>
            ) : (
              <>
                <Download className="w-4 h-4 stroke-[2.5]" />
                <span>Download MAS-CSI-v9-FULL.zip</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
