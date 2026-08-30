import { useState, useEffect, useMemo, useCallback, Fragment } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ShieldAlert,
  ArrowLeft,
  ExternalLink,
  Download,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Loader2,
  Calendar,
  Clock,
  Layers,
  AlertOctagon,
  Copy,
  Check,
  Sparkles,
  Bot,
  MessageSquare,
  RefreshCw,
  Send,
  X,
  Link2,
  CheckSquare,
  ShieldCheck,
} from 'lucide-react';
import axios from 'axios';

import { useAuth } from '@/hooks/useAuth';
import { getScan, getScanFindings, downloadScanPdf } from '@/services/scans';
import {
  getAIStatus,
  getScanAIAnalysis,
  explainFindingWithAI,
  sendAIChat,
} from '@/services/ai';
import type { ScanDetail, Finding } from '@/types/scan';
import type {
  AIStatus,
  ScanAIAnalysis,
  FindingAIExplanation,
  AIChatMessage,
} from '@/types/ai';
import StatusBadge from '@/components/ui/StatusBadge';
import SkeletonRow from '@/components/ui/SkeletonRow';
import AppHeader from '@/components/layout/AppHeader';

function formatDate(iso?: string | null): string {
  if (!iso) return '--';
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return '--';
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return '--';
  }
}

const severityConfig: Record<
  Finding['severity'],
  { label: string; bg: string; text: string; border: string; iconColor: string }
> = {
  CRITICAL: {
    label: 'CRITICAL',
    bg: 'bg-red-500/10',
    text: 'text-red-400',
    border: 'border-red-500/30',
    iconColor: 'text-red-400',
  },
  HIGH: {
    label: 'HIGH',
    bg: 'bg-orange-500/10',
    text: 'text-orange-400',
    border: 'border-orange-500/30',
    iconColor: 'text-orange-400',
  },
  MEDIUM: {
    label: 'MEDIUM',
    bg: 'bg-yellow-500/10',
    text: 'text-yellow-400',
    border: 'border-yellow-500/30',
    iconColor: 'text-yellow-400',
  },
  LOW: {
    label: 'LOW',
    bg: 'bg-blue-500/10',
    text: 'text-blue-400',
    border: 'border-blue-500/30',
    iconColor: 'text-blue-400',
  },
};

type ActiveTab = 'findings' | 'ai-analysis' | 'ai-chat';

export default function ScanResultPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const { user, loading: authLoading } = useAuth();

  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string>('');
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set());
  const [copiedUrl, setCopiedUrl] = useState<boolean>(false);
  const [actionNotice, setActionNotice] = useState<string>('');
  const [pdfLoading, setPdfLoading] = useState<boolean>(false);

  // AI State
  const [activeTab, setActiveTab] = useState<ActiveTab>('findings');
  const [aiStatus, setAiStatus] = useState<AIStatus | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<ScanAIAnalysis | null>(null);
  const [aiAnalysisLoading, setAiAnalysisLoading] = useState<boolean>(false);
  const [aiAnalysisError, setAiAnalysisError] = useState<string>('');

  // Finding Modal State
  const [selectedFindingForAI, setSelectedFindingForAI] = useState<Finding | null>(null);
  const [findingExplanation, setFindingExplanation] = useState<FindingAIExplanation | null>(null);
  const [findingExplanationLoading, setFindingExplanationLoading] = useState<boolean>(false);

  // Chat State
  const [chatMessages, setChatMessages] = useState<AIChatMessage[]>([
    {
      role: 'assistant',
      content:
        'Hello! I am ShadowScan AI Security Analyst. I can explain findings, prioritize your remediation roadmap, or answer web security questions about this scan.',
    },
  ]);
  const [chatInput, setChatInput] = useState<string>('');
  const [chatLoading, setChatLoading] = useState<boolean>(false);

  const numericScanId = scanId ? parseInt(scanId, 10) : NaN;

  const fetchScanData = useCallback(async () => {
    if (isNaN(numericScanId)) {
      setError('Invalid Scan ID provided.');
      setLoading(false);
      return;
    }

    setLoading(true);
    setError('');

    try {
      // 1. Fetch scan details
      const scanData = await getScan(numericScanId);
      setScan(scanData);

      // 2. Fetch findings for this scan
      try {
        const findingsData = await getScanFindings(numericScanId);
        if (Array.isArray(findingsData)) {
          setFindings(findingsData);
        } else {
          setFindings([]);
        }
      } catch {
        setFindings([]);
      }

      // 3. Fetch AI Service Status
      try {
        const status = await getAIStatus();
        setAiStatus(status);
      } catch {
        setAiStatus(null);
      }
    } catch (err: unknown) {
      if (axios.isAxiosError(err)) {
        if (err.response?.status === 404) {
          setError(`Scan #${numericScanId} not found.`);
        } else if (err.response?.status === 403) {
          setError('You do not have permission to view this scan report.');
        } else {
          const detail = err.response?.data?.detail;
          setError(typeof detail === 'string' ? detail : 'Failed to load scan results.');
        }
      } else {
        setError('An unexpected error occurred while loading the scan results.');
      }
    } finally {
      setLoading(false);
    }
  }, [numericScanId]);

  useEffect(() => {
    fetchScanData();
  }, [fetchScanData]);

  // Polling if scan is currently active (PENDING or RUNNING)
  useEffect(() => {
    if (!scan || (scan.status !== 'PENDING' && scan.status !== 'RUNNING')) return;

    const interval = setInterval(() => {
      fetchScanData();
    }, 2500);

    return () => clearInterval(interval);
  }, [scan, fetchScanData]);

  // Fetch AI Analysis when navigating to AI Analysis tab
  const fetchAIAnalysis = useCallback(async () => {
    if (isNaN(numericScanId)) return;
    setAiAnalysisLoading(true);
    setAiAnalysisError('');
    try {
      const data = await getScanAIAnalysis(numericScanId);
      setAiAnalysis(data);
    } catch {
      setAiAnalysisError(
        'AI Security Analyst is currently unavailable. Your scanner findings remain unaffected.'
      );
    } finally {
      setAiAnalysisLoading(false);
    }
  }, [numericScanId]);

  useEffect(() => {
    if (activeTab === 'ai-analysis' && !aiAnalysis && !aiAnalysisLoading && !aiAnalysisError) {
      fetchAIAnalysis();
    }
  }, [activeTab, aiAnalysis, aiAnalysisLoading, aiAnalysisError, fetchAIAnalysis]);

  // Calculate dynamic severity breakdown
  const stats = useMemo(() => {
    const total = findings.length;
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;

    for (const f of findings) {
      const sev = f.severity?.toUpperCase();
      if (sev === 'CRITICAL') critical++;
      else if (sev === 'HIGH') high++;
      else if (sev === 'MEDIUM') medium++;
      else if (sev === 'LOW') low++;
    }

    return { total, critical, high, medium, low };
  }, [findings]);

  const toggleRow = (id: number) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const handleCopyUrl = () => {
    if (scan?.target_url) {
      navigator.clipboard.writeText(scan.target_url);
      setCopiedUrl(true);
      setTimeout(() => setCopiedUrl(false), 2000);
    }
  };

  const handleDownloadPdf = async () => {
    if (!scan || pdfLoading) return;
    setPdfLoading(true);
    try {
      const blob = await downloadScanPdf(scan.id);
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `shadowscan-report-${scan.id}.pdf`;
      link.click();
      URL.revokeObjectURL(url);
    } catch {
      setActionNotice('Failed to generate PDF report. Please try again.');
      setTimeout(() => setActionNotice(''), 4000);
    } finally {
      setPdfLoading(false);
    }
  };

  const handleExportJson = () => {
    if (!scan) return;
    try {
      const exportPayload = {
        scan,
        findings,
        ai_analysis: aiAnalysis,
        exported_at: new Date().toISOString(),
      };
      const blob = new Blob([JSON.stringify(exportPayload, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `shadowscan-report-${scan.id}.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch {
      setActionNotice('Failed to export JSON report.');
      setTimeout(() => setActionNotice(''), 3000);
    }
  };

  // Explain single finding with AI
  const handleExplainFinding = async (finding: Finding) => {
    if (isNaN(numericScanId)) return;
    setSelectedFindingForAI(finding);
    setFindingExplanation(null);
    setFindingExplanationLoading(true);

    try {
      const res = await explainFindingWithAI(numericScanId, finding.id);
      setFindingExplanation(res);
    } catch {
      setFindingExplanation({
        finding_id: finding.id,
        title: finding.vulnerability_name,
        severity: finding.severity,
        meaning: finding.description || 'Vulnerability detected by scanner.',
        impact_analysis: 'AI explanation service currently unavailable.',
        severity_justification: `Classified as ${finding.severity} by ShadowScan rule base.`,
        remediation_guide: finding.recommendation || 'Apply standard security best practices.',
        verification_method: 'Re-run scan to verify remediation.',
        ai_status: 'unavailable',
        model_used: 'fallback',
      });
    } finally {
      setFindingExplanationLoading(false);
    }
  };

  // Chat message submission
  const handleSendChat = async (messageText?: string) => {
    const textToSend = messageText || chatInput;
    if (!textToSend.trim() || isNaN(numericScanId) || chatLoading) return;

    const userMsg: AIChatMessage = { role: 'user', content: textToSend.trim() };
    const updatedHistory = [...chatMessages, userMsg];
    setChatMessages(updatedHistory);
    setChatInput('');
    setChatLoading(true);

    try {
      const resp = await sendAIChat(numericScanId, textToSend.trim(), updatedHistory.slice(-8));
      setChatMessages((prev) => [
        ...prev,
        { role: 'assistant', content: resp.response },
      ]);
    } catch {
      setChatMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content:
            'The AI Security Analyst is currently unreachable. Your scan findings remain unaffected.',
        },
      ]);
    } finally {
      setChatLoading(false);
    }
  };

  if (authLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-brand-bg">
        <Loader2 size={32} className="animate-spin text-brand-cyan" />
      </div>
    );
  }

  return (
    <div className="flex min-h-screen flex-col bg-brand-bg">
      <AppHeader user={user} />

      {/* Main Content */}
      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-8 sm:px-6 lg:px-8">
        {/* Navigation Breadcrumb & Back Link */}
        <div className="mb-6 flex flex-wrap items-center justify-between gap-4">
          <Link
            to="/dashboard"
            id="back-to-dashboard-btn"
            className="inline-flex items-center gap-2 rounded-lg border border-brand-border bg-brand-surface px-3.5 py-2 text-sm font-medium text-brand-subtle transition-colors hover:border-brand-cyan/40 hover:text-brand-cyan"
          >
            <ArrowLeft size={16} />
            Back to Dashboard
          </Link>

          {/* Export Action Buttons */}
          <div className="flex items-center gap-2.5">
            <button
              id="export-json-btn"
              type="button"
              onClick={handleExportJson}
              disabled={loading || !scan}
              className="inline-flex items-center gap-1.5 rounded-lg border border-brand-border bg-brand-surface px-3.5 py-2 text-xs font-semibold text-brand-text transition-all duration-200 hover:border-brand-cyan/40 hover:text-brand-cyan disabled:cursor-not-allowed disabled:opacity-50"
            >
              <FileCode size={14} className="text-brand-cyan" />
              Export JSON
            </button>

            <button
              id="download-pdf-btn"
              type="button"
              onClick={handleDownloadPdf}
              disabled={loading || !scan || pdfLoading}
              className="inline-flex items-center gap-1.5 rounded-lg bg-brand-cyan px-3.5 py-2 text-xs font-semibold text-brand-bg shadow-btn-cyan transition-all duration-200 hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {pdfLoading ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
              {pdfLoading ? 'Generating...' : 'Download PDF'}
            </button>
          </div>
        </div>

        {/* Action Notice */}
        {actionNotice && (
          <div
            className="mb-6 flex items-center justify-between rounded-lg border border-brand-cyan/30 bg-brand-cyan/10 px-4 py-3 text-sm text-brand-cyan"
            role="status"
          >
            <div className="flex items-center gap-2">
              <AlertTriangle size={16} />
              <span>{actionNotice}</span>
            </div>
            <button
              onClick={() => setActionNotice('')}
              className="text-xs font-semibold hover:underline"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Error State */}
        {error && !loading && (
          <div className="rounded-2xl border border-red-500/20 bg-brand-surface p-12 text-center shadow-card">
            <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-red-500/10 text-red-400 ring-1 ring-red-500/30">
              <AlertOctagon size={28} />
            </div>
            <h2 className="text-xl font-bold text-brand-text">Scan Unavailable</h2>
            <p className="mx-auto mt-2 max-w-md text-sm text-brand-subtle">{error}</p>
            <Link
              to="/dashboard"
              className="mt-6 inline-flex items-center gap-2 rounded-lg bg-brand-cyan px-5 py-2.5 text-sm font-semibold text-brand-bg shadow-btn-cyan transition-colors hover:bg-cyan-300"
            >
              <ArrowLeft size={16} />
              Return to Dashboard
            </Link>
          </div>
        )}

        {/* Loading Skeleton */}
        {loading && (
          <div className="flex flex-col gap-6">
            <div className="animate-pulse rounded-2xl border border-brand-border bg-brand-surface p-6 sm:p-8">
              <div className="h-6 w-1/3 rounded bg-brand-card" />
              <div className="mt-3 h-4 w-1/2 rounded bg-brand-card/60" />
            </div>
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
              {Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="animate-pulse rounded-xl border border-brand-border bg-brand-surface p-4">
                  <div className="h-3 w-16 rounded bg-brand-card" />
                  <div className="mt-3 h-7 w-10 rounded bg-brand-card" />
                </div>
              ))}
            </div>
            <div className="rounded-2xl border border-brand-border bg-brand-surface p-6">
              <div className="mb-4 h-5 w-32 rounded bg-brand-card" />
              <table className="w-full">
                <tbody>
                  {Array.from({ length: 4 }).map((_, i) => (
                    <SkeletonRow key={i} cols={5} />
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Loaded Scan Content */}
        {!loading && !error && scan && (
          <div className="flex flex-col gap-8">
            {/* Section 1: Scan Overview Header Card */}
            <div className="rounded-2xl border border-brand-border bg-brand-surface p-6 shadow-card sm:p-8">
              <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
                <div className="flex-1">
                  <div className="flex flex-wrap items-center gap-3">
                    <StatusBadge status={scan.status} />
                    <span className="text-xs font-mono text-brand-muted">Scan #{scan.id}</span>
                    {aiStatus?.available ? (
                      <span className="inline-flex items-center gap-1 rounded-full bg-cyan-500/10 px-2.5 py-0.5 text-xs font-medium text-brand-cyan border border-brand-cyan/20">
                        <Sparkles size={12} />
                        AI Analyst Ready ({aiStatus.model})
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 rounded-full bg-brand-card px-2.5 py-0.5 text-xs font-medium text-brand-muted border border-brand-border">
                        <Bot size={12} />
                        AI Analyst Offline
                      </span>
                    )}
                  </div>

                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    <h1
                      className="font-mono text-xl font-bold text-brand-text sm:text-2xl"
                      title={scan.target_url}
                    >
                      {scan.target_url}
                    </h1>
                    <button
                      type="button"
                      onClick={handleCopyUrl}
                      className="inline-flex items-center gap-1 rounded-md border border-brand-border bg-brand-card px-2 py-1 text-xs text-brand-subtle transition-colors hover:border-brand-cyan/40 hover:text-brand-cyan"
                      title="Copy URL"
                      aria-label="Copy Target URL"
                    >
                      {copiedUrl ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
                      {copiedUrl ? 'Copied' : 'Copy'}
                    </button>
                    <a
                      href={scan.target_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 rounded-md border border-brand-border bg-brand-card px-2 py-1 text-xs text-brand-subtle transition-colors hover:border-brand-cyan/40 hover:text-brand-cyan"
                      title="Open URL in new tab"
                      aria-label="Open URL in new tab"
                    >
                      <ExternalLink size={13} />
                      Visit
                    </a>
                  </div>

                  <div className="mt-4 flex flex-wrap items-center gap-6 text-xs text-brand-subtle">
                    <div className="flex items-center gap-1.5">
                      <Calendar size={14} className="text-brand-muted" />
                      <span>Started: {formatDate(scan.created_at)}</span>
                    </div>
                    {scan.completed_at && (
                      <div className="flex items-center gap-1.5">
                        <Clock size={14} className="text-brand-muted" />
                        <span>Completed: {formatDate(scan.completed_at)}</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Risk Score Widget */}
                <div className="flex shrink-0 items-center gap-4 rounded-xl border border-brand-border bg-brand-card/70 p-4 sm:p-5">
                  <div className="flex flex-col">
                    <span className="text-xs font-semibold uppercase tracking-wider text-brand-muted">
                      Overall Risk Score
                    </span>
                    <span className="mt-0.5 text-xs text-brand-subtle">
                      Vulnerability rating (0.0 - 10.0)
                    </span>
                  </div>

                  <div className="flex items-center">
                    {scan.risk_score !== null ? (
                      <div
                        className={`flex h-14 w-14 items-center justify-center rounded-xl border text-xl font-bold tabular-nums shadow-sm ${
                          scan.risk_score >= 7.0
                            ? 'border-red-500/40 bg-red-500/10 text-red-400'
                            : scan.risk_score >= 4.0
                            ? 'border-yellow-500/40 bg-yellow-500/10 text-yellow-400'
                            : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
                        }`}
                      >
                        {scan.risk_score.toFixed(1)}
                      </div>
                    ) : (
                      <div className="flex h-14 w-14 items-center justify-center rounded-xl border border-brand-border bg-brand-surface font-mono text-sm text-brand-muted">
                        --
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* Section 2: Severity Breakdown Cards */}
            <div>
              <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-brand-muted">
                Severity Breakdown
              </h2>
              <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
                <div className="rounded-xl border border-brand-border bg-brand-surface p-4 shadow-card">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-brand-subtle">Total Findings</span>
                    <Layers size={16} className="text-brand-cyan" />
                  </div>
                  <p className="mt-2 text-2xl font-bold text-brand-text">{stats.total}</p>
                </div>

                <div className="rounded-xl border border-red-500/30 bg-brand-surface p-4 shadow-card">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-red-400">Critical</span>
                    <ShieldAlert size={16} className="text-red-400" />
                  </div>
                  <p className="mt-2 text-2xl font-bold text-red-400">{stats.critical}</p>
                </div>

                <div className="rounded-xl border border-orange-500/30 bg-brand-surface p-4 shadow-card">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-orange-400">High</span>
                    <AlertTriangle size={16} className="text-orange-400" />
                  </div>
                  <p className="mt-2 text-2xl font-bold text-orange-400">{stats.high}</p>
                </div>

                <div className="rounded-xl border border-yellow-500/30 bg-brand-surface p-4 shadow-card">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-yellow-400">Medium</span>
                    <AlertTriangle size={16} className="text-yellow-400" />
                  </div>
                  <p className="mt-2 text-2xl font-bold text-yellow-400">{stats.medium}</p>
                </div>

                <div className="rounded-xl border border-blue-500/30 bg-brand-surface p-4 shadow-card">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-blue-400">Low</span>
                    <CheckCircle2 size={16} className="text-blue-400" />
                  </div>
                  <p className="mt-2 text-2xl font-bold text-blue-400">{stats.low}</p>
                </div>
              </div>
            </div>

            {/* Navigation Tabs */}
            <div className="flex border-b border-brand-border gap-2">
              <button
                type="button"
                onClick={() => setActiveTab('findings')}
                className={`inline-flex items-center gap-2 border-b-2 px-4 py-3 text-sm font-semibold transition-colors ${
                  activeTab === 'findings'
                    ? 'border-brand-cyan text-brand-cyan'
                    : 'border-transparent text-brand-subtle hover:text-brand-text'
                }`}
              >
                <Layers size={16} />
                Overview & Findings ({findings.length})
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('ai-analysis')}
                className={`inline-flex items-center gap-2 border-b-2 px-4 py-3 text-sm font-semibold transition-colors ${
                  activeTab === 'ai-analysis'
                    ? 'border-brand-cyan text-brand-cyan'
                    : 'border-transparent text-brand-subtle hover:text-brand-text'
                }`}
              >
                <Sparkles size={16} className="text-brand-cyan" />
                AI Security Analysis
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('ai-chat')}
                className={`inline-flex items-center gap-2 border-b-2 px-4 py-3 text-sm font-semibold transition-colors ${
                  activeTab === 'ai-chat'
                    ? 'border-brand-cyan text-brand-cyan'
                    : 'border-transparent text-brand-subtle hover:text-brand-text'
                }`}
              >
                <MessageSquare size={16} />
                AI Security Chat
              </button>
            </div>

            {/* TAB 1: Findings Table */}
            {activeTab === 'findings' && (
              <div className="rounded-2xl border border-brand-border bg-brand-surface shadow-card">
                <div className="flex items-center justify-between border-b border-brand-border px-6 py-4">
                  <div>
                    <h2 className="text-base font-semibold text-brand-text">Vulnerability Findings</h2>
                    <p className="text-xs text-brand-muted">
                      Detailed security issues discovered during the automated scan
                    </p>
                  </div>
                  <span className="rounded-full bg-brand-card px-3 py-1 text-xs font-mono text-brand-subtle">
                    {findings.length} item{findings.length === 1 ? '' : 's'}
                  </span>
                </div>

                {findings.length === 0 ? (
                  <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
                    <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-brand-cyan/10 text-brand-cyan ring-1 ring-brand-cyan/30">
                      <CheckCircle2 size={28} />
                    </div>
                    <h3 className="text-base font-semibold text-brand-text">No Vulnerabilities Found</h3>
                    <p className="mt-1 max-w-sm text-xs text-brand-muted">
                      No security flaws were detected for this target.
                    </p>
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm" aria-label="Vulnerability findings table">
                      <thead>
                        <tr className="border-b border-brand-border bg-brand-card/50 text-xs font-medium uppercase tracking-wider text-brand-muted">
                          <th className="px-6 py-3.5">Severity</th>
                          <th className="px-6 py-3.5">Vulnerability Title</th>
                          <th className="px-6 py-3.5">Description</th>
                          <th className="px-6 py-3.5">Recommendation</th>
                          <th className="px-6 py-3.5">Actions</th>
                          <th className="px-4 py-3.5 text-center">Details</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-brand-border">
                        {findings.map((finding) => {
                          const sevKey = (finding.severity?.toUpperCase() || 'LOW') as Finding['severity'];
                          const sev = severityConfig[sevKey] || severityConfig.LOW;
                          const isExpanded = expandedRows.has(finding.id);

                          return (
                            <Fragment key={finding.id}>
                              <tr
                                onClick={() => toggleRow(finding.id)}
                                className="cursor-pointer transition-colors duration-150 hover:bg-brand-card/60"
                              >
                                <td className="whitespace-nowrap px-6 py-4">
                                  <span
                                    className={`inline-flex items-center gap-1 rounded-md border px-2.5 py-0.5 text-xs font-bold ${sev.bg} ${sev.text} ${sev.border}`}
                                  >
                                    {sev.label}
                                  </span>
                                </td>

                                <td className="px-6 py-4 font-medium text-brand-text">
                                  <span className="block max-w-[200px] truncate" title={finding.vulnerability_name}>
                                    {finding.vulnerability_name}
                                  </span>
                                </td>

                                <td className="px-6 py-4 text-xs text-brand-subtle">
                                  <span className="block max-w-[220px] truncate" title={finding.description || '--'}>
                                    {finding.description || '--'}
                                  </span>
                                </td>

                                <td className="px-6 py-4 text-xs text-brand-subtle">
                                  <span className="block max-w-[220px] truncate" title={finding.recommendation || '--'}>
                                    {finding.recommendation || '--'}
                                  </span>
                                </td>

                                <td className="whitespace-nowrap px-6 py-4">
                                  <button
                                    type="button"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      handleExplainFinding(finding);
                                    }}
                                    className="inline-flex items-center gap-1.5 rounded-lg border border-brand-cyan/40 bg-brand-cyan/10 px-2.5 py-1 text-xs font-semibold text-brand-cyan transition-colors hover:bg-brand-cyan/20"
                                  >
                                    <Sparkles size={12} />
                                    Explain with AI
                                  </button>
                                </td>

                                <td className="px-4 py-4 text-center">
                                  <button
                                    type="button"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      toggleRow(finding.id);
                                    }}
                                    className="rounded-md p-1 text-brand-muted transition-colors hover:bg-brand-border/60 hover:text-brand-cyan"
                                    aria-label={isExpanded ? 'Collapse row' : 'Expand row'}
                                  >
                                    {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                                  </button>
                                </td>
                              </tr>

                              {isExpanded && (
                                <tr className="border-b border-brand-border bg-brand-card/80">
                                  <td colSpan={6} className="px-6 py-5">
                                    <div className="flex flex-col gap-4">
                                      <div>
                                        <h4 className="text-xs font-semibold uppercase tracking-wider text-brand-cyan">
                                          Description
                                        </h4>
                                        <p className="mt-1 text-xs leading-relaxed text-brand-text">
                                          {finding.description || 'No detailed description provided.'}
                                        </p>
                                      </div>

                                      <div>
                                        <h4 className="text-xs font-semibold uppercase tracking-wider text-emerald-400">
                                          Remediation & Recommendation
                                        </h4>
                                        <p className="mt-1 text-xs leading-relaxed text-brand-subtle">
                                          {finding.recommendation || 'No recommendation available.'}
                                        </p>
                                      </div>

                                      <div className="flex items-center justify-between border-t border-brand-border/60 pt-3 text-xs text-brand-muted">
                                        <div className="flex items-center gap-4">
                                          <span>Finding ID: #{finding.id}</span>
                                          <span>Plugin: <strong className="text-brand-text">{finding.plugin || 'scanner'}</strong></span>
                                          <span>Status: <strong className="text-brand-text">{finding.status}</strong></span>
                                        </div>
                                        <button
                                          type="button"
                                          onClick={() => handleExplainFinding(finding)}
                                          className="inline-flex items-center gap-1 text-xs font-semibold text-brand-cyan hover:underline"
                                        >
                                          <Sparkles size={12} />
                                          Open Deep AI Analysis
                                        </button>
                                      </div>
                                    </div>
                                  </td>
                                </tr>
                              )}
                            </Fragment>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* TAB 2: AI Security Analysis */}
            {activeTab === 'ai-analysis' && (
              <div className="flex flex-col gap-6">
                {/* Header & Refresh */}
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-lg font-bold text-brand-text flex items-center gap-2">
                      <Sparkles size={20} className="text-brand-cyan" />
                      AI Security Analysis & Correlation
                    </h2>
                    <p className="text-xs text-brand-subtle">
                      Synthesized risk analysis, finding correlations, and remediation roadmap generated by Ollama
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={fetchAIAnalysis}
                    disabled={aiAnalysisLoading}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-brand-border bg-brand-surface px-3 py-1.5 text-xs font-semibold text-brand-subtle transition-colors hover:border-brand-cyan/40 hover:text-brand-cyan disabled:opacity-50"
                  >
                    <RefreshCw size={13} className={aiAnalysisLoading ? 'animate-spin' : ''} />
                    Refresh Analysis
                  </button>
                </div>

                {/* Loading State */}
                {aiAnalysisLoading && (
                  <div className="rounded-2xl border border-brand-border bg-brand-surface p-12 text-center">
                    <Loader2 size={36} className="mx-auto animate-spin text-brand-cyan" />
                    <h3 className="mt-4 text-sm font-semibold text-brand-text">
                      Analyzing scan findings with Ollama...
                    </h3>
                    <p className="mt-1 text-xs text-brand-muted">
                      Correlating 45 plugin outputs, evaluating attack paths, and ordering remediation priorities.
                    </p>
                  </div>
                )}

                {/* Error / Fallback State */}
                {aiAnalysisError && !aiAnalysisLoading && (
                  <div className="rounded-xl border border-yellow-500/30 bg-yellow-500/10 p-4 text-xs text-yellow-300 flex items-start gap-3">
                    <AlertTriangle size={18} className="shrink-0 text-yellow-400" />
                    <div>
                      <h4 className="font-semibold">AI Analysis Notice</h4>
                      <p className="mt-0.5">{aiAnalysisError}</p>
                    </div>
                  </div>
                )}

                {/* Loaded AI Analysis */}
                {!aiAnalysisLoading && aiAnalysis && (
                  <div className="flex flex-col gap-6">
                    {/* Overall Assessment & Executive Summary */}
                    <div className="rounded-2xl border border-brand-border bg-brand-surface p-6 shadow-card">
                      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-brand-border/60 pb-4">
                        <div>
                          <span className="text-xs font-semibold uppercase tracking-wider text-brand-muted">
                            Overall Assessment
                          </span>
                          <p className="mt-1 text-sm font-medium text-brand-text">
                            {aiAnalysis.overall_assessment}
                          </p>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-brand-muted">AI Risk Level:</span>
                          <span className="rounded-md border border-brand-cyan/40 bg-brand-cyan/10 px-3 py-1 text-xs font-bold text-brand-cyan">
                            {aiAnalysis.risk_level}
                          </span>
                        </div>
                      </div>

                      <div className="mt-4">
                        <h4 className="text-xs font-semibold uppercase tracking-wider text-brand-cyan">
                          Executive Summary
                        </h4>
                        <p className="mt-1 text-xs leading-relaxed text-brand-subtle">
                          {aiAnalysis.executive_summary}
                        </p>
                      </div>
                    </div>

                    {/* Top Priorities & Finding Relationships */}
                    <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
                      {/* Priority Ranking */}
                      <div className="rounded-2xl border border-brand-border bg-brand-surface p-6 shadow-card">
                        <h3 className="text-sm font-semibold uppercase tracking-wider text-brand-text flex items-center gap-2">
                          <ShieldAlert size={16} className="text-orange-400" />
                          Top Priority Findings
                        </h3>
                        {aiAnalysis.priority_findings.length === 0 ? (
                          <p className="mt-3 text-xs text-brand-muted">No high priority issues identified.</p>
                        ) : (
                          <div className="mt-4 flex flex-col gap-3">
                            {aiAnalysis.priority_findings.map((pf) => (
                              <div
                                key={pf.finding_id}
                                className="rounded-xl border border-brand-border bg-brand-card/60 p-3 text-xs"
                              >
                                <div className="flex items-center justify-between">
                                  <span className="font-semibold text-brand-text">
                                    #{pf.priority}. {pf.title || `Finding #${pf.finding_id}`}
                                  </span>
                                  <span className="font-mono text-xs text-brand-muted">ID: #{pf.finding_id}</span>
                                </div>
                                <p className="mt-1 text-brand-subtle">{pf.reason}</p>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* Finding Correlations */}
                      <div className="rounded-2xl border border-brand-border bg-brand-surface p-6 shadow-card">
                        <h3 className="text-sm font-semibold uppercase tracking-wider text-brand-text flex items-center gap-2">
                          <Link2 size={16} className="text-brand-cyan" />
                          Finding Relationships & Attack Chains
                        </h3>
                        {aiAnalysis.relationships.length === 0 ? (
                          <p className="mt-3 text-xs text-brand-muted">
                            No compound vulnerability relationships detected. Findings operate independently.
                          </p>
                        ) : (
                          <div className="mt-4 flex flex-col gap-3">
                            {aiAnalysis.relationships.map((rel, idx) => (
                              <div
                                key={idx}
                                className="rounded-xl border border-brand-border bg-brand-card/60 p-3 text-xs"
                              >
                                <div className="flex items-center gap-2">
                                  <span className="font-semibold text-brand-cyan">Related Findings:</span>
                                  <div className="flex gap-1">
                                    {rel.finding_ids.map((id) => (
                                      <span
                                        key={id}
                                        className="rounded bg-brand-border px-1.5 py-0.5 font-mono text-[10px] text-brand-text"
                                      >
                                        #{id}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                                <p className="mt-1.5 text-brand-subtle">{rel.explanation}</p>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Remediation Plan & Verification Steps */}
                    <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
                      {/* Remediation Plan */}
                      <div className="rounded-2xl border border-brand-border bg-brand-surface p-6 shadow-card">
                        <h3 className="text-sm font-semibold uppercase tracking-wider text-emerald-400 flex items-center gap-2">
                          <ShieldCheck size={16} />
                          Recommended Remediation Plan
                        </h3>
                        <div className="mt-4 flex flex-col gap-3">
                          {aiAnalysis.remediation_plan.map((step, idx) => (
                            <div
                              key={idx}
                              className="rounded-xl border border-emerald-500/20 bg-brand-card/60 p-3 text-xs"
                            >
                              <div className="font-semibold text-emerald-300">
                                Step {step.priority}: {step.action}
                              </div>
                              {step.reason && (
                                <p className="mt-1 text-brand-subtle">{step.reason}</p>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Verification Steps */}
                      <div className="rounded-2xl border border-brand-border bg-brand-surface p-6 shadow-card">
                        <h3 className="text-sm font-semibold uppercase tracking-wider text-brand-cyan flex items-center gap-2">
                          <CheckSquare size={16} />
                          Verification Steps
                        </h3>
                        <ul className="mt-4 flex flex-col gap-2.5 text-xs text-brand-subtle">
                          {aiAnalysis.verification_steps.map((vstep, idx) => (
                            <li key={idx} className="flex items-start gap-2 rounded-lg bg-brand-card/40 p-2.5">
                              <span className="font-mono text-brand-cyan font-bold">{idx + 1}.</span>
                              <span className="leading-relaxed">{vstep}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* TAB 3: AI Security Chat */}
            {activeTab === 'ai-chat' && (
              <div className="rounded-2xl border border-brand-border bg-brand-surface shadow-card flex flex-col h-[650px]">
                {/* Chat Header */}
                <div className="flex items-center justify-between border-b border-brand-border px-6 py-4">
                  <div className="flex items-center gap-2.5">
                    <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-brand-cyan/10 text-brand-cyan ring-1 ring-brand-cyan/30">
                      <Bot size={20} />
                    </div>
                    <div>
                      <h3 className="text-sm font-semibold text-brand-text">ShadowScan AI Security Analyst</h3>
                      <p className="text-[11px] text-brand-muted">
                        Interactive consultation scoped to Scan #{scan.id}
                      </p>
                    </div>
                  </div>
                  {aiStatus?.available && (
                    <span className="text-[11px] font-mono text-emerald-400 flex items-center gap-1.5">
                      <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                      Model: {aiStatus.model}
                    </span>
                  )}
                </div>

                {/* Chat History */}
                <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-4">
                  {chatMessages.map((msg, idx) => (
                    <div
                      key={idx}
                      className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
                    >
                      <div
                        className={`max-w-[80%] rounded-2xl p-4 text-xs leading-relaxed ${
                          msg.role === 'user'
                            ? 'bg-brand-cyan text-brand-bg font-medium'
                            : 'border border-brand-border bg-brand-card text-brand-text'
                        }`}
                      >
                        {msg.content}
                      </div>
                    </div>
                  ))}
                  {chatLoading && (
                    <div className="flex justify-start">
                      <div className="rounded-2xl border border-brand-border bg-brand-card p-4 text-xs text-brand-muted flex items-center gap-2">
                        <Loader2 size={14} className="animate-spin text-brand-cyan" />
                        AI is analyzing your security query...
                      </div>
                    </div>
                  )}
                </div>

                {/* Quick Chips */}
                <div className="px-6 py-2 border-t border-brand-border/40 flex flex-wrap gap-1.5">
                  {[
                    'Which finding should I fix first?',
                    'Explain the overall risk in simple terms',
                    'How do I remediate finding #1?',
                    'What verification steps should I take?',
                  ].map((chip) => (
                    <button
                      key={chip}
                      type="button"
                      onClick={() => handleSendChat(chip)}
                      disabled={chatLoading}
                      className="rounded-full border border-brand-border bg-brand-card px-2.5 py-1 text-[11px] text-brand-subtle transition-colors hover:border-brand-cyan/40 hover:text-brand-cyan disabled:opacity-50"
                    >
                      {chip}
                    </button>
                  ))}
                </div>

                {/* Chat Input */}
                <div className="p-4 border-t border-brand-border">
                  <form
                    onSubmit={(e) => {
                      e.preventDefault();
                      handleSendChat();
                    }}
                    className="flex gap-2"
                  >
                    <input
                      type="text"
                      value={chatInput}
                      onChange={(e) => setChatInput(e.target.value)}
                      placeholder="Ask the AI Security Analyst about this scan, specific vulnerabilities, or remediation..."
                      disabled={chatLoading}
                      className="flex-1 rounded-xl border border-brand-border bg-brand-card px-4 py-2.5 text-xs text-brand-text placeholder:text-brand-muted focus:border-brand-cyan focus:outline-none"
                    />
                    <button
                      type="submit"
                      disabled={chatLoading || !chatInput.trim()}
                      className="inline-flex items-center gap-1.5 rounded-xl bg-brand-cyan px-4 py-2.5 text-xs font-semibold text-brand-bg transition-colors hover:bg-cyan-300 disabled:opacity-50"
                    >
                      <Send size={14} />
                      Send
                    </button>
                  </form>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Explain Finding Modal */}
        {selectedFindingForAI && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
            <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-brand-border bg-brand-surface p-6 shadow-2xl">
              <div className="flex items-center justify-between border-b border-brand-border pb-4">
                <div className="flex items-center gap-2">
                  <Sparkles size={18} className="text-brand-cyan" />
                  <h3 className="text-base font-bold text-brand-text">
                    AI Finding Analysis: {selectedFindingForAI.vulnerability_name}
                  </h3>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedFindingForAI(null)}
                  className="rounded-lg p-1 text-brand-muted hover:bg-brand-card hover:text-brand-text"
                >
                  <X size={18} />
                </button>
              </div>

              {findingExplanationLoading && (
                <div className="py-16 text-center">
                  <Loader2 size={32} className="mx-auto animate-spin text-brand-cyan" />
                  <p className="mt-3 text-xs text-brand-muted">
                    Generating technical impact analysis and tailored remediation guide...
                  </p>
                </div>
              )}

              {!findingExplanationLoading && findingExplanation && (
                <div className="mt-4 flex flex-col gap-4 text-xs">
                  <div>
                    <h4 className="font-semibold uppercase tracking-wider text-brand-cyan">
                      What This Finding Means
                    </h4>
                    <p className="mt-1 leading-relaxed text-brand-text">
                      {findingExplanation.meaning}
                    </p>
                  </div>

                  <div>
                    <h4 className="font-semibold uppercase tracking-wider text-orange-400">
                      Potential Technical & Business Impact
                    </h4>
                    <p className="mt-1 leading-relaxed text-brand-subtle">
                      {findingExplanation.impact_analysis}
                    </p>
                  </div>

                  <div>
                    <h4 className="font-semibold uppercase tracking-wider text-yellow-400">
                      Severity Justification ({findingExplanation.severity})
                    </h4>
                    <p className="mt-1 leading-relaxed text-brand-subtle">
                      {findingExplanation.severity_justification}
                    </p>
                  </div>

                  <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4">
                    <h4 className="font-semibold uppercase tracking-wider text-emerald-400">
                      Step-by-Step Remediation Guide
                    </h4>
                    <p className="mt-1 leading-relaxed text-brand-text whitespace-pre-line">
                      {findingExplanation.remediation_guide}
                    </p>
                  </div>

                  <div className="rounded-xl border border-brand-cyan/30 bg-brand-cyan/10 p-4">
                    <h4 className="font-semibold uppercase tracking-wider text-brand-cyan">
                      How to Verify the Fix
                    </h4>
                    <p className="mt-1 leading-relaxed text-brand-text whitespace-pre-line">
                      {findingExplanation.verification_method}
                    </p>
                  </div>

                  <div className="flex justify-end pt-2">
                    <button
                      type="button"
                      onClick={() => setSelectedFindingForAI(null)}
                      className="rounded-lg bg-brand-card border border-brand-border px-4 py-2 text-xs font-semibold text-brand-text hover:border-brand-cyan/40"
                    >
                      Close Analysis
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
