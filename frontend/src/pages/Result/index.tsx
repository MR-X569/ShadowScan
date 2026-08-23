import { useState, useEffect, useMemo, useCallback, Fragment } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import {
  Shield,
  ShieldAlert,
  ArrowLeft,
  ExternalLink,
  Download,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  LayoutDashboard,
  User as UserIcon,
  Settings as SettingsIcon,
  LogOut,
  Loader2,
  Calendar,
  Clock,
  Layers,
  AlertOctagon,
  Copy,
  Check,
} from 'lucide-react';
import axios from 'axios';

import { useAuth } from '@/hooks/useAuth';
import { getScan, getScanFindings } from '@/services/scans';
import { logout } from '@/services/auth';
import type { ScanDetail, Finding } from '@/types/scan';
import StatusBadge from '@/components/ui/StatusBadge';
import SkeletonRow from '@/components/ui/SkeletonRow';

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

export default function ScanResultPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const { user, loading: authLoading } = useAuth();

  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string>('');
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set());
  const [copiedUrl, setCopiedUrl] = useState<boolean>(false);
  const [actionNotice, setActionNotice] = useState<string>('');

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
        // Findings endpoint might not have data or may not be seeded yet
        setFindings([]);
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

  const handleDownloadPdf = () => {
    // TODO: Connect to backend PDF generation endpoint (e.g. GET /scans/{id}/report.pdf) once implemented
    setActionNotice('PDF report generation is pending backend implementation.');
    setTimeout(() => setActionNotice(''), 4000);
  };

  const handleExportJson = () => {
    if (!scan) return;
    try {
      const exportPayload = {
        scan,
        findings,
        exported_at: new Date().toISOString(),
      };
      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(exportPayload, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute('href', dataStr);
      downloadAnchor.setAttribute('download', `shadowscan-report-${scan.id}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    } catch {
      setActionNotice('Failed to export JSON report.');
      setTimeout(() => setActionNotice(''), 3000);
    }
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
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
      {/* Top Navbar */}
      <header className="sticky top-0 z-50 border-b border-brand-border bg-brand-bg/90 backdrop-blur-sm">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-4 sm:px-6 lg:px-8">
          {/* Logo */}
          <Link
            to="/dashboard"
            id="results-navbar-logo"
            className="flex items-center gap-2.5 text-xl font-bold text-brand-text"
            aria-label="Back to dashboard"
          >
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-cyan/10 text-brand-cyan ring-1 ring-brand-cyan/30">
              <Shield size={18} strokeWidth={2} />
            </div>
            <span>
              Shadow<span className="text-brand-cyan">Scan</span>
            </span>
          </Link>

          {/* Navigation Links */}
          <nav className="hidden items-center gap-2 md:flex" aria-label="App Navigation">
            <Link
              to="/dashboard"
              className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm font-medium text-brand-subtle transition-colors hover:bg-brand-surface hover:text-brand-text"
            >
              <LayoutDashboard size={15} />
              Dashboard
            </Link>
            <Link
              to="/profile"
              className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm font-medium text-brand-subtle transition-colors hover:bg-brand-surface hover:text-brand-text"
            >
              <UserIcon size={15} />
              Profile
            </Link>
            <Link
              to="/settings"
              className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm font-medium text-brand-subtle transition-colors hover:bg-brand-surface hover:text-brand-text"
            >
              <SettingsIcon size={15} />
              Settings
            </Link>
          </nav>

          {/* Right: user + logout */}
          <div className="flex items-center gap-3">
            <span className="hidden text-sm text-brand-subtle sm:block">
              {user?.email || '--'}
            </span>
            <button
              id="results-logout-btn"
              onClick={handleLogout}
              className="flex items-center gap-1.5 rounded-lg border border-brand-border px-3 py-2 text-sm font-medium text-brand-subtle transition-all duration-200 hover:border-red-500/30 hover:text-red-400"
            >
              <LogOut size={14} />
              Logout
            </button>
          </div>
        </div>
      </header>

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
              disabled={loading || !scan}
              className="inline-flex items-center gap-1.5 rounded-lg bg-brand-cyan px-3.5 py-2 text-xs font-semibold text-brand-bg shadow-btn-cyan transition-all duration-200 hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <Download size={14} />
              Download PDF
            </button>
          </div>
        </div>

        {/* Action Notice (e.g. PDF pending backend) */}
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
            {/* Header Skeleton */}
            <div className="animate-pulse rounded-2xl border border-brand-border bg-brand-surface p-6 sm:p-8">
              <div className="h-6 w-1/3 rounded bg-brand-card" />
              <div className="mt-3 h-4 w-1/2 rounded bg-brand-card/60" />
            </div>

            {/* Summary Cards Skeleton */}
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
              {Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="animate-pulse rounded-xl border border-brand-border bg-brand-surface p-4">
                  <div className="h-3 w-16 rounded bg-brand-card" />
                  <div className="mt-3 h-7 w-10 rounded bg-brand-card" />
                </div>
              ))}
            </div>

            {/* Table Skeleton */}
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
                {/* Target URL & Meta */}
                <div className="flex-1">
                  <div className="flex flex-wrap items-center gap-3">
                    <StatusBadge status={scan.status} />
                    <span className="text-xs font-mono text-brand-muted">Scan #{scan.id}</span>
                  </div>

                  {/* Target URL with copy and open actions */}
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

                  {/* Timestamps */}
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

            {/* Section 2: Vulnerability Summary Cards */}
            <div>
              <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-brand-muted">
                Severity Breakdown
              </h2>
              <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
                {/* Total */}
                <div className="rounded-xl border border-brand-border bg-brand-surface p-4 shadow-card">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-brand-subtle">Total Findings</span>
                    <Layers size={16} className="text-brand-cyan" />
                  </div>
                  <p className="mt-2 text-2xl font-bold text-brand-text">{stats.total}</p>
                </div>

                {/* Critical */}
                <div className="rounded-xl border border-red-500/30 bg-brand-surface p-4 shadow-card">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-red-400">Critical</span>
                    <ShieldAlert size={16} className="text-red-400" />
                  </div>
                  <p className="mt-2 text-2xl font-bold text-red-400">{stats.critical}</p>
                </div>

                {/* High */}
                <div className="rounded-xl border border-orange-500/30 bg-brand-surface p-4 shadow-card">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-orange-400">High</span>
                    <AlertTriangle size={16} className="text-orange-400" />
                  </div>
                  <p className="mt-2 text-2xl font-bold text-orange-400">{stats.high}</p>
                </div>

                {/* Medium */}
                <div className="rounded-xl border border-yellow-500/30 bg-brand-surface p-4 shadow-card">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-yellow-400">Medium</span>
                    <AlertTriangle size={16} className="text-yellow-400" />
                  </div>
                  <p className="mt-2 text-2xl font-bold text-yellow-400">{stats.medium}</p>
                </div>

                {/* Low */}
                <div className="rounded-xl border border-blue-500/30 bg-brand-surface p-4 shadow-card">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-blue-400">Low</span>
                    <CheckCircle2 size={16} className="text-blue-400" />
                  </div>
                  <p className="mt-2 text-2xl font-bold text-blue-400">{stats.low}</p>
                </div>
              </div>
            </div>

            {/* Section 3: Findings Table */}
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
                /* Empty State */
                <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
                  <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-brand-cyan/10 text-brand-cyan ring-1 ring-brand-cyan/30">
                    <CheckCircle2 size={28} />
                  </div>
                  <h3 className="text-base font-semibold text-brand-text">No Vulnerabilities Found</h3>
                  <p className="mt-1 max-w-sm text-xs text-brand-muted">
                    No security flaws were detected for this target, or the scan is currently queued/running.
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
                        <th className="px-6 py-3.5">Status / Reference</th>
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
                              {/* Severity Badge */}
                              <td className="whitespace-nowrap px-6 py-4">
                                <span
                                  className={`inline-flex items-center gap-1 rounded-md border px-2.5 py-0.5 text-xs font-bold ${sev.bg} ${sev.text} ${sev.border}`}
                                >
                                  {sev.label}
                                </span>
                              </td>

                              {/* Vulnerability Title */}
                              <td className="px-6 py-4 font-medium text-brand-text">
                                <span className="block max-w-[200px] truncate" title={finding.vulnerability_name}>
                                  {finding.vulnerability_name}
                                </span>
                              </td>

                              {/* Description Preview */}
                              <td className="px-6 py-4 text-xs text-brand-subtle">
                                <span className="block max-w-[220px] truncate" title={finding.description || '--'}>
                                  {finding.description || '--'}
                                </span>
                              </td>

                              {/* Recommendation Preview */}
                              <td className="px-6 py-4 text-xs text-brand-subtle">
                                <span className="block max-w-[220px] truncate" title={finding.recommendation || '--'}>
                                  {finding.recommendation || '--'}
                                </span>
                              </td>

                              {/* Status / Reference */}
                              <td className="whitespace-nowrap px-6 py-4 font-mono text-xs text-brand-muted">
                                {finding.status || '--'}
                              </td>

                              {/* Expand/Collapse Toggle */}
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

                            {/* Expanded Detail Panel */}
                            {isExpanded && (
                              <tr className="border-b border-brand-border bg-brand-card/80">
                                <td colSpan={6} className="px-6 py-5">
                                  <div className="flex flex-col gap-4">
                                    {/* Detailed Description */}
                                    <div>
                                      <h4 className="text-xs font-semibold uppercase tracking-wider text-brand-cyan">
                                        Description
                                      </h4>
                                      <p className="mt-1 text-xs leading-relaxed text-brand-text">
                                        {finding.description || 'No detailed description provided.'}
                                      </p>
                                    </div>

                                    {/* Remediation / Recommendation */}
                                    <div>
                                      <h4 className="text-xs font-semibold uppercase tracking-wider text-emerald-400">
                                        Remediation & Recommendation
                                      </h4>
                                      <p className="mt-1 text-xs leading-relaxed text-brand-subtle">
                                        {finding.recommendation || 'No recommendation available.'}
                                      </p>
                                    </div>

                                    {/* Status & ID info */}
                                    <div className="flex items-center gap-4 text-xs text-brand-muted border-t border-brand-border/60 pt-3">
                                      <span>Finding ID: #{finding.id}</span>
                                      <span>Scan ID: #{finding.scan_id}</span>
                                      <span>Status: <strong className="text-brand-text">{finding.status}</strong></span>
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
          </div>
        )}
      </main>
    </div>
  );
}
