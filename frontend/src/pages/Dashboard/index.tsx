import { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  ScanLine,
  Activity,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Loader2,
  Plus,
} from 'lucide-react';
import axios from 'axios';

import { useAuth } from '@/hooks/useAuth';
import { useScans } from '@/hooks/useScans';
import { createScan, listAllFindings } from '@/services/scans';
import type { Finding } from '@/types/scan';
import StatCard from '@/components/ui/StatCard';
import StatusBadge from '@/components/ui/StatusBadge';
import SkeletonRow from '@/components/ui/SkeletonRow';
import AppHeader from '@/components/layout/AppHeader';

function isValidUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

function getSeverityBadge(severity: string) {
  const sev = severity.toUpperCase();
  switch (sev) {
    case 'CRITICAL':
      return 'border-red-500/40 bg-red-500/10 text-red-400';
    case 'HIGH':
      return 'border-orange-500/40 bg-orange-500/10 text-orange-400';
    case 'MEDIUM':
      return 'border-yellow-500/40 bg-yellow-500/10 text-yellow-400';
    case 'LOW':
    default:
      return 'border-cyan-500/40 bg-cyan-500/10 text-cyan-400';
  }
}

import { getToken } from '@/services/auth';
import { useLocation } from 'react-router-dom';

export default function DashboardPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const locationState = location.state as { targetUrl?: string } | null;

  const { user, loading: authLoading } = useAuth(false);
  const { scans, stats, loading: scansLoading, refresh } = useScans();

  const [targetUrl, setTargetUrl] = useState(locationState?.targetUrl || '');

  const [urlError, setUrlError] = useState('');
  const [scanLoading, setScanLoading] = useState(false);
  const [scanError, setScanError] = useState('');
  const [scanSuccess, setScanSuccess] = useState('');
  const [latestFindings, setLatestFindings] = useState<Finding[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(true);

  // Poll for scan updates when any scan is in PENDING or RUNNING status
  useEffect(() => {
    if (!getToken()) return;
    const hasActiveScans = scans.some(
      (s) => s.status === 'PENDING' || s.status === 'RUNNING'
    );
    if (!hasActiveScans) return;

    const interval = setInterval(() => {
      refresh();
      fetchFindings();
    }, 3000);

    return () => clearInterval(interval);
  }, [scans, refresh]);

  const fetchFindings = async () => {
    if (!getToken()) {
      setLatestFindings([]);
      setFindingsLoading(false);
      return;
    }
    try {
      const data = await listAllFindings();
      setLatestFindings(data.slice(0, 5));
    } catch {
      setLatestFindings([]);
    } finally {
      setFindingsLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [user]);

  const handleUrlChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setTargetUrl(e.target.value);
    if (urlError) setUrlError('');
    if (scanError) setScanError('');
  };

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();

    const trimmed = targetUrl.trim();
    if (!trimmed) {
      setUrlError('Target URL is required.');
      return;
    }
    if (!isValidUrl(trimmed)) {
      setUrlError('Enter a valid HTTP or HTTPS URL (e.g. https://example.com).');
      return;
    }

    // Enforce authentication at scan start
    const token = getToken();
    if (!token || !user) {
      navigate('/login', {
        state: {
          redirect: '/dashboard',
          targetUrl: trimmed,
        },
      });
      return;
    }

    setScanLoading(true);
    setScanError('');
    setScanSuccess('');

    try {
      await createScan({ target_url: trimmed });
      setScanSuccess('Scan started successfully! Polling for progress…');
      setTargetUrl('');
      refresh();
      fetchFindings();
    } catch (err: unknown) {
      if (axios.isAxiosError(err)) {
        if (err.response?.status === 401) {
          navigate('/login', {
            state: { redirect: '/dashboard', targetUrl: trimmed },
          });
          return;
        }
        const detail = err.response?.data?.detail;
        if (typeof detail === 'string') {
          setScanError(detail);
        } else {
          setScanError('Failed to create scan. Please try again.');
        }
      } else {
        setScanError('An unexpected error occurred.');
      }
    } finally {
      setScanLoading(false);
    }
  };

  if (authLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-brand-bg">
        <Loader2 size={32} className="animate-spin text-brand-cyan" />
      </div>
    );
  }

  const displayName = user?.full_name || user?.username || 'User';

  return (
    <div className="flex min-h-screen flex-col bg-brand-bg">
      <AppHeader user={user} />

      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-8 sm:px-6 lg:px-8">
        {/* Welcome Section */}
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-brand-text sm:text-3xl">
            {user ? (
              <>
                Welcome back, <span className="text-brand-cyan">{displayName}</span>
              </>
            ) : (
              <>
                Welcome to <span className="text-brand-cyan">ShadowScan</span>
              </>
            )}
          </h1>
          <p className="mt-1 text-sm text-brand-subtle">
            {user
              ? 'Overview of your vulnerability scan activity and security posture.'
              : 'Enterprise-grade vulnerability scanner and automated AI security assessment.'}
          </p>
        </div>


        {/* Stats Grid */}
        <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <StatCard
            label="Total Scans"
            value={stats.total}
            icon={ScanLine}
            description="All submitted scan targets"
          />
          <StatCard
            label="Completed"
            value={stats.completed}
            icon={CheckCircle2}
            color="emerald"
            description="Successfully finished scans"
          />
          <StatCard
            label="Active / Queued"
            value={stats.running + (stats.pending || 0)}
            icon={Activity}
            color="cyan"
            description="Currently in progress"
          />

          <StatCard
            label="Failed"
            value={stats.failed}
            icon={XCircle}
            color="red"
            description="Scans that encountered an error"
          />
        </div>

        {/* Scan Input Section */}
        <div className="mb-8 rounded-2xl border border-brand-border bg-brand-surface p-6 shadow-card">
          <div className="mb-4">
            <h2 className="text-base font-semibold text-brand-text">Start a Vulnerability Scan</h2>
            <p className="mt-0.5 text-xs text-brand-muted">
              Enter any HTTP or HTTPS URL to launch passive security checks.
            </p>
          </div>

          <form onSubmit={handleStartScan} className="flex flex-col gap-3 sm:flex-row">
            <div className="flex-1">
              <input
                id="target-url-input"
                type="url"
                placeholder="https://example.com"
                value={targetUrl}
                onChange={handleUrlChange}
                disabled={scanLoading}
                className="w-full rounded-lg border border-brand-border bg-brand-card px-4 py-2.5 text-sm text-brand-text placeholder-brand-muted outline-none transition-colors focus:border-brand-cyan focus:ring-1 focus:ring-brand-cyan disabled:opacity-50"
              />
              {urlError && <p className="mt-1.5 text-xs text-red-400">{urlError}</p>}
            </div>

            <button
              id="start-scan-btn"
              type="submit"
              disabled={scanLoading}
              className="inline-flex items-center justify-center gap-2 rounded-lg bg-brand-cyan px-6 py-2.5 text-sm font-semibold text-brand-bg shadow-btn-cyan transition-all duration-200 hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {scanLoading ? (
                <>
                  <Loader2 size={16} className="animate-spin" />
                  <span>Starting…</span>
                </>
              ) : (
                <>
                  <Plus size={16} />
                  <span>Start Scan</span>
                </>
              )}
            </button>
          </form>

          {scanSuccess && (
            <p className="mt-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs font-medium text-emerald-400">
              {scanSuccess}
            </p>
          )}
          {scanError && (
            <p className="mt-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs font-medium text-red-400">
              {scanError}
            </p>
          )}
        </div>

        {/* Recent Scans Table */}
        <div className="mb-8 rounded-2xl border border-brand-border bg-brand-surface shadow-card overflow-hidden">
          <div className="flex items-center justify-between border-b border-brand-border px-6 py-4">
            <div>
              <h2 className="text-base font-semibold text-brand-text">Recent Scans</h2>
              <p className="mt-0.5 text-xs text-brand-muted">Latest targets scanned by your account</p>
            </div>
            <Link to="/scans" className="text-xs font-semibold text-brand-cyan hover:underline">
              View All Scans →
            </Link>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-brand-border bg-brand-card/60 text-xs uppercase tracking-wider text-brand-muted">
                <tr>
                  <th className="px-6 py-3.5">Target</th>
                  <th className="px-6 py-3.5">Status</th>
                  <th className="px-6 py-3.5">Risk Score</th>
                  <th className="px-6 py-3.5">Date</th>
                  <th className="px-6 py-3.5 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-brand-border/60">
                {scansLoading ? (
                  Array.from({ length: 3 }).map((_, i) => <SkeletonRow key={i} />)
                ) : scans.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-12 text-center text-sm text-brand-muted">
                      No scans yet. Enter a URL above to launch your first scan.
                    </td>
                  </tr>
                ) : (
                  scans.slice(0, 5).map((scan) => (
                    <tr key={scan.id} className="transition-colors hover:bg-brand-card/40">
                      <td className="px-6 py-4">
                        <span className="font-mono font-medium text-brand-text break-all">
                          {scan.target_url}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <StatusBadge status={scan.status} />
                      </td>
                      <td className="px-6 py-4">
                        {scan.risk_score !== null ? (
                          <span
                            className={`font-semibold tabular-nums ${
                              scan.risk_score >= 7
                                ? 'text-red-400'
                                : scan.risk_score >= 4
                                ? 'text-yellow-400'
                                : 'text-emerald-400'
                            }`}
                          >
                            {scan.risk_score.toFixed(1)}
                          </span>
                        ) : (
                          <span className="text-xs text-brand-muted">—</span>
                        )}
                      </td>
                      <td className="px-6 py-4 text-xs text-brand-subtle whitespace-nowrap">
                        {formatDate(scan.created_at)}
                      </td>
                      <td className="px-6 py-4 text-right">
                        <button
                          onClick={() => navigate(`/scans/${scan.id}`)}
                          className="inline-flex items-center gap-1 text-xs font-semibold text-brand-cyan hover:text-cyan-300"
                        >
                          <ExternalLink size={12} />
                          View
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Latest Findings Section */}
        <div className="rounded-2xl border border-brand-border bg-brand-surface shadow-card overflow-hidden">
          <div className="flex items-center justify-between border-b border-brand-border px-6 py-4">
            <div>
              <h2 className="text-base font-semibold text-brand-text">Latest Findings</h2>
              <p className="mt-0.5 text-xs text-brand-muted">
                Aggregated vulnerabilities identified from your latest scans
              </p>
            </div>
            <Link to="/findings" className="text-xs font-semibold text-brand-cyan hover:underline">
              View All Findings →
            </Link>
          </div>

          <div className="divide-y divide-brand-border/60">
            {findingsLoading ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 size={24} className="animate-spin text-brand-cyan" />
              </div>
            ) : latestFindings.length === 0 ? (
              <div className="px-6 py-12 text-center text-sm text-brand-muted">
                No vulnerabilities detected yet. Run a scan on a web target to see findings.
              </div>
            ) : (
              latestFindings.map((f) => (
                <div
                  key={f.id}
                  className="flex items-center justify-between px-6 py-4 hover:bg-brand-card/30"
                >
                  <div className="flex items-center gap-3">
                    <span
                      className={`rounded-full border px-2.5 py-0.5 text-xs font-bold ${getSeverityBadge(
                        f.severity
                      )}`}
                    >
                      {f.severity.toUpperCase()}
                    </span>
                    <div>
                      <p className="font-semibold text-brand-text">
                        {f.vulnerability_name || f.title}
                      </p>
                      {f.description && (
                        <p className="text-xs text-brand-subtle line-clamp-1">{f.description}</p>
                      )}
                    </div>
                  </div>

                  {f.scan_id && (
                    <Link
                      to={`/scans/${f.scan_id}`}
                      className="flex items-center gap-1 text-xs font-medium text-brand-cyan hover:underline"
                    >
                      Scan #{f.scan_id}
                      <ExternalLink size={12} />
                    </Link>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
