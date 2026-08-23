import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  ScanLine,
  Activity,
  CheckCircle2,
  XCircle,
  LayoutDashboard,
  User as UserIcon,
  Settings as SettingsIcon,
  LogOut,
  Shield,
  AlertTriangle,
  ExternalLink,
  Loader2,
} from 'lucide-react';
import axios from 'axios';

import { useAuth } from '@/hooks/useAuth';
import { useScans } from '@/hooks/useScans';
import { createScan } from '@/services/scans';
import { logout } from '@/services/auth';
import StatCard from '@/components/ui/StatCard';
import StatusBadge from '@/components/ui/StatusBadge';
import SkeletonRow from '@/components/ui/SkeletonRow';

// ---------------------------------------------------------------------------
// URL validation helper
// ---------------------------------------------------------------------------

function isValidUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Date formatter
// ---------------------------------------------------------------------------

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

// ---------------------------------------------------------------------------
// Dashboard Page
// ---------------------------------------------------------------------------

export default function DashboardPage() {
  const navigate = useNavigate();
  const { user, loading: authLoading } = useAuth();
  const { scans, stats, loading: scansLoading, error: scansError, refresh } = useScans();

  const [targetUrl, setTargetUrl] = useState('');
  const [urlError, setUrlError] = useState('');
  const [scanLoading, setScanLoading] = useState(false);
  const [scanError, setScanError] = useState('');
  const [scanSuccess, setScanSuccess] = useState('');

  // ------------------------------------------------------------------
  // Handlers
  // ------------------------------------------------------------------

  const handleUrlChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setTargetUrl(e.target.value);
    if (urlError) setUrlError('');
    if (scanError) setScanError('');
    if (scanSuccess) setScanSuccess('');
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

    setScanLoading(true);
    setScanError('');
    setScanSuccess('');

    try {
      await createScan({ target_url: trimmed });
      setScanSuccess('Scan created successfully. Refreshing scan list…');
      setTargetUrl('');
      refresh();
    } catch (err: unknown) {
      if (axios.isAxiosError(err)) {
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

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  // ------------------------------------------------------------------
  // Auth loading guard
  // ------------------------------------------------------------------

  if (authLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-brand-bg">
        <Loader2 size={32} className="animate-spin text-brand-cyan" />
      </div>
    );
  }

  // ------------------------------------------------------------------
  // Render
  // ------------------------------------------------------------------

  const displayName = user?.full_name || user?.username || 'User';

  return (
    <div className="flex min-h-screen flex-col bg-brand-bg">
      {/* ----------------------------------------------------------------
          Top Navbar — Dashboard variant (no landing nav links)
      ---------------------------------------------------------------- */}
      <header className="sticky top-0 z-50 border-b border-brand-border bg-brand-bg/90 backdrop-blur-sm">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-4 sm:px-6 lg:px-8">
          {/* Logo */}
          <Link
            to="/dashboard"
            className="flex items-center gap-2.5 text-xl font-bold text-brand-text"
            aria-label="ShadowScan dashboard"
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
              className="flex items-center gap-1.5 rounded-lg bg-brand-cyan/10 px-3 py-2 text-sm font-medium text-brand-cyan ring-1 ring-brand-cyan/30"
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
              {user?.email}
            </span>
            <button
              id="dashboard-logout-btn"
              onClick={handleLogout}
              className="flex items-center gap-1.5 rounded-lg border border-brand-border px-3 py-2 text-sm font-medium text-brand-subtle transition-all duration-200 hover:border-red-500/30 hover:text-red-400"
            >
              <LogOut size={14} />
              Logout
            </button>
          </div>
        </div>
      </header>

      {/* ----------------------------------------------------------------
          Main Content
      ---------------------------------------------------------------- */}
      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-8 sm:px-6 lg:px-8">

        {/* ---- Welcome Section ---- */}
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-brand-text sm:text-3xl">
            Welcome, <span className="text-brand-cyan">{displayName}</span>
          </h1>
          <p className="mt-1 text-sm text-brand-subtle">
            Manage your security scans and view vulnerability reports.
          </p>
        </div>

        {/* ---- Scan Card ---- */}
        <div className="mb-8 rounded-xl border border-brand-border bg-brand-surface p-6 shadow-card">
          <h2 className="mb-4 text-base font-semibold text-brand-text">New Scan</h2>

          <form id="scan-form" onSubmit={handleStartScan} noValidate>
            <div className="flex flex-col gap-3 sm:flex-row">
              <div className="flex-1">
                <input
                  id="scan-target-url"
                  type="url"
                  value={targetUrl}
                  onChange={handleUrlChange}
                  placeholder="https://example.com"
                  disabled={scanLoading}
                  autoComplete="off"
                  className={[
                    'w-full rounded-lg border bg-brand-card px-3.5 py-2.5 text-sm text-brand-text placeholder:text-brand-muted outline-none transition-all duration-200',
                    'focus:border-brand-cyan focus:ring-1 focus:ring-brand-cyan/30',
                    urlError
                      ? 'border-red-500/60 focus:border-red-500 focus:ring-red-500/20'
                      : 'border-brand-border hover:border-brand-cyan/30',
                  ].join(' ')}
                />
                {urlError && (
                  <p className="mt-1.5 text-xs text-red-400" role="alert">
                    {urlError}
                  </p>
                )}
              </div>
              <button
                id="scan-start-btn"
                type="submit"
                disabled={scanLoading}
                className="flex shrink-0 items-center justify-center gap-2 rounded-lg bg-brand-cyan px-5 py-2.5 text-sm font-semibold text-brand-bg shadow-btn-cyan transition-all duration-200 hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {scanLoading ? (
                  <>
                    <Loader2 size={15} className="animate-spin" />
                    Starting…
                  </>
                ) : (
                  <>
                    <ScanLine size={15} />
                    Start Scan
                  </>
                )}
              </button>
            </div>
          </form>

          {/* Scan feedback messages */}
          {scanSuccess && (
            <p className="mt-3 flex items-center gap-1.5 text-xs text-emerald-400">
              <CheckCircle2 size={13} />
              {scanSuccess}
            </p>
          )}
          {scanError && (
            <p className="mt-3 flex items-center gap-1.5 text-xs text-red-400" role="alert">
              <AlertTriangle size={13} />
              {scanError}
            </p>
          )}
        </div>

        {/* ---- Statistics ---- */}
        <div className="mb-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard
            label="Total Scans"
            value={stats.total}
            icon={<ScanLine size={20} />}
            accent="cyan"
          />
          <StatCard
            label="Running"
            value={stats.running}
            icon={<Activity size={20} />}
            accent="blue"
          />
          <StatCard
            label="Completed"
            value={stats.completed}
            icon={<CheckCircle2 size={20} />}
            accent="green"
          />
          <StatCard
            label="Failed"
            value={stats.failed}
            icon={<XCircle size={20} />}
            accent="red"
          />
        </div>

        {/* ---- Recent Scans Table ---- */}
        <div className="mb-8 rounded-xl border border-brand-border bg-brand-surface shadow-card">
          <div className="flex items-center justify-between border-b border-brand-border px-6 py-4">
            <h2 className="text-base font-semibold text-brand-text">Recent Scans</h2>
            {scansLoading && (
              <Loader2 size={15} className="animate-spin text-brand-muted" />
            )}
          </div>

          {/* Backend error */}
          {scansError && !scansLoading && (
            <div className="flex items-center gap-2 px-6 py-4 text-sm text-red-400">
              <AlertTriangle size={15} />
              {scansError}
            </div>
          )}

          <div className="overflow-x-auto">
            <table className="w-full text-sm" aria-label="Recent scans">
              <thead>
                <tr className="border-b border-brand-border text-left">
                  <th className="px-4 py-3 text-xs font-medium uppercase tracking-wide text-brand-muted">
                    Target URL
                  </th>
                  <th className="px-4 py-3 text-xs font-medium uppercase tracking-wide text-brand-muted">
                    Status
                  </th>
                  <th className="px-4 py-3 text-xs font-medium uppercase tracking-wide text-brand-muted">
                    Created At
                  </th>
                  <th className="px-4 py-3 text-xs font-medium uppercase tracking-wide text-brand-muted">
                    Risk Score
                  </th>
                  <th className="px-4 py-3 text-xs font-medium uppercase tracking-wide text-brand-muted">
                    Action
                  </th>
                </tr>
              </thead>
              <tbody>
                {scansLoading
                  ? Array.from({ length: 4 }).map((_, i) => (
                      <SkeletonRow key={i} cols={5} />
                    ))
                  : scans.length === 0
                  ? (
                      <tr>
                        <td
                          colSpan={5}
                          className="px-6 py-12 text-center text-sm text-brand-muted"
                        >
                          No scans available yet.
                        </td>
                      </tr>
                    )
                  : scans.map((scan) => (
                      <tr
                        key={scan.id}
                        className="border-b border-brand-border transition-colors duration-150 last:border-0 hover:bg-brand-card/50"
                      >
                        {/* Target URL */}
                        <td className="max-w-[240px] px-4 py-3">
                          <span
                            className="block truncate font-mono text-xs text-brand-text"
                            title={scan.target_url}
                          >
                            {scan.target_url}
                          </span>
                        </td>

                        {/* Status */}
                        <td className="px-4 py-3">
                          <StatusBadge status={scan.status} />
                        </td>

                        {/* Created At */}
                        <td className="whitespace-nowrap px-4 py-3 text-xs text-brand-subtle">
                          {formatDate(scan.created_at)}
                        </td>

                        {/* Risk Score */}
                        <td className="px-4 py-3">
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

                        {/* Action */}
                        <td className="px-4 py-3">
                          {/* TODO: Navigate to full scan result/report page when built */}
                          <button
                            id={`scan-view-btn-${scan.id}`}
                            type="button"
                            onClick={() => navigate(`/scans/${scan.id}`)}
                            className="flex items-center gap-1 text-xs font-medium text-brand-cyan transition-colors hover:text-cyan-300"
                          >
                            <ExternalLink size={12} />
                            View
                          </button>
                        </td>
                      </tr>
                    ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* ---- Latest Findings Section ---- */}
        <div className="rounded-xl border border-brand-border bg-brand-surface shadow-card">
          <div className="border-b border-brand-border px-6 py-4">
            <h2 className="text-base font-semibold text-brand-text">Latest Findings</h2>
            <p className="mt-0.5 text-xs text-brand-muted">
              Aggregated findings from your most recent scans.
            </p>
          </div>

          <div className="px-6 py-12 text-center">
            {/*
             * TODO: Report Integration
             * When the findings/report endpoints are available, replace this placeholder with:
             *   - A list of FindingResponse items fetched from GET /scans/{id}/findings
             *   - Group by severity (CRITICAL, HIGH, MEDIUM, LOW)
             *   - Link each finding to its scan detail page
             */}
            <p className="text-sm text-brand-muted">No findings available.</p>
            <p className="mt-1 text-xs text-brand-muted">
              Complete a scan to see vulnerability findings here.
            </p>
          </div>
        </div>
      </main>
    </div>
  );
}
