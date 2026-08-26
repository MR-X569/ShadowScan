import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldAlert,
  Search,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Loader2,
  RefreshCw,
  FileCode2,
} from 'lucide-react';

import { useAuth } from '@/hooks/useAuth';
import { listAllFindings } from '@/services/scans';
import type { Finding } from '@/types/scan';
import AppHeader from '@/components/layout/AppHeader';

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

export default function FindingsPage() {
  const { user, loading: authLoading } = useAuth();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const fetchFindings = async () => {
    setLoading(true);
    try {
      const data = await listAllFindings();
      setFindings(data);
    } catch {
      setFindings([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, []);

  const counts = {
    CRITICAL: findings.filter((f) => f.severity.toUpperCase() === 'CRITICAL').length,
    HIGH: findings.filter((f) => f.severity.toUpperCase() === 'HIGH').length,
    MEDIUM: findings.filter((f) => f.severity.toUpperCase() === 'MEDIUM').length,
    LOW: findings.filter((f) => f.severity.toUpperCase() === 'LOW').length,
  };

  const filtered = findings.filter((f) => {
    const title = f.vulnerability_name || f.title || '';
    const desc = f.description || '';
    const matchesSearch =
      title.toLowerCase().includes(search.toLowerCase()) ||
      desc.toLowerCase().includes(search.toLowerCase());
    const matchesSeverity =
      severityFilter === 'ALL' || f.severity.toUpperCase() === severityFilter;
    return matchesSearch && matchesSeverity;
  });

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

      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-8 sm:px-6 lg:px-8">
        {/* Page Header */}
        <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-2xl font-bold text-brand-text sm:text-3xl">
              Vulnerability <span className="text-brand-cyan">Findings</span>
            </h1>
            <p className="mt-1 text-sm text-brand-subtle">
              Consolidated security issues identified across all your scans.
            </p>
          </div>

          <button
            onClick={fetchFindings}
            className="inline-flex items-center gap-1.5 self-start rounded-lg border border-brand-border bg-brand-surface px-3 py-2 text-xs font-semibold text-brand-subtle hover:text-brand-text"
          >
            <RefreshCw size={14} />
            Refresh
          </button>
        </div>

        {/* Severity Stat Cards */}
        <div className="mb-8 grid grid-cols-2 gap-4 sm:grid-cols-4">
          <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4">
            <span className="text-xs font-medium uppercase text-red-400">Critical</span>
            <p className="mt-2 text-2xl font-bold text-red-400">{counts.CRITICAL}</p>
          </div>
          <div className="rounded-xl border border-orange-500/30 bg-orange-500/10 p-4">
            <span className="text-xs font-medium uppercase text-orange-400">High</span>
            <p className="mt-2 text-2xl font-bold text-orange-400">{counts.HIGH}</p>
          </div>
          <div className="rounded-xl border border-yellow-500/30 bg-yellow-500/10 p-4">
            <span className="text-xs font-medium uppercase text-yellow-400">Medium</span>
            <p className="mt-2 text-2xl font-bold text-yellow-400">{counts.MEDIUM}</p>
          </div>
          <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/10 p-4">
            <span className="text-xs font-medium uppercase text-cyan-400">Low</span>
            <p className="mt-2 text-2xl font-bold text-cyan-400">{counts.LOW}</p>
          </div>
        </div>

        {/* Filter Controls */}
        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative flex-1 sm:max-w-xs">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-brand-muted" />
            <input
              type="text"
              placeholder="Search findings…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full rounded-lg border border-brand-border bg-brand-surface py-2 pl-9 pr-3 text-xs text-brand-text outline-none focus:border-brand-cyan"
            />
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-brand-muted">Severity:</span>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`rounded-md px-2.5 py-1 text-xs font-semibold transition-colors ${
                  severityFilter === sev
                    ? 'bg-brand-cyan/20 text-brand-cyan ring-1 ring-brand-cyan/40'
                    : 'text-brand-subtle hover:bg-brand-surface hover:text-brand-text'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        {/* Findings List */}
        <div className="flex flex-col gap-3">
          {loading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 size={32} className="animate-spin text-brand-cyan" />
            </div>
          ) : filtered.length === 0 ? (
            <div className="rounded-2xl border border-brand-border bg-brand-surface py-16 text-center text-brand-muted">
              <ShieldAlert size={36} className="mx-auto mb-2 opacity-30" />
              <p className="text-sm font-medium">No findings found</p>
              <p className="mt-1 text-xs">Run a security scan to detect vulnerabilities.</p>
            </div>
          ) : (
            filtered.map((item) => {
              const isExpanded = expandedId === item.id;
              const title = item.vulnerability_name || item.title || 'Untitled Finding';
              return (
                <div
                  key={item.id}
                  className="rounded-xl border border-brand-border bg-brand-surface shadow-card overflow-hidden transition-colors"
                >
                  <div
                    onClick={() => setExpandedId(isExpanded ? null : item.id)}
                    className="flex cursor-pointer items-center justify-between px-6 py-4 hover:bg-brand-card/40"
                  >
                    <div className="flex items-center gap-3">
                      <span
                        className={`rounded-full border px-2.5 py-0.5 text-xs font-bold ${getSeverityBadge(
                          item.severity
                        )}`}
                      >
                        {item.severity.toUpperCase()}
                      </span>
                      <span className="font-semibold text-brand-text">{title}</span>
                      {item.plugin && (
                        <span className="hidden rounded bg-brand-border/60 px-2 py-0.5 font-mono text-[10px] text-brand-muted sm:inline-block">
                          {item.plugin}
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-4">
                      {item.scan_id && (
                        <Link
                          to={`/scans/${item.scan_id}`}
                          onClick={(e) => e.stopPropagation()}
                          className="flex items-center gap-1 text-xs font-medium text-brand-cyan hover:underline"
                        >
                          Scan #{item.scan_id}
                          <ExternalLink size={12} />
                        </Link>
                      )}
                      {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                    </div>
                  </div>

                  {/* Expanded Detail */}
                  {isExpanded && (
                    <div className="border-t border-brand-border/60 bg-brand-card/30 px-6 py-4 text-xs space-y-3">
                      {item.description && (
                        <div>
                          <span className="font-semibold uppercase tracking-wider text-brand-muted">
                            Description
                          </span>
                          <p className="mt-1 leading-relaxed text-brand-subtle">{item.description}</p>
                        </div>
                      )}

                      {item.recommendation && (
                        <div>
                          <span className="font-semibold uppercase tracking-wider text-emerald-400">
                            Remediation
                          </span>
                          <p className="mt-1 leading-relaxed text-brand-subtle">{item.recommendation}</p>
                        </div>
                      )}

                      {item.evidence && (
                        <div>
                          <span className="flex items-center gap-1 font-semibold uppercase tracking-wider text-brand-muted">
                            <FileCode2 size={13} /> Evidence
                          </span>
                          <pre className="mt-1 overflow-x-auto rounded-lg border border-brand-border/80 bg-brand-bg p-3 font-mono text-[11px] text-brand-text">
                            {item.evidence}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </main>
    </div>
  );
}
