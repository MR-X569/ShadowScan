import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ScanLine,
  Search,
  ExternalLink,
  Trash2,
  Plus,
  Loader2,
  RefreshCw,
} from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { useScans } from '@/hooks/useScans';
import { createScan, deleteScan } from '@/services/scans';
import AppHeader from '@/components/layout/AppHeader';
import StatusBadge from '@/components/ui/StatusBadge';
import SkeletonRow from '@/components/ui/SkeletonRow';

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

export default function ScansPage() {
  const navigate = useNavigate();
  const { user, loading: authLoading } = useAuth();
  const { scans, loading, refresh } = useScans();

  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [newUrl, setNewUrl] = useState('');
  const [creating, setCreating] = useState(false);
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [error, setError] = useState('');

  const handleCreateScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUrl.trim()) return;
    setCreating(true);
    setError('');
    try {
      await createScan({ target_url: newUrl.trim() });
      setNewUrl('');
      refresh();
    } catch {
      setError('Failed to create scan. Please check the URL.');
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm('Are you sure you want to delete this scan and all its findings?')) return;
    setDeletingId(id);
    try {
      await deleteScan(id);
      refresh();
    } catch {
      setError('Failed to delete scan.');
    } finally {
      setDeletingId(null);
    }
  };

  const filteredScans = scans.filter((s) => {
    const matchesSearch = s.target_url.toLowerCase().includes(search.toLowerCase());
    const matchesStatus = statusFilter === 'ALL' || s.status === statusFilter;
    return matchesSearch && matchesStatus;
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
              Security <span className="text-brand-cyan">Scans</span>
            </h1>
            <p className="mt-1 text-sm text-brand-subtle">
              Manage, monitor, and review all your target scans.
            </p>
          </div>

          <button
            onClick={() => refresh()}
            className="inline-flex items-center gap-1.5 self-start rounded-lg border border-brand-border bg-brand-surface px-3 py-2 text-xs font-semibold text-brand-subtle hover:text-brand-text"
          >
            <RefreshCw size={14} />
            Refresh
          </button>
        </div>

        {/* Quick New Scan Card */}
        <div className="mb-8 rounded-2xl border border-brand-border bg-brand-surface p-6 shadow-card">
          <h2 className="text-base font-semibold text-brand-text">Run a New Scan</h2>
          <form onSubmit={handleCreateScan} className="mt-4 flex flex-col gap-3 sm:flex-row">
            <input
              type="url"
              placeholder="https://example.com"
              value={newUrl}
              onChange={(e) => setNewUrl(e.target.value)}
              className="flex-1 rounded-lg border border-brand-border bg-brand-card px-4 py-2.5 text-sm text-brand-text placeholder-brand-muted outline-none focus:border-brand-cyan"
              required
            />
            <button
              type="submit"
              disabled={creating}
              className="inline-flex items-center justify-center gap-2 rounded-lg bg-brand-cyan px-5 py-2.5 text-sm font-semibold text-brand-bg transition-colors hover:bg-cyan-300 disabled:opacity-50"
            >
              {creating ? <Loader2 size={16} className="animate-spin" /> : <Plus size={16} />}
              Start Scan
            </button>
          </form>
          {error && <p className="mt-2 text-xs text-red-400">{error}</p>}
        </div>

        {/* Filter Controls */}
        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative flex-1 sm:max-w-xs">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-brand-muted" />
            <input
              type="text"
              placeholder="Search target URL…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full rounded-lg border border-brand-border bg-brand-surface py-2 pl-9 pr-3 text-xs text-brand-text outline-none focus:border-brand-cyan"
            />
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-brand-muted">Status:</span>
            {['ALL', 'COMPLETED', 'RUNNING', 'PENDING', 'FAILED'].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`rounded-md px-2.5 py-1 text-xs font-semibold transition-colors ${
                  statusFilter === st
                    ? 'bg-brand-cyan/20 text-brand-cyan ring-1 ring-brand-cyan/40'
                    : 'text-brand-subtle hover:bg-brand-surface hover:text-brand-text'
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        </div>

        {/* Scans Table */}
        <div className="rounded-2xl border border-brand-border bg-brand-surface shadow-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-brand-border bg-brand-card/60 text-xs uppercase tracking-wider text-brand-muted">
                <tr>
                  <th className="px-6 py-3.5">Target</th>
                  <th className="px-6 py-3.5">Status</th>
                  <th className="px-6 py-3.5">Risk Score</th>
                  <th className="px-6 py-3.5">Date</th>
                  <th className="px-6 py-3.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-brand-border/60">
                {loading ? (
                  Array.from({ length: 4 }).map((_, i) => (
                    <SkeletonRow key={i} />
                  ))
                ) : filteredScans.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-12 text-center text-sm text-brand-muted">
                      <ScanLine size={32} className="mx-auto mb-2 opacity-30" />
                      No scans found matching your filter.
                    </td>
                  </tr>
                ) : (
                  filteredScans.map((scan) => (
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
                        <div className="flex items-center justify-end gap-3">
                          <button
                            onClick={() => navigate(`/scans/${scan.id}`)}
                            className="inline-flex items-center gap-1 text-xs font-semibold text-brand-cyan hover:text-cyan-300"
                          >
                            <ExternalLink size={13} />
                            View
                          </button>
                          <button
                            disabled={deletingId === scan.id}
                            onClick={() => handleDelete(scan.id)}
                            className="inline-flex items-center gap-1 text-xs text-brand-muted hover:text-red-400"
                            title="Delete scan"
                          >
                            {deletingId === scan.id ? (
                              <Loader2 size={13} className="animate-spin" />
                            ) : (
                              <Trash2 size={13} />
                            )}
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </main>
    </div>
  );
}
