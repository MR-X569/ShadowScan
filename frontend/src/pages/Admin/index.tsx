import { useState, useEffect, useCallback } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  Users,
  ScanLine,
  AlertTriangle,
  LayoutDashboard,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Trash2,
  UserCheck,
  UserX,
  Loader2,
  ExternalLink,
  Activity,
  ShieldAlert,
} from 'lucide-react';

import { useAuth } from '@/hooks/useAuth';
import AppHeader from '@/components/layout/AppHeader';
import StatCard from '@/components/ui/StatCard';
import StatusBadge from '@/components/ui/StatusBadge';
import type { ScanStatus } from '@/types/scan';
import {
  getAdminStats,
  getAdminUsers,
  getAdminScans,
  getAdminFindings,
  disableUser,
  enableUser,
  deleteUser,
} from '@/services/admin';
import type {
  AdminStats,
  AdminUser,
  AdminScan,
  AdminFinding,
} from '@/services/admin';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type TabKey = 'dashboard' | 'users' | 'scans' | 'findings';

const tabs: { key: TabKey; label: string; icon: typeof LayoutDashboard }[] = [
  { key: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { key: 'users', label: 'Users', icon: Users },
  { key: 'scans', label: 'Scans', icon: ScanLine },
  { key: 'findings', label: 'Findings', icon: AlertTriangle },
];

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
      return 'border-blue-500/40 bg-blue-500/10 text-blue-400';
  }
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

export default function AdminPage() {
  const { user, loading: authLoading } = useAuth();
  const navigate = useNavigate();

  const [activeTab, setActiveTab] = useState<TabKey>('dashboard');
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [scans, setScans] = useState<AdminScan[]>([]);
  const [findings, setFindings] = useState<AdminFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<number | null>(null);
  const [notice, setNotice] = useState('');

  // Guard: redirect non-admins
  useEffect(() => {
    if (!authLoading && user && user.role !== 'ADMIN') {
      navigate('/dashboard', { replace: true });
    }
  }, [authLoading, user, navigate]);

  const loadTabData = useCallback(async (tab: TabKey) => {
    setLoading(true);
    try {
      if (tab === 'dashboard') {
        setStats(await getAdminStats());
      } else if (tab === 'users') {
        setUsers(await getAdminUsers());
      } else if (tab === 'scans') {
        setScans(await getAdminScans());
      } else if (tab === 'findings') {
        setFindings(await getAdminFindings());
      }
    } catch {
      setNotice('Failed to load data.');
      setTimeout(() => setNotice(''), 4000);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!authLoading && user?.role === 'ADMIN') {
      loadTabData(activeTab);
    }
  }, [activeTab, authLoading, user, loadTabData]);

  const handleTabChange = (tab: TabKey) => {
    setActiveTab(tab);
  };

  // User actions
  const handleDisable = async (userId: number) => {
    setActionLoading(userId);
    try {
      const res = await disableUser(userId);
      setNotice(res.detail);
      await loadTabData('users');
    } catch {
      setNotice('Failed to disable user.');
    } finally {
      setActionLoading(null);
      setTimeout(() => setNotice(''), 3000);
    }
  };

  const handleEnable = async (userId: number) => {
    setActionLoading(userId);
    try {
      const res = await enableUser(userId);
      setNotice(res.detail);
      await loadTabData('users');
    } catch {
      setNotice('Failed to enable user.');
    } finally {
      setActionLoading(null);
      setTimeout(() => setNotice(''), 3000);
    }
  };

  const handleDelete = async (userId: number, username: string) => {
    if (!window.confirm(`Permanently delete user "${username}"? This cannot be undone.`)) return;
    setActionLoading(userId);
    try {
      const res = await deleteUser(userId);
      setNotice(res.detail);
      await loadTabData('users');
    } catch {
      setNotice('Failed to delete user.');
    } finally {
      setActionLoading(null);
      setTimeout(() => setNotice(''), 3000);
    }
  };

  if (authLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-brand-bg">
        <Loader2 size={32} className="animate-spin text-brand-cyan" />
      </div>
    );
  }

  if (!user || user.role !== 'ADMIN') return null;

  return (
    <div className="flex min-h-screen flex-col bg-brand-bg">
      <AppHeader user={user} />

      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-8 sm:px-6 lg:px-8">
        {/* Page Title */}
        <div className="mb-6 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-cyan/10 text-brand-cyan ring-1 ring-brand-cyan/30">
            <ShieldCheck size={22} />
          </div>
          <div>
            <h1 className="text-xl font-bold text-brand-text">Admin Dashboard</h1>
            <p className="text-xs text-brand-muted">Platform management &amp; monitoring</p>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="mb-6 flex gap-1 overflow-x-auto rounded-xl border border-brand-border bg-brand-surface p-1">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.key;
            return (
              <button
                key={tab.key}
                onClick={() => handleTabChange(tab.key)}
                className={`flex items-center gap-1.5 rounded-lg px-4 py-2.5 text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-brand-cyan/10 text-brand-cyan ring-1 ring-brand-cyan/30'
                    : 'text-brand-subtle hover:bg-brand-card hover:text-brand-text'
                }`}
              >
                <Icon size={15} />
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* Notice */}
        {notice && (
          <div className="mb-6 flex items-center justify-between rounded-lg border border-brand-cyan/30 bg-brand-cyan/10 px-4 py-3 text-sm text-brand-cyan">
            <span>{notice}</span>
            <button onClick={() => setNotice('')} className="text-xs font-semibold hover:underline">
              Dismiss
            </button>
          </div>
        )}

        {/* Loading */}
        {loading && (
          <div className="flex items-center justify-center py-24">
            <Loader2 size={28} className="animate-spin text-brand-cyan" />
          </div>
        )}

        {/* ============================================================= */}
        {/* Dashboard Tab */}
        {/* ============================================================= */}
        {!loading && activeTab === 'dashboard' && stats && (
          <div className="flex flex-col gap-8">
            {/* Stat Cards */}
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4">
              <StatCard label="Total Users" value={stats.total_users} icon={Users} accent="cyan" />
              <StatCard label="Verified Users" value={stats.verified_users} icon={CheckCircle2} accent="green" />
              <StatCard label="Total Scans" value={stats.total_scans} icon={ScanLine} accent="blue" />
              <StatCard label="Running" value={stats.scans_running} icon={Activity} accent="blue" />
              <StatCard label="Completed" value={stats.scans_completed} icon={CheckCircle2} accent="emerald" />
              <StatCard label="Failed" value={stats.scans_failed} icon={XCircle} accent="red" />
              <StatCard label="Critical Findings" value={stats.critical_findings} icon={ShieldAlert} accent="red" />
              <StatCard label="High Findings" value={stats.high_findings} icon={AlertTriangle} accent="red" />
            </div>

            {/* Latest Scans & Users side by side */}
            <div className="grid gap-6 lg:grid-cols-2">
              {/* Latest Scans */}
              <div className="rounded-2xl border border-brand-border bg-brand-surface shadow-card">
                <div className="border-b border-brand-border px-6 py-4">
                  <h2 className="text-sm font-semibold text-brand-text">Latest Scans</h2>
                </div>
                {stats.latest_scans.length === 0 ? (
                  <p className="px-6 py-8 text-center text-xs text-brand-muted">No scans yet.</p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm">
                      <thead>
                        <tr className="border-b border-brand-border bg-brand-card/50 text-xs font-medium uppercase tracking-wider text-brand-muted">
                          <th className="px-6 py-3">Target</th>
                          <th className="px-6 py-3">User</th>
                          <th className="px-6 py-3">Status</th>
                          <th className="px-6 py-3">Created</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-brand-border">
                        {stats.latest_scans.map((s) => (
                          <tr key={s.id} className="transition-colors hover:bg-brand-card/40">
                            <td className="max-w-[180px] truncate px-6 py-3 font-mono text-xs text-brand-text" title={s.target_url}>
                              {s.target_url}
                            </td>
                            <td className="px-6 py-3 text-xs text-brand-subtle">{s.username}</td>
                            <td className="px-6 py-3">
                              <StatusBadge status={s.status as ScanStatus} />
                            </td>
                            <td className="whitespace-nowrap px-6 py-3 text-xs text-brand-muted">{formatDate(s.created_at)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* Latest Users */}
              <div className="rounded-2xl border border-brand-border bg-brand-surface shadow-card">
                <div className="border-b border-brand-border px-6 py-4">
                  <h2 className="text-sm font-semibold text-brand-text">Latest Users</h2>
                </div>
                {stats.latest_users.length === 0 ? (
                  <p className="px-6 py-8 text-center text-xs text-brand-muted">No users yet.</p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm">
                      <thead>
                        <tr className="border-b border-brand-border bg-brand-card/50 text-xs font-medium uppercase tracking-wider text-brand-muted">
                          <th className="px-6 py-3">Username</th>
                          <th className="px-6 py-3">Email</th>
                          <th className="px-6 py-3">Verified</th>
                          <th className="px-6 py-3">Joined</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-brand-border">
                        {stats.latest_users.map((u) => (
                          <tr key={u.id} className="transition-colors hover:bg-brand-card/40">
                            <td className="px-6 py-3 font-medium text-brand-text">{u.username}</td>
                            <td className="px-6 py-3 text-xs text-brand-subtle">{u.email}</td>
                            <td className="px-6 py-3">
                              {u.is_verified ? (
                                <span className="inline-flex items-center gap-1 text-xs text-emerald-400"><CheckCircle2 size={13} /> Yes</span>
                              ) : (
                                <span className="inline-flex items-center gap-1 text-xs text-yellow-400"><XCircle size={13} /> No</span>
                              )}
                            </td>
                            <td className="whitespace-nowrap px-6 py-3 text-xs text-brand-muted">{formatDate(u.created_at)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ============================================================= */}
        {/* Users Tab */}
        {/* ============================================================= */}
        {!loading && activeTab === 'users' && (
          <div className="rounded-2xl border border-brand-border bg-brand-surface shadow-card">
            <div className="flex items-center justify-between border-b border-brand-border px-6 py-4">
              <div>
                <h2 className="text-base font-semibold text-brand-text">All Users</h2>
                <p className="text-xs text-brand-muted">Manage platform users</p>
              </div>
              <span className="rounded-full bg-brand-card px-3 py-1 text-xs font-mono text-brand-subtle">
                {users.length} user{users.length === 1 ? '' : 's'}
              </span>
            </div>

            {users.length === 0 ? (
              <p className="px-6 py-12 text-center text-sm text-brand-muted">No users found.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm" aria-label="Users table">
                  <thead>
                    <tr className="border-b border-brand-border bg-brand-card/50 text-xs font-medium uppercase tracking-wider text-brand-muted">
                      <th className="px-6 py-3.5">Username</th>
                      <th className="px-6 py-3.5">Email</th>
                      <th className="px-6 py-3.5">Role</th>
                      <th className="px-6 py-3.5">Verified</th>
                      <th className="px-6 py-3.5">Status</th>
                      <th className="px-6 py-3.5">Created</th>
                      <th className="px-6 py-3.5 text-center">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-brand-border">
                    {users.map((u) => (
                      <tr key={u.id} className="transition-colors hover:bg-brand-card/40">
                        <td className="px-6 py-3.5 font-medium text-brand-text">{u.username}</td>
                        <td className="px-6 py-3.5 text-xs text-brand-subtle">{u.email}</td>
                        <td className="px-6 py-3.5">
                          <span className={`inline-flex rounded-md px-2 py-0.5 text-xs font-bold ${
                            u.role === 'ADMIN'
                              ? 'bg-brand-cyan/10 text-brand-cyan border border-brand-cyan/30'
                              : 'bg-brand-card text-brand-subtle border border-brand-border'
                          }`}>
                            {u.role}
                          </span>
                        </td>
                        <td className="px-6 py-3.5">
                          {u.is_verified ? (
                            <span className="inline-flex items-center gap-1 text-xs text-emerald-400"><CheckCircle2 size={13} /> Yes</span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-xs text-yellow-400"><XCircle size={13} /> No</span>
                          )}
                        </td>
                        <td className="px-6 py-3.5">
                          {u.is_active ? (
                            <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-2.5 py-0.5 text-xs font-medium text-emerald-400 ring-1 ring-emerald-500/20">
                              <span className="h-1.5 w-1.5 rounded-full bg-current opacity-80" /> Active
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1.5 rounded-full bg-red-500/10 px-2.5 py-0.5 text-xs font-medium text-red-400 ring-1 ring-red-500/20">
                              <span className="h-1.5 w-1.5 rounded-full bg-current opacity-80" /> Disabled
                            </span>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-6 py-3.5 text-xs text-brand-muted">{formatDate(u.created_at)}</td>
                        <td className="px-6 py-3.5">
                          {u.role === 'ADMIN' ? (
                            <span className="block text-center text-xs text-brand-muted">—</span>
                          ) : (
                            <div className="flex items-center justify-center gap-1.5">
                              {u.is_active ? (
                                <button
                                  onClick={() => handleDisable(u.id)}
                                  disabled={actionLoading === u.id}
                                  className="inline-flex items-center gap-1 rounded-md border border-yellow-500/30 bg-yellow-500/10 px-2.5 py-1 text-xs font-medium text-yellow-400 transition-colors hover:bg-yellow-500/20 disabled:opacity-50"
                                  title="Disable user"
                                >
                                  {actionLoading === u.id ? <Loader2 size={12} className="animate-spin" /> : <UserX size={12} />}
                                  Disable
                                </button>
                              ) : (
                                <button
                                  onClick={() => handleEnable(u.id)}
                                  disabled={actionLoading === u.id}
                                  className="inline-flex items-center gap-1 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-xs font-medium text-emerald-400 transition-colors hover:bg-emerald-500/20 disabled:opacity-50"
                                  title="Enable user"
                                >
                                  {actionLoading === u.id ? <Loader2 size={12} className="animate-spin" /> : <UserCheck size={12} />}
                                  Enable
                                </button>
                              )}
                              <button
                                onClick={() => handleDelete(u.id, u.username)}
                                disabled={actionLoading === u.id}
                                className="inline-flex items-center gap-1 rounded-md border border-red-500/30 bg-red-500/10 px-2.5 py-1 text-xs font-medium text-red-400 transition-colors hover:bg-red-500/20 disabled:opacity-50"
                                title="Delete user"
                              >
                                {actionLoading === u.id ? <Loader2 size={12} className="animate-spin" /> : <Trash2 size={12} />}
                                Delete
                              </button>
                            </div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ============================================================= */}
        {/* Scans Tab */}
        {/* ============================================================= */}
        {!loading && activeTab === 'scans' && (
          <div className="rounded-2xl border border-brand-border bg-brand-surface shadow-card">
            <div className="flex items-center justify-between border-b border-brand-border px-6 py-4">
              <div>
                <h2 className="text-base font-semibold text-brand-text">All Scans</h2>
                <p className="text-xs text-brand-muted">Scans across all users</p>
              </div>
              <span className="rounded-full bg-brand-card px-3 py-1 text-xs font-mono text-brand-subtle">
                {scans.length} scan{scans.length === 1 ? '' : 's'}
              </span>
            </div>

            {scans.length === 0 ? (
              <p className="px-6 py-12 text-center text-sm text-brand-muted">No scans found.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm" aria-label="Scans table">
                  <thead>
                    <tr className="border-b border-brand-border bg-brand-card/50 text-xs font-medium uppercase tracking-wider text-brand-muted">
                      <th className="px-6 py-3.5">Target</th>
                      <th className="px-6 py-3.5">User</th>
                      <th className="px-6 py-3.5">Status</th>
                      <th className="px-6 py-3.5">Risk Score</th>
                      <th className="px-6 py-3.5">Created</th>
                      <th className="px-6 py-3.5 text-center">Result</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-brand-border">
                    {scans.map((s) => (
                      <tr key={s.id} className="transition-colors hover:bg-brand-card/40">
                        <td className="max-w-[220px] truncate px-6 py-3.5 font-mono text-xs text-brand-text" title={s.target_url}>
                          {s.target_url}
                        </td>
                        <td className="px-6 py-3.5 text-xs text-brand-subtle">{s.username}</td>
                        <td className="px-6 py-3.5">
                          <StatusBadge status={s.status as ScanStatus} />
                        </td>
                        <td className="px-6 py-3.5">
                          {s.risk_score !== null ? (
                            <span className={`text-sm font-bold tabular-nums ${
                              s.risk_score >= 7.0 ? 'text-red-400' : s.risk_score >= 4.0 ? 'text-yellow-400' : 'text-emerald-400'
                            }`}>
                              {s.risk_score.toFixed(1)}
                            </span>
                          ) : (
                            <span className="text-xs text-brand-muted">--</span>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-6 py-3.5 text-xs text-brand-muted">{formatDate(s.created_at)}</td>
                        <td className="px-6 py-3.5 text-center">
                          <Link
                            to={`/results/${s.id}`}
                            className="inline-flex items-center gap-1 rounded-md border border-brand-border bg-brand-card px-2.5 py-1 text-xs text-brand-subtle transition-colors hover:border-brand-cyan/40 hover:text-brand-cyan"
                          >
                            <ExternalLink size={12} />
                            Open
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ============================================================= */}
        {/* Findings Tab */}
        {/* ============================================================= */}
        {!loading && activeTab === 'findings' && (
          <div className="rounded-2xl border border-brand-border bg-brand-surface shadow-card">
            <div className="flex items-center justify-between border-b border-brand-border px-6 py-4">
              <div>
                <h2 className="text-base font-semibold text-brand-text">All Findings</h2>
                <p className="text-xs text-brand-muted">Vulnerabilities across all scans</p>
              </div>
              <span className="rounded-full bg-brand-card px-3 py-1 text-xs font-mono text-brand-subtle">
                {findings.length} finding{findings.length === 1 ? '' : 's'}
              </span>
            </div>

            {findings.length === 0 ? (
              <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
                <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-brand-cyan/10 text-brand-cyan ring-1 ring-brand-cyan/30">
                  <CheckCircle2 size={28} />
                </div>
                <h3 className="text-base font-semibold text-brand-text">No Findings</h3>
                <p className="mt-1 max-w-sm text-xs text-brand-muted">
                  No vulnerability findings exist yet.
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm" aria-label="Findings table">
                  <thead>
                    <tr className="border-b border-brand-border bg-brand-card/50 text-xs font-medium uppercase tracking-wider text-brand-muted">
                      <th className="px-6 py-3.5">Severity</th>
                      <th className="px-6 py-3.5">Plugin</th>
                      <th className="px-6 py-3.5">Vulnerability</th>
                      <th className="px-6 py-3.5">Target</th>
                      <th className="px-6 py-3.5">Description</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-brand-border">
                    {findings.map((f) => (
                      <tr key={f.id} className="transition-colors hover:bg-brand-card/40">
                        <td className="whitespace-nowrap px-6 py-3.5">
                          <span className={`inline-flex items-center gap-1 rounded-md border px-2.5 py-0.5 text-xs font-bold ${getSeverityBadge(f.severity)}`}>
                            {f.severity.toUpperCase()}
                          </span>
                        </td>
                        <td className="px-6 py-3.5 text-xs text-brand-muted">{f.plugin || '--'}</td>
                        <td className="max-w-[180px] truncate px-6 py-3.5 font-medium text-brand-text" title={f.vulnerability_name}>
                          {f.vulnerability_name}
                        </td>
                        <td className="max-w-[160px] truncate px-6 py-3.5 font-mono text-xs text-brand-subtle" title={f.target_url}>
                          {f.target_url}
                        </td>
                        <td className="max-w-[240px] truncate px-6 py-3.5 text-xs text-brand-muted" title={f.description || '--'}>
                          {f.description || '--'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
