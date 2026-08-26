import { useNavigate } from 'react-router-dom';
import {
  User as UserIcon,
  Mail,
  ShieldCheck,
  ShieldAlert,
  Calendar,
  KeyRound,
  LogOut,
  Loader2,
  CheckCircle2,
  XCircle,
  Sparkles,
} from 'lucide-react';

import { useAuth } from '@/hooks/useAuth';
import { logout } from '@/services/auth';

import AppHeader from '@/components/layout/AppHeader';

function formatDate(iso?: string | null): string {
  if (!iso) return '--';

  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return '--';
    return d.toLocaleDateString(undefined, {
      month: 'long',
      day: 'numeric',
      year: 'numeric',
    });
  } catch {
    return '--';
  }
}

export default function ProfilePage() {
  const navigate = useNavigate();
  const { user, loading } = useAuth();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-brand-bg">
        <Loader2 size={32} className="animate-spin text-brand-cyan" />
      </div>
    );
  }

  const initial = user?.full_name?.trim()
    ? user.full_name.trim().charAt(0).toUpperCase()
    : user?.username?.charAt(0).toUpperCase() || 'U';

  const roleText = user?.role ? user.role.toUpperCase() : '--';
  const isActive = user?.is_active ?? null;
  const isVerified = user?.is_verified ?? null;
  const memberSince = user?.created_at ? formatDate(user.created_at) : '--';

  return (
    <div className="flex min-h-screen flex-col bg-brand-bg">
      <AppHeader user={user} />

      {/* Main Content */}
      <main className="mx-auto w-full max-w-5xl flex-1 px-4 py-8 sm:px-6 lg:px-8">

        {/* Breadcrumb / Section Header */}
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-brand-text sm:text-3xl">
            User <span className="text-brand-cyan">Profile</span>
          </h1>
          <p className="mt-1 text-sm text-brand-subtle">
            Manage and view your account information and authentication credentials.
          </p>
        </div>

        {/* Profile Card Container */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          {/* Left Column: Avatar & Quick Summary */}
          <div className="flex flex-col items-center rounded-2xl border border-brand-border bg-brand-surface p-6 text-center shadow-card lg:p-8">
            {/* Cyber Avatar */}
            <div className="relative mb-4">
              <div className="flex h-24 w-24 items-center justify-center rounded-2xl bg-gradient-to-tr from-brand-cyan/20 to-brand-blue/20 text-3xl font-extrabold text-brand-cyan ring-2 ring-brand-cyan/40 shadow-btn-cyan">
                {initial}
              </div>
              {isActive && (
                <div
                  className="absolute -bottom-1 -right-1 flex h-6 w-6 items-center justify-center rounded-full bg-emerald-500 text-brand-bg ring-4 ring-brand-surface"
                  title="Account active"
                >
                  <CheckCircle2 size={14} strokeWidth={3} />
                </div>
              )}
            </div>

            <h2 className="text-lg font-bold text-brand-text">
              {user?.full_name || user?.username || '--'}
            </h2>
            <p className="text-xs font-mono text-brand-subtle">{user?.email || '--'}</p>

            <div className="mt-3 inline-flex items-center gap-1.5 rounded-full border border-brand-cyan/30 bg-brand-cyan/10 px-3 py-1 text-xs font-semibold text-brand-cyan">
              <ShieldCheck size={13} />
              {roleText}
            </div>

            {/* Action Buttons */}
            <div className="mt-8 flex w-full flex-col gap-3">
              <button
                id="edit-profile-btn"
                type="button"
                disabled
                className="group relative flex w-full items-center justify-center gap-2 rounded-lg border border-brand-border bg-brand-card/70 px-4 py-2.5 text-sm font-medium text-brand-muted cursor-not-allowed opacity-75"
              >
                <UserIcon size={15} />
                Edit Profile
                <span className="ml-1.5 rounded-md bg-brand-border/80 px-2 py-0.5 text-[10px] font-semibold text-brand-subtle">
                  Coming Soon
                </span>
              </button>

              <button
                id="profile-card-logout-btn"
                type="button"
                onClick={handleLogout}
                className="flex w-full items-center justify-center gap-2 rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-2.5 text-sm font-semibold text-red-400 transition-all duration-200 hover:bg-red-500/20 hover:border-red-500/40"
              >
                <LogOut size={15} />
                Logout
              </button>
            </div>
          </div>

          {/* Right Column: Detailed Information */}
          <div className="rounded-2xl border border-brand-border bg-brand-surface p-6 shadow-card lg:col-span-2 lg:p-8">
            <div className="flex items-center justify-between border-b border-brand-border pb-4">
              <div>
                <h2 className="text-base font-semibold text-brand-text">Account Details</h2>
                <p className="text-xs text-brand-muted">
                  Personal identity and access privileges
                </p>
              </div>
              <div className="flex items-center gap-1.5 text-xs text-brand-muted">
                <Sparkles size={14} className="text-brand-cyan" />
                <span>ShadowScan Secure ID: #{user?.id ?? '--'}</span>
              </div>
            </div>

            <div className="mt-6 grid grid-cols-1 gap-6 sm:grid-cols-2">
              {/* Full Name */}
              <div className="flex flex-col gap-1 rounded-xl border border-brand-border/60 bg-brand-card/40 p-4">
                <span className="text-xs font-medium uppercase tracking-wider text-brand-muted">
                  Full Name
                </span>
                <span className="text-sm font-semibold text-brand-text">
                  {user?.full_name || '--'}
                </span>
              </div>

              {/* Username */}
              <div className="flex flex-col gap-1 rounded-xl border border-brand-border/60 bg-brand-card/40 p-4">
                <span className="text-xs font-medium uppercase tracking-wider text-brand-muted">
                  Username
                </span>
                <span className="font-mono text-sm font-semibold text-brand-text">
                  @{user?.username || '--'}
                </span>
              </div>

              {/* Email Address */}
              <div className="flex flex-col gap-1 rounded-xl border border-brand-border/60 bg-brand-card/40 p-4 sm:col-span-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium uppercase tracking-wider text-brand-muted">
                    Email Address
                  </span>
                  {isVerified !== null ? (
                    isVerified ? (
                      <span className="inline-flex items-center gap-1 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[11px] font-semibold text-emerald-400">
                        <ShieldCheck size={12} />
                        Verified
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 rounded-md border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[11px] font-semibold text-amber-400">
                        <ShieldAlert size={12} />
                        Unverified
                      </span>
                    )
                  ) : (
                    <span className="text-xs text-brand-muted">--</span>
                  )}
                </div>
                <div className="mt-1 flex items-center gap-2">
                  <Mail size={16} className="text-brand-muted" />
                  <span className="text-sm font-medium text-brand-text">
                    {user?.email || '--'}
                  </span>
                </div>
              </div>

              {/* Role */}
              <div className="flex flex-col gap-1 rounded-xl border border-brand-border/60 bg-brand-card/40 p-4">
                <span className="text-xs font-medium uppercase tracking-wider text-brand-muted">
                  System Role
                </span>
                <div className="mt-0.5 flex items-center gap-2">
                  <KeyRound size={15} className="text-brand-cyan" />
                  <span className="text-sm font-semibold text-brand-text">{roleText}</span>
                </div>
              </div>

              {/* Account Status */}
              <div className="flex flex-col gap-1 rounded-xl border border-brand-border/60 bg-brand-card/40 p-4">
                <span className="text-xs font-medium uppercase tracking-wider text-brand-muted">
                  Account Status
                </span>
                <div className="mt-0.5 flex items-center gap-2">
                  {isActive === null ? (
                    <span className="text-sm text-brand-muted">--</span>
                  ) : isActive ? (
                    <span className="inline-flex items-center gap-1.5 text-sm font-semibold text-emerald-400">
                      <CheckCircle2 size={15} />
                      Active
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 text-sm font-semibold text-red-400">
                      <XCircle size={15} />
                      Inactive
                    </span>
                  )}
                </div>
              </div>

              {/* Member Since */}
              <div className="flex flex-col gap-1 rounded-xl border border-brand-border/60 bg-brand-card/40 p-4 sm:col-span-2">
                <span className="text-xs font-medium uppercase tracking-wider text-brand-muted">
                  Member Since
                </span>
                <div className="mt-0.5 flex items-center gap-2">
                  <Calendar size={15} className="text-brand-subtle" />
                  <span className="text-sm font-medium text-brand-text">
                    {memberSince}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
