import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Eye,
  EyeOff,
  CheckCircle2,
  Circle,
  AlertCircle,
  Loader2,
  Key,
  LogOut,
} from 'lucide-react';
import axios from 'axios';

import { useAuth } from '@/hooks/useAuth';
import { logout, changePassword } from '@/services/auth';
import AppHeader from '@/components/layout/AppHeader';
import InputField from '@/components/ui/InputField';

interface PasswordRule {
  label: string;
  test: (pw: string) => boolean;
}

const PASSWORD_RULES: PasswordRule[] = [
  { label: 'Minimum 8 characters', test: (pw) => pw.length >= 8 },
  { label: 'One uppercase letter', test: (pw) => /[A-Z]/.test(pw) },
  { label: 'One lowercase letter', test: (pw) => /[a-z]/.test(pw) },
  { label: 'One number', test: (pw) => /[0-9]/.test(pw) },
  { label: 'One special character', test: (pw) => /[^A-Za-z0-9]/.test(pw) },
];

export default function SettingsPage() {
  const navigate = useNavigate();
  const { user, loading: authLoading } = useAuth();

  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const [showOldPassword, setShowOldPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [loading, setLoading] = useState(false);
  const [serverError, setServerError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  const ruleResults = useMemo(() => {
    return PASSWORD_RULES.map((r) => ({
      label: r.label,
      passed: r.test(newPassword),
    }));
  }, [newPassword]);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };



  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setServerError('');
    setSuccessMessage('');
    const errors: Record<string, string> = {};

    if (!oldPassword) {
      errors.oldPassword = 'Old password is required.';
    }

    if (!newPassword) {
      errors.newPassword = 'New password is required.';
    } else if (PASSWORD_RULES.some((r) => !r.test(newPassword))) {
      errors.newPassword = 'Password does not meet all security requirements.';
    }

    if (!confirmPassword) {
      errors.confirmPassword = 'Confirm your new password.';
    } else if (newPassword !== confirmPassword) {
      errors.confirmPassword = 'Passwords do not match.';
    }

    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return;
    }

    setLoading(true);

    try {
      const response = await changePassword({
        old_password: oldPassword,
        new_password: newPassword,
      });

      setSuccessMessage(response.message || 'Password changed successfully.');
      setOldPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setFieldErrors({});
    } catch (err: unknown) {
      if (axios.isAxiosError(err)) {
        const detail = err.response?.data?.detail;
        if (typeof detail === 'string') {
          setServerError(detail);
        } else if (Array.isArray(detail)) {
          setServerError(detail.map((d) => d.msg).join(' '));
        } else {
          setServerError('Failed to change password. Please check your old password and try again.');
        }
      } else {
        setServerError('An unexpected error occurred. Please try again.');
      }
    } finally {
      setLoading(false);
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
      <main className="mx-auto w-full max-w-5xl flex-1 px-4 py-8 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-brand-text sm:text-3xl">
            Account <span className="text-brand-cyan">Settings</span>
          </h1>
          <p className="mt-1 text-sm text-brand-subtle">
            Manage your password credentials and session access.
          </p>
        </div>

        <div className="flex flex-col gap-8">
          {/* Card 1: Change Password */}
          <div className="rounded-2xl border border-brand-border bg-brand-surface p-6 shadow-card sm:p-8">
            <div className="flex items-center gap-3 border-b border-brand-border pb-4">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-cyan/10 text-brand-cyan ring-1 ring-brand-cyan/30">
                <Key size={18} />
              </div>
              <div>
                <h2 className="text-base font-semibold text-brand-text">Change Password</h2>
                <p className="text-xs text-brand-muted">
                  Update your security password regularly to protect your account
                </p>
              </div>
            </div>

            {/* Server Error Alert */}
            {serverError && (
              <div
                className="mt-6 flex items-start gap-2.5 rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-400"
                role="alert"
              >
                <AlertCircle size={18} className="mt-0.5 shrink-0" />
                <span>{serverError}</span>
              </div>
            )}

            {/* Success Alert */}
            {successMessage && (
              <div
                className="mt-6 flex items-start gap-2.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400"
                role="status"
              >
                <CheckCircle2 size={18} className="mt-0.5 shrink-0" />
                <span>{successMessage}</span>
              </div>
            )}

            <form
              id="change-password-form"
              onSubmit={handlePasswordSubmit}
              noValidate
              className="mt-6 flex flex-col gap-5"
            >
              {/* Old Password */}
              <InputField
                id="settings-old-password"
                name="oldPassword"
                label="Current Password"
                type={showOldPassword ? 'text' : 'password'}
                placeholder="Enter current password"
                autoComplete="current-password"
                value={oldPassword}
                onChange={(e) => {
                  setOldPassword(e.target.value);
                  if (fieldErrors.oldPassword) setFieldErrors((p) => ({ ...p, oldPassword: '' }));
                  if (serverError) setServerError('');
                }}
                error={fieldErrors.oldPassword}
                disabled={loading}
                rightElement={
                  <button
                    type="button"
                    onClick={() => setShowOldPassword((v) => !v)}
                    className="text-brand-muted transition-colors hover:text-brand-subtle"
                    aria-label={showOldPassword ? 'Hide old password' : 'Show old password'}
                    tabIndex={-1}
                  >
                    {showOldPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                }
              />

              {/* New Password */}
              <div className="flex flex-col gap-1.5">
                <InputField
                  id="settings-new-password"
                  name="newPassword"
                  label="New Password"
                  type={showNewPassword ? 'text' : 'password'}
                  placeholder="Create a strong new password"
                  autoComplete="new-password"
                  value={newPassword}
                  onChange={(e) => {
                    setNewPassword(e.target.value);
                    if (fieldErrors.newPassword) setFieldErrors((p) => ({ ...p, newPassword: '' }));
                    if (serverError) setServerError('');
                  }}
                  error={fieldErrors.newPassword}
                  disabled={loading}
                  rightElement={
                    <button
                      type="button"
                      onClick={() => setShowNewPassword((v) => !v)}
                      className="text-brand-muted transition-colors hover:text-brand-subtle"
                      aria-label={showNewPassword ? 'Hide new password' : 'Show new password'}
                      tabIndex={-1}
                    >
                      {showNewPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                  }
                />

                {/* Live Password Rules */}
                {newPassword.length > 0 && (
                  <ul
                    className="mt-1 flex flex-col gap-1 rounded-lg border border-brand-border bg-brand-card px-4 py-3"
                    aria-label="Password requirements"
                  >
                    {ruleResults.map((rule) => (
                      <li
                        key={rule.label}
                        className={`flex items-center gap-2 text-xs transition-colors duration-150 ${
                          rule.passed ? 'text-emerald-400' : 'text-brand-muted'
                        }`}
                      >
                        {rule.passed ? (
                          <CheckCircle2 size={13} className="shrink-0" />
                        ) : (
                          <Circle size={13} className="shrink-0" />
                        )}
                        {rule.label}
                      </li>
                    ))}
                  </ul>
                )}
              </div>


              {/* Confirm Password */}
              <InputField
                id="settings-confirm-password"
                name="confirmPassword"
                label="Confirm New Password"
                type={showConfirmPassword ? 'text' : 'password'}
                placeholder="Re-enter your new password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => {
                  setConfirmPassword(e.target.value);
                  if (fieldErrors.confirmPassword) setFieldErrors((p) => ({ ...p, confirmPassword: '' }));
                  if (serverError) setServerError('');
                }}
                error={fieldErrors.confirmPassword}
                disabled={loading}
                rightElement={
                  <button
                    type="button"
                    onClick={() => setShowConfirmPassword((v) => !v)}
                    className="text-brand-muted transition-colors hover:text-brand-subtle"
                    aria-label={showConfirmPassword ? 'Hide confirm password' : 'Show confirm password'}
                    tabIndex={-1}
                  >
                    {showConfirmPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                }
              />

              {/* Submit */}
              <div className="mt-2 flex justify-end">
                <button
                  id="save-password-btn"
                  type="submit"
                  disabled={loading || !oldPassword || !newPassword || !confirmPassword}
                  className="flex items-center justify-center gap-2 rounded-lg bg-brand-cyan px-6 py-2.5 text-sm font-semibold text-brand-bg shadow-btn-cyan transition-all duration-200 hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {loading ? (
                    <>
                      <Loader2 size={16} className="animate-spin" />
                      Updating Password…
                    </>
                  ) : (
                    'Update Password'
                  )}
                </button>
              </div>
            </form>
          </div>

          {/* Card 2: Logout */}
          <div className="rounded-2xl border border-brand-border bg-brand-surface p-6 shadow-card sm:p-8">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 className="text-base font-semibold text-brand-text">Session Management</h2>
                <p className="mt-0.5 text-xs text-brand-muted">
                  Log out of your ShadowScan session on this device
                </p>
              </div>
              <button
                id="settings-session-logout-btn"
                type="button"
                onClick={handleLogout}
                className="flex items-center justify-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-5 py-2.5 text-sm font-semibold text-red-400 transition-all duration-200 hover:bg-red-500/20 hover:border-red-500/50"
              >
                <LogOut size={16} />
                Logout of Account
              </button>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
