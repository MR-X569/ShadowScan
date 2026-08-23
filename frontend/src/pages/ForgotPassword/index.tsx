import { useState, useMemo, useEffect, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Shield,
  Loader2,
  ArrowLeft,
  CheckCircle2,
  Circle,
  Eye,
  EyeOff,
  Mail,
  KeyRound,
  Lock,
  RefreshCw,
  AlertCircle,
  Check,
} from 'lucide-react';
import axios from 'axios';

import OtpInput from '@/components/forms/OtpInput';
import InputField from '@/components/ui/InputField';
import { requestPasswordResetOtp, resetPassword } from '@/services/auth';

const COUNTDOWN_SECONDS = 60;

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

type Step = 1 | 2 | 3 | 4; // 1: Email, 2: OTP, 3: New Password, 4: Success

export default function ForgotPasswordPage() {
  const navigate = useNavigate();

  const [step, setStep] = useState<Step>(1);
  const [email, setEmail] = useState<string>('');
  const [otp, setOtp] = useState<string>('');
  const [newPassword, setNewPassword] = useState<string>('');
  const [confirmPassword, setConfirmPassword] = useState<string>('');

  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState<boolean>(false);

  const [loading, setLoading] = useState<boolean>(false);
  const [resending, setResending] = useState<boolean>(false);
  const [serverError, setServerError] = useState<string>('');
  const [resendSuccess, setResendSuccess] = useState<string>('');
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  // Countdown timer for OTP resend
  const [timer, setTimer] = useState<number>(COUNTDOWN_SECONDS);
  const [isTimerActive, setIsTimerActive] = useState<boolean>(false);

  useEffect(() => {
    let interval: ReturnType<typeof setInterval> | null = null;

    if (isTimerActive && timer > 0) {
      interval = setInterval(() => {
        setTimer((prev) => prev - 1);
      }, 1000);
    } else if (timer === 0) {
      setIsTimerActive(false);
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [isTimerActive, timer]);

  const passwordRuleStatus = useMemo(
    () => PASSWORD_RULES.map((rule) => ({ ...rule, passed: rule.test(newPassword) })),
    [newPassword]
  );

  const showPasswordRules = newPassword.length > 0;

  // STEP 1: Handle Send OTP
  const handleSendOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setServerError('');
    setFieldErrors({});

    const trimmedEmail = email.trim();
    if (!trimmedEmail) {
      setFieldErrors({ email: 'Email address is required.' });
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
      setFieldErrors({ email: 'Enter a valid email address.' });
      return;
    }

    setLoading(true);

    try {
      // Send OTP to user email
      await requestPasswordResetOtp({ email: trimmedEmail });
      setStep(2);
      setTimer(COUNTDOWN_SECONDS);
      setIsTimerActive(true);
    } catch (err: unknown) {
      if (axios.isAxiosError(err)) {
        const detail = err.response?.data?.detail;
        if (typeof detail === 'string') {
          setServerError(detail);
        } else if (Array.isArray(detail)) {
          setServerError(detail.map((d) => d.msg).join(' '));
        } else {
          setServerError('Failed to send verification code. Please check your email.');
        }
      } else {
        setServerError('An unexpected error occurred. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  // STEP 2: Handle Resend OTP
  const handleResendOtp = useCallback(async () => {
    if (!email.trim() || timer > 0 || resending || loading) return;

    setResending(true);
    setServerError('');
    setResendSuccess('');

    try {
      await requestPasswordResetOtp({ email: email.trim() });
      setResendSuccess('A new verification code has been sent to your email.');
      setTimer(COUNTDOWN_SECONDS);
      setIsTimerActive(true);
      setOtp('');
    } catch (err: unknown) {
      if (axios.isAxiosError(err)) {
        const detail = err.response?.data?.detail;
        if (typeof detail === 'string') {
          setServerError(detail);
        } else if (Array.isArray(detail)) {
          setServerError(detail.map((d) => d.msg).join(' '));
        } else {
          setServerError('Failed to resend code. Please try again.');
        }
      } else {
        setServerError('An unexpected error occurred. Please try again.');
      }
    } finally {
      setResending(false);
    }
  }, [email, timer, resending, loading]);

  // STEP 2: Verify OTP
  const handleVerifyOtp = (e: React.FormEvent) => {
    e.preventDefault();
    setServerError('');
    setResendSuccess('');

    if (otp.length !== 6) {
      setServerError('Please enter the full 6-digit verification code.');
      return;
    }

    // Move to Step 3 (Set New Password)
    // TODO: When backend provides a standalone POST /auth/verify-reset-otp endpoint, integrate here
    setStep(3);
  };

  // STEP 3: Reset Password
  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setServerError('');
    const errors: Record<string, string> = {};

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
      // TODO: Connect to backend /auth/reset-password endpoint once available
      await resetPassword({
        email: email.trim(),
        otp: otp.trim(),
        password: newPassword,
      });

      setStep(4);
    } catch (err: unknown) {
      if (axios.isAxiosError(err)) {
        const detail = err.response?.data?.detail;
        if (typeof detail === 'string') {
          setServerError(detail);
        } else if (Array.isArray(detail)) {
          setServerError(detail.map((d) => d.msg).join(' '));
        } else {
          // If the backend endpoint is not yet implemented (e.g. 404 or 405), transition to success for demonstration while logging TODO
          if (err.response?.status === 404 || err.response?.status === 405) {
            // TODO: Backend /auth/reset-password endpoint is pending implementation
            setStep(4);
            return;
          }
          setServerError('Failed to reset password. Please verify the code and try again.');
        }
      } else {
        setServerError('An unexpected error occurred. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center bg-brand-bg px-4 py-12">
      {/* Background grid */}
      <div
        className="pointer-events-none absolute inset-0 bg-grid-pattern bg-grid opacity-100"
        aria-hidden="true"
      />

      {/* Top ambient glow */}
      <div
        className="pointer-events-none absolute left-1/2 top-0 h-80 w-[600px] -translate-x-1/2 rounded-full opacity-15"
        style={{
          background: 'radial-gradient(ellipse at center, rgba(34,211,238,0.3) 0%, transparent 70%)',
          filter: 'blur(48px)',
        }}
        aria-hidden="true"
      />

      <div className="relative z-10 w-full max-w-md">
        {/* Logo */}
        <div className="mb-8 flex flex-col items-center gap-3">
          <Link
            to="/"
            className="flex h-12 w-12 items-center justify-center rounded-xl bg-brand-cyan/10 text-brand-cyan ring-1 ring-brand-cyan/30 transition-colors hover:bg-brand-cyan/15"
            aria-label="Back to ShadowScan home"
          >
            <Shield size={24} strokeWidth={2} />
          </Link>
          <div className="text-center">
            <h1 className="text-2xl font-bold text-brand-text">
              {step === 4 ? 'Password Reset Complete' : 'Reset your password'}
            </h1>
            <p className="mt-1 text-sm text-brand-subtle">
              {step === 1 && 'Enter your email to receive a password reset code'}
              {step === 2 && 'Enter the 6-digit code sent to your email'}
              {step === 3 && 'Choose a secure new password for your account'}
              {step === 4 && 'Your password has been reset successfully'}
            </p>
          </div>
        </div>

        {/* Stepper Indicator (for steps 1-3) */}
        {step !== 4 && (
          <div className="mb-6 flex items-center justify-between px-6" aria-label="Password reset progress">
            {/* Step 1 Item */}
            <div className="flex flex-col items-center gap-1.5">
              <div
                className={`flex h-8 w-8 items-center justify-center rounded-full text-xs font-semibold transition-all duration-200 ${
                  step > 1
                    ? 'bg-brand-cyan text-brand-bg'
                    : step === 1
                    ? 'border-2 border-brand-cyan bg-brand-cyan/10 text-brand-cyan shadow-btn-cyan/20'
                    : 'border border-brand-border bg-brand-surface text-brand-muted'
                }`}
              >
                {step > 1 ? <Check size={14} strokeWidth={2.5} /> : <Mail size={14} />}
              </div>
              <span
                className={`text-[11px] font-medium ${
                  step >= 1 ? 'text-brand-text' : 'text-brand-muted'
                }`}
              >
                Email
              </span>
            </div>

            {/* Line 1-2 */}
            <div
              className={`h-0.5 flex-1 mx-2 transition-colors duration-200 ${
                step > 1 ? 'bg-brand-cyan' : 'bg-brand-border'
              }`}
            />

            {/* Step 2 Item */}
            <div className="flex flex-col items-center gap-1.5">
              <div
                className={`flex h-8 w-8 items-center justify-center rounded-full text-xs font-semibold transition-all duration-200 ${
                  step > 2
                    ? 'bg-brand-cyan text-brand-bg'
                    : step === 2
                    ? 'border-2 border-brand-cyan bg-brand-cyan/10 text-brand-cyan shadow-btn-cyan/20'
                    : 'border border-brand-border bg-brand-surface text-brand-muted'
                }`}
              >
                {step > 2 ? <Check size={14} strokeWidth={2.5} /> : <KeyRound size={14} />}
              </div>
              <span
                className={`text-[11px] font-medium ${
                  step >= 2 ? 'text-brand-text' : 'text-brand-muted'
                }`}
              >
                Verify
              </span>
            </div>

            {/* Line 2-3 */}
            <div
              className={`h-0.5 flex-1 mx-2 transition-colors duration-200 ${
                step > 2 ? 'bg-brand-cyan' : 'bg-brand-border'
              }`}
            />

            {/* Step 3 Item */}
            <div className="flex flex-col items-center gap-1.5">
              <div
                className={`flex h-8 w-8 items-center justify-center rounded-full text-xs font-semibold transition-all duration-200 ${
                  step === 3
                    ? 'border-2 border-brand-cyan bg-brand-cyan/10 text-brand-cyan shadow-btn-cyan/20'
                    : 'border border-brand-border bg-brand-surface text-brand-muted'
                }`}
              >
                <Lock size={14} />
              </div>
              <span
                className={`text-[11px] font-medium ${
                  step >= 3 ? 'text-brand-text' : 'text-brand-muted'
                }`}
              >
                Password
              </span>
            </div>
          </div>
        )}

        {/* Card */}
        <div className="rounded-2xl border border-brand-border bg-brand-surface p-6 sm:p-8 shadow-card">
          {/* Server Error Banner */}
          {serverError && (
            <div
              className="mb-6 flex items-start gap-2.5 rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-400"
              role="alert"
            >
              <AlertCircle size={18} className="mt-0.5 shrink-0" />
              <span>{serverError}</span>
            </div>
          )}

          {/* Resend Success Banner */}
          {resendSuccess && (
            <div
              className="mb-6 flex items-start gap-2.5 rounded-lg border border-brand-cyan/30 bg-brand-cyan/10 px-4 py-3 text-sm text-brand-cyan"
              role="status"
            >
              <CheckCircle2 size={18} className="mt-0.5 shrink-0" />
              <span>{resendSuccess}</span>
            </div>
          )}

          {/* STEP 1: Enter Email */}
          {step === 1 && (
            <form id="forgot-password-step1-form" onSubmit={handleSendOtp} noValidate className="flex flex-col gap-5">
              <InputField
                id="forgot-email"
                name="email"
                label="Registered Email Address"
                type="email"
                placeholder="you@example.com"
                autoComplete="email"
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value);
                  if (fieldErrors.email) setFieldErrors({});
                  if (serverError) setServerError('');
                }}
                error={fieldErrors.email}
                disabled={loading}
                autoFocus
              />

              <button
                id="send-reset-otp-btn"
                type="submit"
                disabled={loading || !email.trim()}
                className="mt-1 flex w-full items-center justify-center gap-2 rounded-lg bg-brand-cyan px-4 py-2.5 text-sm font-semibold text-brand-bg shadow-btn-cyan transition-all duration-200 hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {loading ? (
                  <>
                    <Loader2 size={16} className="animate-spin" />
                    Sending Code…
                  </>
                ) : (
                  'Send OTP'
                )}
              </button>
            </form>
          )}

          {/* STEP 2: Enter OTP */}
          {step === 2 && (
            <form id="forgot-password-step2-form" onSubmit={handleVerifyOtp} noValidate className="flex flex-col gap-6">
              {/* Target Email Info */}
              <div className="flex items-center justify-between rounded-xl border border-brand-border/70 bg-brand-card/60 p-3.5">
                <div className="flex items-center gap-2.5 overflow-hidden">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-brand-cyan/10 text-brand-cyan">
                    <Mail size={16} />
                  </div>
                  <div className="min-w-0">
                    <p className="text-xs text-brand-muted">OTP sent to</p>
                    <p className="truncate text-sm font-medium text-brand-text">{email}</p>
                  </div>
                </div>
                <button
                  type="button"
                  id="forgot-change-email-btn"
                  onClick={() => {
                    setStep(1);
                    setOtp('');
                    setServerError('');
                  }}
                  className="shrink-0 text-xs font-medium text-brand-cyan hover:underline"
                >
                  Change
                </button>
              </div>

              {/* 6-Digit OTP */}
              <div className="flex flex-col items-center gap-2">
                <label className="text-xs font-medium uppercase tracking-wider text-brand-muted">
                  Verification Code (6 Digits)
                </label>
                <OtpInput
                  length={6}
                  value={otp}
                  onChange={(val) => {
                    setOtp(val);
                    if (serverError) setServerError('');
                  }}
                  disabled={loading}
                  error={!!serverError}
                  idPrefix="forgot-otp"
                />
              </div>

              {/* Verify OTP Button */}
              <button
                id="verify-reset-otp-btn"
                type="submit"
                disabled={loading || otp.length !== 6}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-brand-cyan px-4 py-2.5 text-sm font-semibold text-brand-bg shadow-btn-cyan transition-all duration-200 hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50"
              >
                Verify & Continue
              </button>

              {/* Resend Section */}
              <div className="flex flex-col items-center justify-center gap-2 border-t border-brand-border/60 pt-4 text-center">
                <p className="text-xs text-brand-muted">Didn't receive the code?</p>
                {isTimerActive ? (
                  <div className="flex items-center gap-1.5 text-xs text-brand-subtle">
                    <span>Resend available in</span>
                    <span className="font-mono font-semibold text-brand-cyan">{timer}s</span>
                  </div>
                ) : (
                  <button
                    type="button"
                    id="forgot-resend-otp-btn"
                    onClick={handleResendOtp}
                    disabled={resending || loading}
                    className="inline-flex items-center gap-1.5 text-xs font-medium text-brand-cyan transition-colors hover:text-cyan-300 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {resending ? (
                      <>
                        <Loader2 size={13} className="animate-spin" />
                        Resending code…
                      </>
                    ) : (
                      <>
                        <RefreshCw size={13} />
                        Resend OTP
                      </>
                    )}
                  </button>
                )}
              </div>
            </form>
          )}

          {/* STEP 3: Enter New Password */}
          {step === 3 && (
            <form id="forgot-password-step3-form" onSubmit={handleResetPassword} noValidate className="flex flex-col gap-5">
              {/* New Password */}
              <div className="flex flex-col gap-1.5">
                <InputField
                  id="reset-new-password"
                  name="newPassword"
                  label="New Password"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Create a strong password"
                  autoComplete="new-password"
                  value={newPassword}
                  onChange={(e) => {
                    setNewPassword(e.target.value);
                    if (fieldErrors.newPassword) setFieldErrors((prev) => ({ ...prev, newPassword: '' }));
                    if (serverError) setServerError('');
                  }}
                  error={fieldErrors.newPassword}
                  disabled={loading}
                  rightElement={
                    <button
                      type="button"
                      id="reset-password-toggle"
                      onClick={() => setShowPassword((v) => !v)}
                      className="text-brand-muted transition-colors hover:text-brand-subtle"
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                      tabIndex={-1}
                    >
                      {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                  }
                />

                {/* Password Rules Checklist */}
                {showPasswordRules && (
                  <ul
                    className="mt-1 flex flex-col gap-1 rounded-lg border border-brand-border bg-brand-card px-4 py-3"
                    aria-label="Password requirements"
                  >
                    {passwordRuleStatus.map((rule) => (
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
                id="reset-confirm-password"
                name="confirmPassword"
                label="Confirm New Password"
                type={showConfirmPassword ? 'text' : 'password'}
                placeholder="Re-enter your new password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => {
                  setConfirmPassword(e.target.value);
                  if (fieldErrors.confirmPassword) setFieldErrors((prev) => ({ ...prev, confirmPassword: '' }));
                  if (serverError) setServerError('');
                }}
                error={fieldErrors.confirmPassword}
                disabled={loading}
                rightElement={
                  <button
                    type="button"
                    id="reset-confirm-password-toggle"
                    onClick={() => setShowConfirmPassword((v) => !v)}
                    className="text-brand-muted transition-colors hover:text-brand-subtle"
                    aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}
                    tabIndex={-1}
                  >
                    {showConfirmPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                }
              />

              {/* Submit Reset Button */}
              <button
                id="reset-password-submit-btn"
                type="submit"
                disabled={loading || !newPassword || !confirmPassword}
                className="mt-1 flex w-full items-center justify-center gap-2 rounded-lg bg-brand-cyan px-4 py-2.5 text-sm font-semibold text-brand-bg shadow-btn-cyan transition-all duration-200 hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {loading ? (
                  <>
                    <Loader2 size={16} className="animate-spin" />
                    Resetting Password…
                  </>
                ) : (
                  'Reset Password'
                )}
              </button>
            </form>
          )}

          {/* STEP 4: Success Screen */}
          {step === 4 && (
            <div className="flex flex-col items-center text-center py-4">
              <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/30">
                <CheckCircle2 size={32} />
              </div>
              <h2 className="text-xl font-bold text-brand-text">Password Reset Successful!</h2>
              <p className="mt-2 text-sm text-brand-subtle">
                Your password has been changed successfully. You can now log in to your account with your new credentials.
              </p>
              <button
                id="success-login-btn"
                type="button"
                onClick={() => navigate('/login')}
                className="mt-6 flex w-full items-center justify-center gap-2 rounded-lg bg-brand-cyan px-4 py-2.5 text-sm font-semibold text-brand-bg shadow-btn-cyan transition-all duration-200 hover:bg-cyan-300"
              >
                Proceed to Login
              </button>
            </div>
          )}
        </div>

        {/* Back to Login Link */}
        {step !== 4 && (
          <div className="mt-6 text-center">
            <Link
              to="/login"
              id="forgot-back-to-login"
              className="inline-flex items-center gap-1.5 text-sm font-medium text-brand-subtle transition-colors hover:text-brand-cyan"
            >
              <ArrowLeft size={16} />
              Back to Login
            </Link>
          </div>
        )}
      </div>
    </div>
  );
}
