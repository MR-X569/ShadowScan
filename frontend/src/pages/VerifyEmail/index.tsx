import { useState, useEffect, useCallback } from 'react';
import { Link, useNavigate, useLocation, useSearchParams } from 'react-router-dom';
import { Shield, Loader2, ArrowLeft, CheckCircle2, RefreshCw, Mail, AlertCircle, Edit3 } from 'lucide-react';
import axios from 'axios';

import OtpInput from '@/components/forms/OtpInput';
import InputField from '@/components/ui/InputField';
import { verifyEmail, resendVerificationOtp } from '@/services/auth';

const COUNTDOWN_SECONDS = 60;

export default function VerifyEmailPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();

  // Retrieve email passed via router state or query param
  const initialEmail = (location.state as { email?: string })?.email || searchParams.get('email') || '';

  const [email, setEmail] = useState<string>(initialEmail);
  const [isEditingEmail, setIsEditingEmail] = useState<boolean>(!initialEmail);
  const [otp, setOtp] = useState<string>('');
  const [timer, setTimer] = useState<number>(COUNTDOWN_SECONDS);
  const [isTimerActive, setIsTimerActive] = useState<boolean>(true);

  const [loading, setLoading] = useState<boolean>(false);
  const [resending, setResending] = useState<boolean>(false);
  const [serverError, setServerError] = useState<string>('');
  const [resendSuccess, setResendSuccess] = useState<string>('');
  const [verifiedSuccess, setVerifiedSuccess] = useState<string>('');

  // Countdown timer handler
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

  // Handle Resend OTP
  const handleResendOtp = useCallback(async () => {
    if (!email.trim() || timer > 0 || resending || loading) return;

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setServerError('Please enter a valid email address to resend OTP.');
      setIsEditingEmail(true);
      return;
    }

    setResending(true);
    setServerError('');
    setResendSuccess('');

    try {
      const response = await resendVerificationOtp({ email: email.trim() });
      setResendSuccess(response.message || 'Verification OTP has been resent.');
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
          setServerError('Failed to resend verification OTP. Please try again.');
        }
      } else {
        setServerError('An unexpected error occurred. Please try again.');
      }
    } finally {
      setResending(false);
    }
  }, [email, timer, resending, loading]);

  // Handle Verify OTP
  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!email.trim()) {
      setServerError('Email address is required.');
      setIsEditingEmail(true);
      return;
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setServerError('Please enter a valid email address.');
      setIsEditingEmail(true);
      return;
    }

    if (otp.length !== 6) {
      setServerError('Please enter all 6 digits of the OTP code.');
      return;
    }

    setLoading(true);
    setServerError('');
    setResendSuccess('');

    try {
      const response = await verifyEmail({
        email: email.trim(),
        otp: otp.trim(),
      });

      setVerifiedSuccess(response.message || 'Email verified successfully!');
      // Navigate to login after brief success notification
      setTimeout(() => {
        navigate('/login', { state: { emailVerified: true } });
      }, 2000);
    } catch (err: unknown) {
      if (axios.isAxiosError(err)) {
        const detail = err.response?.data?.detail;
        if (typeof detail === 'string') {
          setServerError(detail);
        } else if (Array.isArray(detail)) {
          setServerError(detail.map((d) => d.msg).join(' '));
        } else {
          setServerError('Verification failed. Invalid or expired OTP code.');
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
      {/* Background grid pattern */}
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
        {/* Logo & Header */}
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
              Verify your email
            </h1>
            <p className="mt-1 text-sm text-brand-subtle">
              Enter the 6-digit verification code sent to your inbox
            </p>
          </div>
        </div>

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
          {resendSuccess && !verifiedSuccess && (
            <div
              className="mb-6 flex items-start gap-2.5 rounded-lg border border-brand-cyan/30 bg-brand-cyan/10 px-4 py-3 text-sm text-brand-cyan"
              role="status"
            >
              <CheckCircle2 size={18} className="mt-0.5 shrink-0" />
              <span>{resendSuccess}</span>
            </div>
          )}

          {/* Verification Success Banner */}
          {verifiedSuccess && (
            <div
              className="mb-6 flex items-start gap-2.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400"
              role="status"
            >
              <CheckCircle2 size={18} className="mt-0.5 shrink-0 text-emerald-400" />
              <div>
                <p className="font-semibold">{verifiedSuccess}</p>
                <p className="mt-0.5 text-xs text-emerald-400/80">Redirecting to login…</p>
              </div>
            </div>
          )}

          {/* Email Display & Edit Badge */}
          <div className="mb-6 rounded-xl border border-brand-border/70 bg-brand-card/60 p-3.5">
            {isEditingEmail ? (
              <div className="flex flex-col gap-2">
                <InputField
                  id="verify-email-input"
                  name="email"
                  label="Target Email Address"
                  type="email"
                  placeholder="you@example.com"
                  value={email}
                  onChange={(e) => {
                    setEmail(e.target.value);
                    if (serverError) setServerError('');
                  }}
                  disabled={loading || !!verifiedSuccess}
                />
                {initialEmail && (
                  <button
                    type="button"
                    onClick={() => setIsEditingEmail(false)}
                    className="self-end text-xs text-brand-cyan hover:underline"
                  >
                    Done editing
                  </button>
                )}
              </div>
            ) : (
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2.5 overflow-hidden">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-brand-cyan/10 text-brand-cyan">
                    <Mail size={16} />
                  </div>
                  <div className="min-w-0">
                    <p className="text-xs text-brand-muted">Code sent to</p>
                    <p className="truncate text-sm font-medium text-brand-text">{email}</p>
                  </div>
                </div>
                <button
                  type="button"
                  id="change-email-btn"
                  onClick={() => setIsEditingEmail(true)}
                  disabled={loading || !!verifiedSuccess}
                  className="flex shrink-0 items-center gap-1 rounded-md px-2 py-1 text-xs font-medium text-brand-subtle transition-colors hover:bg-brand-surface hover:text-brand-cyan disabled:opacity-50"
                  aria-label="Change email address"
                >
                  <Edit3 size={13} />
                  Edit
                </button>
              </div>
            )}
          </div>

          <form id="verify-email-form" onSubmit={handleVerify} noValidate className="flex flex-col gap-6">
            {/* 6-Digit OTP Input */}
            <div className="flex flex-col items-center gap-2">
              <label className="text-xs font-medium uppercase tracking-wider text-brand-muted">
                Security Code (6 Digits)
              </label>
              <OtpInput
                length={6}
                value={otp}
                onChange={(val) => {
                  setOtp(val);
                  if (serverError) setServerError('');
                }}
                disabled={loading || !!verifiedSuccess}
                error={!!serverError}
                idPrefix="verify-otp"
              />
            </div>

            {/* Verify Email Submit Button */}
            <button
              id="verify-email-submit-btn"
              type="submit"
              disabled={loading || otp.length !== 6 || !!verifiedSuccess || !email.trim()}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-brand-cyan px-4 py-2.5 text-sm font-semibold text-brand-bg shadow-btn-cyan transition-all duration-200 hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? (
                <>
                  <Loader2 size={16} className="animate-spin" />
                  Verifying OTP…
                </>
              ) : verifiedSuccess ? (
                <>
                  <CheckCircle2 size={16} />
                  Verified
                </>
              ) : (
                'Verify Email'
              )}
            </button>
          </form>

          {/* Resend Section */}
          <div className="mt-6 flex flex-col items-center justify-center gap-2 border-t border-brand-border/60 pt-5 text-center">
            <p className="text-xs text-brand-muted">Didn't receive the email code?</p>
            {isTimerActive ? (
              <div className="flex items-center gap-1.5 text-xs text-brand-subtle">
                <span>Resend available in</span>
                <span className="font-mono font-semibold text-brand-cyan">{timer}s</span>
              </div>
            ) : (
              <button
                type="button"
                id="resend-otp-btn"
                onClick={handleResendOtp}
                disabled={resending || loading || !!verifiedSuccess || !email.trim()}
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
        </div>

        {/* Back to Login Link */}
        <div className="mt-6 text-center">
          <Link
            to="/login"
            id="verify-back-to-login"
            className="inline-flex items-center gap-1.5 text-sm font-medium text-brand-subtle transition-colors hover:text-brand-cyan"
          >
            <ArrowLeft size={16} />
            Back to Login
          </Link>
        </div>
      </div>
    </div>
  );
}
