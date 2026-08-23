import { useState, useMemo } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Eye, EyeOff, Shield, Loader2, CheckCircle2, Circle } from 'lucide-react';
import axios from 'axios';

import InputField from '@/components/ui/InputField';
import { register } from '@/services/auth';

interface FormState {
  full_name: string;
  username: string;
  email: string;
  password: string;
  confirm_password: string;
}

interface FormErrors {
  full_name?: string;
  username?: string;
  email?: string;
  password?: string;
  confirm_password?: string;
}

interface PasswordRule {
  label: string;
  test: (pw: string) => boolean;
}

const PASSWORD_RULES: PasswordRule[] = [
  { label: 'Minimum 8 characters',     test: (pw) => pw.length >= 8 },
  { label: 'One uppercase letter',      test: (pw) => /[A-Z]/.test(pw) },
  { label: 'One lowercase letter',      test: (pw) => /[a-z]/.test(pw) },
  { label: 'One number',               test: (pw) => /[0-9]/.test(pw) },
  { label: 'One special character',    test: (pw) => /[^A-Za-z0-9]/.test(pw) },
];

function validateForm(form: FormState): FormErrors {
  const errors: FormErrors = {};

  if (!form.full_name.trim()) {
    errors.full_name = 'Full name is required.';
  }

  if (!form.username.trim()) {
    errors.username = 'Username is required.';
  } else if (form.username.trim().length < 3) {
    errors.username = 'Username must be at least 3 characters.';
  }

  if (!form.email.trim()) {
    errors.email = 'Email address is required.';
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) {
    errors.email = 'Enter a valid email address.';
  }

  if (!form.password) {
    errors.password = 'Password is required.';
  } else if (PASSWORD_RULES.some((r) => !r.test(form.password))) {
    errors.password = 'Password does not meet all requirements.';
  }

  if (!form.confirm_password) {
    errors.confirm_password = 'Please confirm your password.';
  } else if (form.password !== form.confirm_password) {
    errors.confirm_password = 'Passwords do not match.';
  }

  return errors;
}

export default function RegisterPage() {
  const navigate = useNavigate();

  const [form, setForm] = useState<FormState>({
    full_name: '',
    username: '',
    email: '',
    password: '',
    confirm_password: '',
  });
  const [errors, setErrors] = useState<FormErrors>({});
  const [serverError, setServerError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);

  const passwordRuleStatus = useMemo(
    () => PASSWORD_RULES.map((rule) => ({ ...rule, passed: rule.test(form.password) })),
    [form.password]
  );

  const showPasswordRules = form.password.length > 0;

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
    if (errors[name as keyof FormErrors]) {
      setErrors((prev) => ({ ...prev, [name]: undefined }));
    }
    if (serverError) setServerError('');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const validationErrors = validateForm(form);
    if (Object.keys(validationErrors).length > 0) {
      setErrors(validationErrors);
      return;
    }

    setLoading(true);
    setServerError('');

    try {
      await register({
        full_name: form.full_name.trim(),
        username: form.username.trim(),
        email: form.email.trim(),
        password: form.password,
      });
      navigate('/login');
    } catch (err: unknown) {
      if (axios.isAxiosError(err)) {
        const detail = err.response?.data?.detail;
        if (typeof detail === 'string') {
          setServerError(detail);
        } else if (Array.isArray(detail)) {
          setServerError(detail.map((d) => d.msg).join(' '));
        } else {
          setServerError('Registration failed. Please try again.');
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

      {/* Top glow */}
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
              Create your account
            </h1>
            <p className="mt-1 text-sm text-brand-subtle">
              Start scanning your websites for vulnerabilities
            </p>
          </div>
        </div>

        {/* Card */}
        <div className="rounded-2xl border border-brand-border bg-brand-surface p-8 shadow-card">
          {/* Server Error Banner */}
          {serverError && (
            <div
              className="mb-6 rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-400"
              role="alert"
            >
              {serverError}
            </div>
          )}

          <form id="register-form" onSubmit={handleSubmit} noValidate className="flex flex-col gap-5">
            {/* Full Name */}
            <InputField
              id="register-full-name"
              name="full_name"
              label="Full Name"
              type="text"
              placeholder="John Doe"
              autoComplete="name"
              value={form.full_name}
              onChange={handleChange}
              error={errors.full_name}
              disabled={loading}
            />

            {/* Username */}
            <InputField
              id="register-username"
              name="username"
              label="Username"
              type="text"
              placeholder="johndoe"
              autoComplete="username"
              value={form.username}
              onChange={handleChange}
              error={errors.username}
              disabled={loading}
            />

            {/* Email */}
            <InputField
              id="register-email"
              name="email"
              label="Email Address"
              type="email"
              placeholder="you@example.com"
              autoComplete="email"
              value={form.email}
              onChange={handleChange}
              error={errors.email}
              disabled={loading}
            />

            {/* Password */}
            <div className="flex flex-col gap-1.5">
              <InputField
                id="register-password"
                name="password"
                label="Password"
                type={showPassword ? 'text' : 'password'}
                placeholder="Create a strong password"
                autoComplete="new-password"
                value={form.password}
                onChange={handleChange}
                error={errors.password}
                disabled={loading}
                rightElement={
                  <button
                    type="button"
                    id="register-password-toggle"
                    onClick={() => setShowPassword((v) => !v)}
                    className="text-brand-muted transition-colors hover:text-brand-subtle"
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                    tabIndex={-1}
                  >
                    {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                }
              />

              {/* Live Password Rules */}
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
              id="register-confirm-password"
              name="confirm_password"
              label="Confirm Password"
              type={showConfirm ? 'text' : 'password'}
              placeholder="Repeat your password"
              autoComplete="new-password"
              value={form.confirm_password}
              onChange={handleChange}
              error={errors.confirm_password}
              disabled={loading}
              rightElement={
                <button
                  type="button"
                  id="register-confirm-password-toggle"
                  onClick={() => setShowConfirm((v) => !v)}
                  className="text-brand-muted transition-colors hover:text-brand-subtle"
                  aria-label={showConfirm ? 'Hide password' : 'Show password'}
                  tabIndex={-1}
                >
                  {showConfirm ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              }
            />

            {/* Submit */}
            <button
              id="register-submit-btn"
              type="submit"
              disabled={loading}
              className="mt-1 flex w-full items-center justify-center gap-2 rounded-lg bg-brand-cyan px-4 py-2.5 text-sm font-semibold text-brand-bg shadow-btn-cyan transition-all duration-200 hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading ? (
                <>
                  <Loader2 size={16} className="animate-spin" />
                  Creating account…
                </>
              ) : (
                'Create Account'
              )}
            </button>

            {/* Divider */}
            <div className="flex items-center gap-3">
              <div className="h-px flex-1 bg-brand-border" />
              <span className="text-xs text-brand-muted">or</span>
              <div className="h-px flex-1 bg-brand-border" />
            </div>

            {/* Google Button */}
            {/* TODO: Google OAuth Integration */}
            <button
              id="register-google-btn"
              type="button"
              disabled={loading}
              className="flex w-full items-center justify-center gap-3 rounded-lg border border-brand-border bg-brand-card px-4 py-2.5 text-sm font-medium text-brand-text transition-all duration-200 hover:border-brand-cyan/30 hover:bg-brand-card/80 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {/* Google G SVG — official colors */}
              <svg
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 48 48"
                width="18"
                height="18"
                aria-hidden="true"
              >
                <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z" />
                <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z" />
                <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z" />
                <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z" />
              </svg>
              Continue with Google
            </button>
          </form>
        </div>

        {/* Bottom link */}
        <p className="mt-6 text-center text-sm text-brand-subtle">
          Already have an account?{' '}
          <Link
            to="/login"
            id="register-login-link"
            className="font-medium text-brand-cyan transition-colors hover:text-cyan-300"
          >
            Login
          </Link>
        </p>
      </div>
    </div>
  );
}
