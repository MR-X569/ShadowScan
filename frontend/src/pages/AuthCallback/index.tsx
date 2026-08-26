import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import { Shield, Loader2, AlertCircle, ArrowLeft } from 'lucide-react';
import axios from 'axios';

import { exchangeGoogleCallback, exchangeGoogleTokenCookie } from '@/services/auth';

export default function AuthCallbackPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [error, setError] = useState<string>('');

  useEffect(() => {
    const errorParam = searchParams.get('error');
    const directToken = searchParams.get('token') || searchParams.get('access_token');
    const code = searchParams.get('code');
    const state = searchParams.get('state');

    // If Google returned an error query parameter
    if (errorParam) {
      setError(`Google Authentication failed: ${errorParam}`);
      return;
    }

    // Direct token in URL (fallback)
    if (directToken) {
      localStorage.setItem('token', directToken);
      navigate('/dashboard', { replace: true });
      return;
    }

    // Try exchange via secure httpOnly cookie first
    exchangeGoogleTokenCookie()
      .then(() => {
        navigate('/dashboard', { replace: true });
      })
      .catch(() => {
        // If cookie exchange failed, check if code and state were provided
        if (code && state) {
          exchangeGoogleCallback({ code, state })
            .then(() => {
              navigate('/dashboard', { replace: true });
            })
            .catch((err: unknown) => {
              if (axios.isAxiosError(err)) {
                const detail = err.response?.data?.detail;
                setError(typeof detail === 'string' ? detail : 'Failed to complete Google authentication.');
              } else {
                setError('An unexpected error occurred during Google authentication.');
              }
            });
        } else {
          setError('Google authentication failed or session expired. Please try logging in again.');
        }
      });
  }, [searchParams, navigate]);


  return (
    <div className="relative flex min-h-screen items-center justify-center bg-brand-bg px-4 py-12">
      {/* Background grid */}
      <div
        className="pointer-events-none absolute inset-0 bg-grid-pattern bg-grid opacity-100"
        aria-hidden="true"
      />

      <div className="relative z-10 w-full max-w-md">
        <div className="mb-8 flex flex-col items-center gap-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-brand-cyan/10 text-brand-cyan ring-1 ring-brand-cyan/30">
            <Shield size={24} strokeWidth={2} />
          </div>
          <h1 className="text-xl font-bold text-brand-text">
            {error ? 'Authentication Error' : 'Authenticating…'}
          </h1>
        </div>

        <div className="rounded-2xl border border-brand-border bg-brand-surface p-8 shadow-card text-center">
          {error ? (
            <div className="flex flex-col items-center gap-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-red-500/10 text-red-400 ring-1 ring-red-500/30">
                <AlertCircle size={24} />
              </div>
              <p className="text-sm text-red-400" role="alert">
                {error}
              </p>
              <Link
                to="/login"
                className="mt-4 inline-flex items-center gap-2 rounded-lg bg-brand-cyan px-5 py-2.5 text-sm font-semibold text-brand-bg shadow-btn-cyan transition-colors hover:bg-cyan-300"
              >
                <ArrowLeft size={15} />
                Return to Login
              </Link>
            </div>
          ) : (
            <div className="flex flex-col items-center gap-4 py-6">
              <Loader2 size={32} className="animate-spin text-brand-cyan" />
              <p className="text-sm text-brand-subtle">
                Verifying Google authentication credentials…
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
