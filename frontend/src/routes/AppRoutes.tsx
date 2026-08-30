import { Routes, Route, Navigate } from 'react-router-dom';
import LandingPage from '@/pages/Landing';
import LoginPage from '@/pages/Login';
import RegisterPage from '@/pages/Register';
import VerifyEmailPage from '@/pages/VerifyEmail';
import ForgotPasswordPage from '@/pages/ForgotPassword';
import DashboardPage from '@/pages/Dashboard';
import ProfilePage from '@/pages/Profile';
import SettingsPage from '@/pages/Settings';
import ScanResultPage from '@/pages/Result';
import ScansPage from '@/pages/Scans';
import FindingsPage from '@/pages/Findings';
import AuthCallbackPage from '@/pages/AuthCallback';
import AdminPage from '@/pages/Admin';
import { getToken } from '@/services/auth';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const token = getToken();
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}

function NotFound() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-brand-bg text-center px-4">
      <h1 className="text-4xl font-extrabold text-brand-text">404</h1>
      <p className="mt-2 text-sm text-brand-subtle">The page you are looking for does not exist.</p>
      <a
        href="/dashboard"
        className="mt-6 rounded-lg bg-brand-cyan px-4 py-2 text-sm font-semibold text-brand-bg transition-colors hover:bg-cyan-300"
      >
        Go to Dashboard
      </a>
    </div>
  );
}

export default function AppRoutes() {
  return (
    <Routes>
      {/* Public routes */}
      <Route path="/" element={<LandingPage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/verify-email" element={<VerifyEmailPage />} />
      <Route path="/forgot-password" element={<ForgotPasswordPage />} />
      <Route path="/auth/google/callback" element={<AuthCallbackPage />} />

      {/* Protected routes */}
      <Route
        path="/dashboard"
        element={
          <ProtectedRoute>
            <DashboardPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/scans"
        element={
          <ProtectedRoute>
            <ScansPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/findings"
        element={
          <ProtectedRoute>
            <FindingsPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/profile"
        element={
          <ProtectedRoute>
            <ProfilePage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/settings"
        element={
          <ProtectedRoute>
            <SettingsPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/results/:scanId"
        element={
          <ProtectedRoute>
            <ScanResultPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/scans/:scanId"
        element={
          <ProtectedRoute>
            <ScanResultPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/admin"
        element={
          <ProtectedRoute>
            <AdminPage />
          </ProtectedRoute>
        }
      />

      {/* Catch-all */}
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}