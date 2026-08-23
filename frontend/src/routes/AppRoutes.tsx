import { Routes, Route } from 'react-router-dom';
import LandingPage from '@/pages/Landing';
import LoginPage from '@/pages/Login';
import RegisterPage from '@/pages/Register';
import VerifyEmailPage from '@/pages/VerifyEmail';
import ForgotPasswordPage from '@/pages/ForgotPassword';
import DashboardPage from '@/pages/Dashboard';
import ProfilePage from '@/pages/Profile';
import SettingsPage from '@/pages/Settings';
import ScanResultPage from '@/pages/Result';
import AuthCallbackPage from '@/pages/AuthCallback';

// Placeholder pages — to be implemented separately
function Scans() {
  return <h1 className="p-8 text-white">Scans</h1>;
}

function Findings() {
  return <h1 className="p-8 text-white">Findings</h1>;
}

function NotFound() {
  return <h1 className="p-8 text-white">404 — Page Not Found</h1>;
}

export default function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />

      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/verify-email" element={<VerifyEmailPage />} />
      <Route path="/forgot-password" element={<ForgotPasswordPage />} />
      <Route path="/auth/google/callback" element={<AuthCallbackPage />} />

      <Route path="/dashboard" element={<DashboardPage />} />
      <Route path="/profile" element={<ProfilePage />} />
      <Route path="/settings" element={<SettingsPage />} />
      <Route path="/results/:scanId" element={<ScanResultPage />} />
      <Route path="/scans/:scanId" element={<ScanResultPage />} />
      <Route path="/scans" element={<Scans />} />
      <Route path="/findings" element={<Findings />} />

      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}