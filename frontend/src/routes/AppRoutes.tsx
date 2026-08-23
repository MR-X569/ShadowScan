import { Routes, Route } from 'react-router-dom';
import LandingPage from '@/pages/Landing';
import LoginPage from '@/pages/Login';
import RegisterPage from '@/pages/Register';
import DashboardPage from '@/pages/Dashboard';

// Placeholder pages — to be implemented separately
function Scans() {
  return <h1 className="p-8 text-white">Scans</h1>;
}

function Findings() {
  return <h1 className="p-8 text-white">Findings</h1>;
}

function Settings() {
  return <h1 className="p-8 text-white">Settings</h1>;
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

      <Route path="/dashboard" element={<DashboardPage />} />
      <Route path="/scans" element={<Scans />} />
      <Route path="/findings" element={<Findings />} />
      <Route path="/settings" element={<Settings />} />

      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}