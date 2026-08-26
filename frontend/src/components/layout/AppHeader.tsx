import { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  ScanLine,
  AlertTriangle,
  User as UserIcon,
  Settings as SettingsIcon,
  LogOut,
  Menu,
  X,
} from 'lucide-react';
import { logout } from '@/services/auth';
import type { UserProfile } from '@/types/user';

interface AppHeaderProps {
  user?: UserProfile | null;
}

const navItems = [
  { label: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
  { label: 'Scans', path: '/scans', icon: ScanLine },
  { label: 'Findings', path: '/findings', icon: AlertTriangle },
  { label: 'Profile', path: '/profile', icon: UserIcon },
  { label: 'Settings', path: '/settings', icon: SettingsIcon },
];

export default function AppHeader({ user }: AppHeaderProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <header className="sticky top-0 z-50 border-b border-brand-border bg-brand-bg/90 backdrop-blur-sm">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-4 sm:px-6 lg:px-8">
        {/* Logo */}
        <Link
          to="/dashboard"
          className="flex items-center gap-2.5 text-xl font-bold text-brand-text"
          aria-label="ShadowScan dashboard"
        >
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-cyan/10 text-brand-cyan ring-1 ring-brand-cyan/30">
            <Shield size={18} strokeWidth={2} />
          </div>
          <span>
            Shadow<span className="text-brand-cyan">Scan</span>
          </span>
        </Link>

        {/* Desktop Navigation */}
        <nav className="hidden items-center gap-1.5 md:flex" aria-label="App Navigation">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path || (item.path !== '/dashboard' && location.pathname.startsWith(item.path));
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-brand-cyan/10 text-brand-cyan ring-1 ring-brand-cyan/30'
                    : 'text-brand-subtle hover:bg-brand-surface hover:text-brand-text'
                }`}
              >
                <Icon size={15} />
                {item.label}
              </Link>
            );
          })}
        </nav>

        {/* Desktop User Info & Logout */}
        <div className="hidden items-center gap-3 md:flex">
          {user?.email && (
            <span className="text-sm text-brand-subtle">
              {user.email}
            </span>
          )}
          <button
            onClick={handleLogout}
            className="flex items-center gap-1.5 rounded-lg border border-brand-border px-3 py-2 text-sm font-medium text-brand-subtle transition-all duration-200 hover:border-red-500/30 hover:text-red-400"
          >
            <LogOut size={14} />
            Logout
          </button>
        </div>

        {/* Mobile Menu Button */}
        <button
          type="button"
          onClick={() => setMobileMenuOpen((prev) => !prev)}
          className="flex items-center justify-center rounded-lg border border-brand-border p-2 text-brand-subtle transition-colors hover:text-brand-text md:hidden"
          aria-label="Toggle navigation menu"
        >
          {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </div>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="border-t border-brand-border bg-brand-surface px-4 py-4 md:hidden">
          <nav className="flex flex-col gap-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  onClick={() => setMobileMenuOpen(false)}
                  className={`flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors ${
                    isActive
                      ? 'bg-brand-cyan/10 text-brand-cyan'
                      : 'text-brand-subtle hover:bg-brand-card hover:text-brand-text'
                  }`}
                >
                  <Icon size={16} />
                  {item.label}
                </Link>
              );
            })}

            <div className="mt-3 border-t border-brand-border pt-3">
              {user?.email && (
                <p className="px-3 py-1 text-xs text-brand-muted truncate">
                  Signed in as <span className="font-semibold text-brand-text">{user.email}</span>
                </p>
              )}
              <button
                onClick={() => {
                  setMobileMenuOpen(false);
                  handleLogout();
                }}
                className="mt-2 flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium text-red-400 hover:bg-red-500/10"
              >
                <LogOut size={16} />
                Logout
              </button>
            </div>
          </nav>
        </div>
      )}
    </header>
  );
}
