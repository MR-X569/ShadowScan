import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Menu, X, Shield } from 'lucide-react';
import Button from '@/components/ui/Button';

const navLinks = [
  { label: 'Home', href: '#home' },
  { label: 'About', href: '#about' },
  { label: 'Contact', href: '#contact' },
];

export default function Navbar() {
  const [mobileOpen, setMobileOpen] = useState(false);

  const handleNavClick = (href: string) => {
    setMobileOpen(false);
    const target = document.querySelector(href);
    if (target) {
      target.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <header className="fixed top-0 left-0 right-0 z-50 border-b border-brand-border bg-brand-bg/90 backdrop-blur-sm">
      <nav className="mx-auto flex max-w-7xl items-center justify-between px-4 py-4 sm:px-6 lg:px-8" aria-label="Main navigation">
        {/* Logo */}
        <Link
          to="/"
          id="navbar-logo"
          className="flex items-center gap-2.5 text-xl font-bold text-brand-text"
          aria-label="ShadowScan home"
        >
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-cyan/10 text-brand-cyan ring-1 ring-brand-cyan/30">
            <Shield size={18} strokeWidth={2} />
          </div>
          <span>
            Shadow<span className="text-brand-cyan">Scan</span>
          </span>
        </Link>

        {/* Desktop Nav Links */}
        <ul className="hidden items-center gap-8 md:flex" role="list">
          {navLinks.map((link) => (
            <li key={link.label}>
              <button
                id={`nav-link-${link.label.toLowerCase()}`}
                onClick={() => handleNavClick(link.href)}
                className="text-sm font-medium text-brand-subtle transition-colors duration-200 hover:text-brand-text"
              >
                {link.label}
              </button>
            </li>
          ))}
        </ul>

        {/* Desktop Auth Buttons */}
        <div className="hidden items-center gap-3 md:flex">
          <Button id="navbar-login-btn" to="/login" variant="ghost" size="sm">
            Login
          </Button>
          <Button id="navbar-signup-btn" to="/register" variant="outline" size="sm">
            Sign Up
          </Button>
        </div>

        {/* Mobile Menu Toggle */}
        <button
          id="navbar-mobile-menu-toggle"
          className="flex items-center justify-center rounded-lg border border-brand-border p-2 text-brand-subtle transition-colors duration-200 hover:border-brand-cyan/40 hover:text-brand-text md:hidden"
          onClick={() => setMobileOpen((prev) => !prev)}
          aria-label="Toggle mobile menu"
          aria-expanded={mobileOpen}
        >
          {mobileOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </nav>

      {/* Mobile Dropdown */}
      {mobileOpen && (
        <div className="border-t border-brand-border bg-brand-bg md:hidden">
          <ul className="flex flex-col px-4 py-4 gap-1" role="list">
            {navLinks.map((link) => (
              <li key={link.label}>
                <button
                  id={`mobile-nav-link-${link.label.toLowerCase()}`}
                  onClick={() => handleNavClick(link.href)}
                  className="w-full rounded-lg px-3 py-2.5 text-left text-sm font-medium text-brand-subtle transition-colors duration-200 hover:bg-brand-surface hover:text-brand-text"
                >
                  {link.label}
                </button>
              </li>
            ))}
            <li className="mt-3 border-t border-brand-border pt-3">
              <div className="flex flex-col gap-2">
                <Button id="mobile-login-btn" to="/login" variant="ghost" size="sm" className="w-full justify-center">
                  Login
                </Button>
                <Button id="mobile-signup-btn" to="/register" variant="outline" size="sm" className="w-full justify-center">
                  Sign Up
                </Button>
              </div>
            </li>
          </ul>
        </div>
      )}
    </header>
  );
}
