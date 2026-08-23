import { Shield, Github } from 'lucide-react';

const footerLinks = [
  { label: 'About', href: '#about' },
  { label: 'Contact', href: '#contact' },
];

const handleScrollTo = (href: string) => {
  const target = document.querySelector(href);
  if (target) {
    target.scrollIntoView({ behavior: 'smooth' });
  }
};

export default function Footer() {
  return (
    <footer id="contact" className="border-t border-brand-border bg-brand-bg">
      <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8">
        <div className="flex flex-col items-center gap-8 md:flex-row md:items-center md:justify-between">
          {/* Brand */}
          <div className="flex flex-col items-center gap-3 md:items-start">
            <div className="flex items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-cyan/10 text-brand-cyan ring-1 ring-brand-cyan/30">
                <Shield size={18} strokeWidth={2} />
              </div>
              <span className="text-lg font-bold text-brand-text">
                Shadow<span className="text-brand-cyan">Scan</span>
              </span>
            </div>
            <p className="max-w-xs text-center text-sm text-brand-subtle md:text-left">
              Automated website vulnerability scanning and security reporting.
            </p>
          </div>

          {/* Links */}
          <nav aria-label="Footer navigation">
            <ul className="flex items-center gap-6" role="list">
              {footerLinks.map((link) => (
                <li key={link.label}>
                  <button
                    id={`footer-link-${link.label.toLowerCase()}`}
                    onClick={() => handleScrollTo(link.href)}
                    className="text-sm text-brand-subtle transition-colors duration-200 hover:text-brand-text"
                  >
                    {link.label}
                  </button>
                </li>
              ))}
              <li>
                <a
                  id="footer-github-link"
                  href="https://github.com"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1.5 text-sm text-brand-subtle transition-colors duration-200 hover:text-brand-text"
                  aria-label="ShadowScan on GitHub"
                >
                  <Github size={15} />
                  GitHub
                </a>
              </li>
            </ul>
          </nav>
        </div>

        {/* Divider + Copyright */}
        <div className="mt-8 border-t border-brand-border pt-6 text-center">
          <p className="text-sm text-brand-muted" style={{ color: '#4b5563' }}>
            &copy; {new Date().getFullYear()} ShadowScan. All rights reserved.
          </p>
        </div>
      </div>
    </footer>
  );
}
