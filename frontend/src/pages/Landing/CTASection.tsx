import { ArrowRight } from 'lucide-react';
import Button from '@/components/ui/Button';

export default function CTASection() {
  return (
    <section className="bg-brand-surface py-24">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="relative overflow-hidden rounded-2xl border border-brand-border bg-cta-glow px-6 py-16 text-center sm:px-12">
          {/* Decorative top accent line */}
          <div
            className="pointer-events-none absolute inset-x-0 top-0 h-px"
            style={{
              background:
                'linear-gradient(90deg, transparent, rgba(34,211,238,0.5), transparent)',
            }}
            aria-hidden="true"
          />

          {/* Content */}
          <p className="mb-3 font-mono text-xs font-medium uppercase tracking-widest text-brand-cyan">
            Get Started
          </p>
          <h2 className="mb-4 text-3xl font-bold text-brand-text sm:text-4xl">
            Ready to Secure Your Website?
          </h2>
          <p className="mx-auto mb-10 max-w-xl text-base leading-relaxed text-brand-subtle">
            Join ShadowScan today and start identifying vulnerabilities in your web applications
            with automated security assessments and detailed reports.
          </p>

          <div className="flex flex-col items-center justify-center gap-4 sm:flex-row">
            <Button id="cta-login-btn" to="/login" variant="primary" size="lg">
              Login
              <ArrowRight size={16} />
            </Button>
            <Button id="cta-register-btn" to="/register" variant="secondary" size="lg">
              Create Account
            </Button>
          </div>
        </div>
      </div>
    </section>
  );
}
