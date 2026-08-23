import { ArrowRight, Lock } from 'lucide-react';
import Button from '@/components/ui/Button';

export default function HeroSection() {
  return (
    <section
      id="home"
      className="relative flex min-h-screen items-center justify-center overflow-hidden bg-hero-glow"
    >
      {/* Background grid */}
      <div
        className="pointer-events-none absolute inset-0 bg-grid-pattern bg-grid opacity-100"
        aria-hidden="true"
      />

      {/* Radial glow accent */}
      <div
        className="pointer-events-none absolute left-1/2 top-0 h-[600px] w-[900px] -translate-x-1/2 rounded-full opacity-20"
        style={{
          background:
            'radial-gradient(ellipse at center, rgba(34,211,238,0.25) 0%, transparent 70%)',
          filter: 'blur(40px)',
        }}
        aria-hidden="true"
      />

      {/* Content */}
      <div className="relative z-10 mx-auto max-w-4xl px-4 py-32 text-center sm:px-6 lg:px-8">
        {/* Badge */}
        <div className="mb-8 inline-flex items-center gap-2 rounded-full border border-brand-cyan/20 bg-brand-cyan/5 px-4 py-1.5">
          <Lock size={13} className="text-brand-cyan" />
          <span className="font-mono text-xs font-medium tracking-widest text-brand-cyan uppercase">
            Website Vulnerability Scanner
          </span>
        </div>

        {/* Heading */}
        <h1 className="mb-6 text-5xl font-extrabold tracking-tight text-brand-text sm:text-6xl lg:text-7xl">
          Shadow<span className="text-brand-cyan">Scan</span>
        </h1>

        {/* Subtitle */}
        <p className="mb-4 text-xl font-medium text-brand-subtle sm:text-2xl">
          Website Vulnerability Scanner
        </p>

        {/* Description */}
        <p className="mx-auto mb-12 max-w-2xl text-base leading-relaxed text-brand-subtle sm:text-lg">
          ShadowScan helps users analyze websites for security weaknesses through automated
          vulnerability assessments and generates detailed security reports.
        </p>

        {/* CTA Buttons */}
        <div className="flex flex-col items-center justify-center gap-4 sm:flex-row">
          <Button id="hero-login-btn" to="/login" variant="primary" size="lg">
            Login
            <ArrowRight size={16} />
          </Button>
          <Button id="hero-signup-btn" to="/register" variant="outline" size="lg">
            Sign Up
          </Button>
        </div>
      </div>
    </section>
  );
}
