import { motion } from 'framer-motion'
import { Shield, Github, Twitter, Linkedin, ArrowUpRight, Zap } from 'lucide-react'
import { NAV_LINKS } from '@/utils/constants'
import { NeonButton } from '@/components/ui/NeonButton'

const FOOTER_LINKS = {
  Product: ['Features', 'How It Works', 'Pricing', 'Changelog'],
  Resources: ['Documentation', 'API Reference', 'CVE Database', 'Blog'],
  Company: ['About', 'Security', 'Privacy Policy', 'Terms of Service'],
}

const SOCIALS = [
  { icon: Github,   href: '#', label: 'GitHub' },
  { icon: Twitter,  href: '#', label: 'Twitter/X' },
  { icon: Linkedin, href: '#', label: 'LinkedIn' },
]

export function FooterSection() {
  return (
    <footer className="relative overflow-hidden border-t border-white/[0.06]">
      {/* Radial glow */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] pointer-events-none"
        style={{ background: 'radial-gradient(ellipse at top, rgba(0,220,229,0.06) 0%, transparent 70%)' }} />
      <div className="absolute inset-0 grid-bg opacity-20" />

      {/* CTA banner */}
      <div className="relative max-w-7xl mx-auto px-6 py-20 border-b border-white/[0.06]">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.8 }}
          className="glass-card rounded-2xl p-10 md:p-14 text-center relative overflow-hidden"
          style={{ boxShadow: '0 0 60px rgba(0,220,229,0.06)' }}
        >
          {/* Corner accents */}
          <div className="absolute top-0 left-0 w-20 h-20"
            style={{ background: 'radial-gradient(circle at top left, rgba(0,220,229,0.12), transparent 70%)' }} />
          <div className="absolute bottom-0 right-0 w-32 h-32"
            style={{ background: 'radial-gradient(circle at bottom right, rgba(182,0,248,0.1), transparent 70%)' }} />

          <p className="section-label mb-4">// GET STARTED</p>
          <h2 className="font-display font-black text-3xl md:text-5xl text-cyber-text mb-4">
            Your website is being{' '}
            <span className="text-neon-cyan">watched right now.</span>
          </h2>
          <p className="text-cyber-muted max-w-lg mx-auto mb-8 text-lg">
            Every second your vulnerabilities are undetected is a second attackers
            have the advantage. Start your free scan today.
          </p>
          <div className="flex flex-wrap gap-4 justify-center">
            <NeonButton size="lg" variant="primary" id="footer-cta-scan">
              <Zap className="w-5 h-5" />
              Start Free Scan
            </NeonButton>
            <NeonButton size="lg" variant="ghost" id="footer-cta-docs">
              View Documentation
              <ArrowUpRight className="w-4 h-4" />
            </NeonButton>
          </div>
        </motion.div>
      </div>

      {/* Main footer */}
      <div className="relative max-w-7xl mx-auto px-6 py-16">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-12">
          {/* Brand column */}
          <div className="lg:col-span-2">
            <div className="flex items-center gap-2.5 mb-4">
              <div className="w-8 h-8 rounded-lg bg-cyber-cyan/10 border border-cyber-cyan/30 flex items-center justify-center">
                <Shield className="w-4 h-4 text-cyber-cyan" strokeWidth={1.5} />
              </div>
              <span className="font-display font-bold text-lg">
                <span className="text-cyber-text">Shadow</span>
                <span className="text-cyber-cyan">Scan</span>
              </span>
            </div>
            <p className="text-cyber-muted text-sm font-display leading-relaxed mb-6 max-w-xs">
              AI-powered website security scanner. Find vulnerabilities before attackers do.
            </p>
            {/* Social links */}
            <div className="flex gap-3">
              {SOCIALS.map(({ icon: Icon, href, label }) => (
                <a
                  key={label}
                  href={href}
                  aria-label={label}
                  className="w-9 h-9 rounded-lg border border-white/[0.08] flex items-center justify-center text-cyber-muted hover:text-cyber-cyan hover:border-cyber-cyan/30 transition-all duration-200"
                >
                  <Icon className="w-4 h-4" />
                </a>
              ))}
            </div>
          </div>

          {/* Link columns */}
          {Object.entries(FOOTER_LINKS).map(([section, links]) => (
            <div key={section}>
              <p className="font-mono text-xs text-cyber-muted tracking-widest uppercase mb-4">{section}</p>
              <ul className="space-y-2.5">
                {links.map((link) => (
                  <li key={link}>
                    <a
                      href="#"
                      className="font-display text-sm text-cyber-muted hover:text-cyber-cyan transition-colors duration-200"
                    >
                      {link}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        {/* Bottom bar */}
        <div className="mt-16 pt-8 border-t border-white/[0.06] flex flex-col md:flex-row items-center justify-between gap-4">
          <p className="font-mono text-xs text-cyber-muted">
            © 2024 ShadowScan. All rights reserved.
          </p>
          <div className="flex items-center gap-2 font-mono text-xs text-cyber-muted">
            <span>Built with</span>
            <span className="text-red-400">♥</span>
            <span>and</span>
            <span className="text-cyber-cyan">neon.</span>
          </div>
          <div className="flex gap-4">
            {['Privacy', 'Terms', 'Security'].map((l) => (
              <a key={l} href="#" className="font-mono text-xs text-cyber-muted hover:text-cyber-cyan transition-colors">
                {l}
              </a>
            ))}
          </div>
        </div>
      </div>
    </footer>
  )
}
