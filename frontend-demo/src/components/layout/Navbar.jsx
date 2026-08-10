import { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { cn } from '@/utils/cn'
import { NAV_LINKS } from '@/utils/constants'
import { NeonButton } from '@/components/ui/NeonButton'
import { Menu, X, Shield, Zap } from 'lucide-react'

export function Navbar() {
  const [scrolled, setScrolled] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [activeSection, setActiveSection] = useState('')

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 40)
    window.addEventListener('scroll', handleScroll, { passive: true })
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  const handleNavClick = (href) => {
    setMobileOpen(false)
    const el = document.querySelector(href)
    if (el) {
      const y = el.getBoundingClientRect().top + window.scrollY - 80
      window.__lenis?.scrollTo(y, { duration: 1.4, easing: (t) => 1 - Math.pow(1 - t, 4) })
    }
  }

  return (
    <>
      <motion.nav
        initial={{ y: -80, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 0.8, delay: 0.2, ease: [0.22, 1, 0.36, 1] }}
        className={cn(
          'fixed top-0 left-0 right-0 z-50 transition-all duration-500',
          scrolled
            ? 'glass border-b border-white/[0.06] shadow-[0_4px_30px_rgba(0,0,0,0.5)]'
            : 'bg-transparent'
        )}
      >
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          {/* Logo */}
          <motion.a
            href="#"
            className="flex items-center gap-2.5 group"
            whileHover={{ scale: 1.02 }}
            onClick={(e) => { e.preventDefault(); window.__lenis?.scrollTo(0) }}
          >
            <div className="relative">
              <div className="w-8 h-8 rounded-lg bg-cyber-cyan/10 border border-cyber-cyan/30 flex items-center justify-center group-hover:bg-cyber-cyan/20 group-hover:border-cyber-cyan/50 transition-all duration-300">
                <Shield className="w-4 h-4 text-cyber-cyan" strokeWidth={1.5} />
              </div>
              <div className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-cyber-cyan animate-pulse" />
            </div>
            <span className="font-display font-bold text-lg tracking-tight">
              <span className="text-cyber-text">Shadow</span>
              <span className="text-cyber-cyan">Scan</span>
            </span>
          </motion.a>

          {/* Desktop Nav */}
          <div className="hidden md:flex items-center gap-1">
            {NAV_LINKS.map((link) => (
              <button
                key={link.href}
                onClick={() => handleNavClick(link.href)}
                className="px-4 py-2 text-sm font-medium text-cyber-muted hover:text-cyber-text transition-colors duration-200 rounded-lg hover:bg-white/[0.04] font-display"
              >
                {link.label}
              </button>
            ))}
          </div>

          {/* CTA */}
          <div className="hidden md:flex items-center gap-3">
            <button className="text-sm text-cyber-muted hover:text-cyber-text transition-colors font-display">
              Sign In
            </button>
            <NeonButton
              size="sm"
              variant="primary"
              onClick={() => handleNavClick('#demo')}
              className="group"
            >
              <Zap className="w-3.5 h-3.5 group-hover:animate-pulse" />
              Start Scan
            </NeonButton>
          </div>

          {/* Mobile toggle */}
          <button
            className="md:hidden w-9 h-9 flex items-center justify-center rounded-lg border border-white/10 text-cyber-muted hover:text-cyber-cyan hover:border-cyber-cyan/30 transition-all"
            onClick={() => setMobileOpen(!mobileOpen)}
            aria-label="Toggle menu"
          >
            {mobileOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
          </button>
        </div>
      </motion.nav>

      {/* Mobile Drawer */}
      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.3 }}
            className="fixed top-16 left-0 right-0 z-40 glass border-b border-white/[0.06] px-6 py-6 flex flex-col gap-2"
          >
            {NAV_LINKS.map((link, i) => (
              <motion.button
                key={link.href}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.05 }}
                onClick={() => handleNavClick(link.href)}
                className="w-full text-left px-4 py-3 rounded-lg text-cyber-muted hover:text-cyber-text hover:bg-white/[0.04] transition-all font-display"
              >
                {link.label}
              </motion.button>
            ))}
            <div className="mt-2 pt-4 border-t border-white/[0.06]">
              <NeonButton variant="primary" className="w-full justify-center" onClick={() => handleNavClick('#demo')}>
                <Zap className="w-4 h-4" />
                Start Free Scan
              </NeonButton>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  )
}
