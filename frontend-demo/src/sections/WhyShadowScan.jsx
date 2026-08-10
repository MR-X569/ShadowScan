import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'
import { Shield, Zap, Brain, Lock } from 'lucide-react'
import { GlassCard } from '@/components/ui/GlassCard'
import { STATS } from '@/utils/constants'

const WHY_CARDS = [
  {
    icon: Brain,
    title: 'AI-First Architecture',
    description: 'Our neural engine is trained on 10 million+ real-world vulnerabilities. It understands context, not just patterns — eliminating false positives that plague traditional scanners.',
    accent: '#00DCE5',
    delay: 0.1,
  },
  {
    icon: Zap,
    title: 'Lightning Fast',
    description: 'Complete full-stack security audits in under 2 minutes. Our parallel scanning engine simultaneously tests thousands of attack vectors without slowing down your site.',
    accent: '#B600F8',
    delay: 0.2,
  },
  {
    icon: Shield,
    title: 'OWASP Certified Coverage',
    description: 'Full coverage of OWASP Top 10, SANS Top 25, and NIST frameworks. Every finding includes CVE references, CVSS scores, and step-by-step remediation guides.',
    accent: '#00F5FF',
    delay: 0.3,
  },
  {
    icon: Lock,
    title: 'Zero Trust Approach',
    description: 'We scan as an adversary would. Our engine simulates real-world attack chains — not just isolated tests — to surface vulnerabilities that matter in practice.',
    accent: '#00DCE5',
    delay: 0.4,
  },
]

function StatCounter({ value, suffix, label, prefix, index }) {
  const ref = useRef()
  const inView = useInView(ref, { once: true, margin: '-50px' })

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, y: 30 }}
      animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.7, delay: index * 0.1, ease: [0.22, 1, 0.36, 1] }}
      className="flex flex-col items-center text-center"
    >
      <div className="font-display font-black text-5xl md:text-6xl mb-2 tabular-nums gradient-text-cyan">
        {prefix}{value}{suffix}
      </div>
      <div className="font-mono text-xs text-cyber-muted tracking-widest uppercase">{label}</div>
    </motion.div>
  )
}

function WhyCard({ icon: Icon, title, description, accent, delay, index }) {
  const ref = useRef()
  const inView = useInView(ref, { once: true, margin: '-60px' })

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, y: 50, rotateX: 10 }}
      animate={inView ? { opacity: 1, y: 0, rotateX: 0 } : {}}
      transition={{ duration: 0.8, delay, ease: [0.22, 1, 0.36, 1] }}
      className="group"
      style={{ perspective: 1000 }}
    >
      <GlassCard className="p-6 h-full relative overflow-hidden cursor-default">
        {/* Accent corner */}
        <div
          className="absolute top-0 right-0 w-24 h-24 opacity-10 group-hover:opacity-20 transition-opacity duration-500"
          style={{
            background: `radial-gradient(circle at top right, ${accent}, transparent 70%)`,
          }}
        />

        {/* Icon */}
        <div
          className="w-12 h-12 rounded-xl flex items-center justify-center mb-5 group-hover:scale-110 transition-transform duration-300"
          style={{
            background: `rgba(${accent === '#00DCE5' ? '0,220,229' : accent === '#B600F8' ? '182,0,248' : '0,245,255'}, 0.12)`,
            border: `1px solid ${accent}30`,
          }}
        >
          <Icon className="w-6 h-6" style={{ color: accent }} strokeWidth={1.5} />
        </div>

        <h3 className="font-display font-bold text-lg text-cyber-text mb-3">{title}</h3>
        <p className="font-display text-sm text-cyber-muted leading-relaxed">{description}</p>

        {/* Bottom accent line — appears on hover */}
        <div
          className="absolute bottom-0 left-0 h-[2px] w-0 group-hover:w-full transition-all duration-500"
          style={{ background: `linear-gradient(to right, ${accent}, transparent)` }}
        />
      </GlassCard>
    </motion.div>
  )
}

export function WhyShadowScan() {
  const ref = useRef()
  const inView = useInView(ref, { once: true, margin: '-100px' })

  return (
    <section id="why" className="relative py-32 overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 grid-bg opacity-20" />
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] pointer-events-none"
        style={{ background: 'radial-gradient(ellipse at top, rgba(0,220,229,0.06) 0%, transparent 70%)' }} />

      <div className="max-w-7xl mx-auto px-6">
        {/* Header */}
        <div ref={ref} className="text-center mb-20">
          <motion.p
            initial={{ opacity: 0 }}
            animate={inView ? { opacity: 1 } : {}}
            transition={{ duration: 0.5 }}
            className="section-label mb-4"
          >
            // WHY SHADOWSCAN
          </motion.p>
          <motion.h2
            initial={{ opacity: 0, y: 30 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.8, delay: 0.1, ease: [0.22, 1, 0.36, 1] }}
            className="font-display font-black text-4xl md:text-6xl text-cyber-text mb-6"
          >
            Security that thinks{' '}
            <span className="text-neon-cyan">like a hacker.</span>
          </motion.h2>
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.7, delay: 0.2 }}
            className="text-cyber-muted max-w-2xl mx-auto text-lg font-display leading-relaxed"
          >
            Most scanners check boxes. ShadowScan thinks like an attacker —
            finding vulnerabilities that hide in the shadows between conventional checks.
          </motion.p>
        </div>

        {/* Stats row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mb-20">
          {STATS.map((stat, i) => (
            <StatCounter key={stat.label} {...stat} index={i} />
          ))}
        </div>

        {/* Divider */}
        <div className="h-px bg-gradient-to-r from-transparent via-cyber-cyan/20 to-transparent mb-20" />

        {/* Cards grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {WHY_CARDS.map((card, i) => (
            <WhyCard key={card.title} {...card} index={i} />
          ))}
        </div>
      </div>
    </section>
  )
}
