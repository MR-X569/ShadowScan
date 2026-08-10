import { useRef, useState } from 'react'
import { motion, useInView } from 'framer-motion'
import {
  Scan, ShieldAlert, Cpu, Gauge, FileText, History,
} from 'lucide-react'
import { FEATURES } from '@/utils/constants'
import { CyberBadge } from '@/components/ui/CyberBadge'

const ICON_MAP = {
  scan:        Scan,
  'shield-alert': ShieldAlert,
  cpu:         Cpu,
  gauge:       Gauge,
  'file-text': FileText,
  history:     History,
}

const BADGE_COLOR_MAP = {
  CORE:         'cyan',
  SECURITY:     'red',
  INTELLIGENCE: 'purple',
  AI:           'cyan',
  EXPORT:       'purple',
  ANALYTICS:    'green',
}

function FeatureCard({ feature, index }) {
  const [hovered, setHovered] = useState(false)
  const [tilt, setTilt] = useState({ x: 0, y: 0 })
  const cardRef = useRef()
  const inView = useInView(cardRef, { once: true, margin: '-80px' })

  const Icon = ICON_MAP[feature.icon] ?? Scan
  const badgeColor = BADGE_COLOR_MAP[feature.tag] ?? 'cyan'

  const handleMouseMove = (e) => {
    if (!cardRef.current) return
    const rect = cardRef.current.getBoundingClientRect()
    const x = ((e.clientX - rect.left) / rect.width - 0.5) * 20
    const y = ((e.clientY - rect.top) / rect.height - 0.5) * -20
    setTilt({ x, y })
  }

  const resetTilt = () => {
    setTilt({ x: 0, y: 0 })
    setHovered(false)
  }

  const cyanHex = '#00DCE5'
  const purpleHex = '#B600F8'
  const accentColor = feature.color === '#B600F8' ? purpleHex : cyanHex

  return (
    <motion.div
      ref={cardRef}
      initial={{ opacity: 0, y: 60 }}
      animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.7, delay: index * 0.08, ease: [0.22, 1, 0.36, 1] }}
      style={{
        perspective: 800,
        transformStyle: 'preserve-3d',
      }}
    >
      <div
        ref={cardRef}
        className="glass-card rounded-xl p-6 h-full relative overflow-hidden cursor-default transition-all duration-200"
        style={{
          transform: hovered
            ? `rotateX(${tilt.y}deg) rotateY(${tilt.x}deg) translateZ(10px)`
            : 'rotateX(0) rotateY(0) translateZ(0)',
          boxShadow: hovered
            ? `0 30px 60px rgba(0,0,0,0.5), 0 0 30px ${accentColor}18`
            : '0 8px 32px rgba(0,0,0,0.4)',
          borderColor: hovered ? `${accentColor}28` : 'rgba(255,255,255,0.06)',
          transition: 'transform 0.15s ease-out, box-shadow 0.3s, border-color 0.3s',
        }}
        onMouseEnter={() => setHovered(true)}
        onMouseMove={handleMouseMove}
        onMouseLeave={resetTilt}
      >
        {/* Corner glow */}
        <div
          className="absolute -top-10 -right-10 w-40 h-40 rounded-full pointer-events-none transition-opacity duration-500"
          style={{
            background: `radial-gradient(circle, ${accentColor}18 0%, transparent 70%)`,
            opacity: hovered ? 1 : 0,
          }}
        />

        {/* Tag */}
        <div className="mb-4">
          <CyberBadge color={badgeColor}>{feature.tag}</CyberBadge>
        </div>

        {/* Icon */}
        <div
          className="w-14 h-14 rounded-xl flex items-center justify-center mb-5 transition-all duration-300"
          style={{
            background: `${accentColor}12`,
            border: `1px solid ${accentColor}28`,
            boxShadow: hovered ? `0 0 20px ${accentColor}28` : 'none',
            transform: hovered ? 'translateZ(20px) scale(1.05)' : 'translateZ(0) scale(1)',
          }}
        >
          <Icon
            className="w-7 h-7 transition-all duration-300"
            style={{ color: accentColor }}
            strokeWidth={1.5}
          />
        </div>

        <h3 className="font-display font-bold text-lg text-cyber-text mb-3">{feature.title}</h3>
        <p className="font-display text-sm text-cyber-muted leading-relaxed">{feature.description}</p>

        {/* Bottom trace line */}
        <div
          className="absolute bottom-0 left-0 h-[1px] transition-all duration-700"
          style={{
            width: hovered ? '100%' : '0%',
            background: `linear-gradient(to right, ${accentColor}, transparent)`,
          }}
        />

        {/* Scan line */}
        {hovered && (
          <div
            className="absolute left-0 right-0 h-px pointer-events-none"
            style={{
              background: `linear-gradient(to right, transparent, ${accentColor}40, transparent)`,
              animation: 'scanV 1.5s linear infinite',
              top: 0,
            }}
          />
        )}
      </div>
    </motion.div>
  )
}

export function Features() {
  const headerRef = useRef()
  const inView = useInView(headerRef, { once: true, margin: '-80px' })

  return (
    <section id="features" className="relative py-32 overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 dot-bg opacity-30" />
      <div className="absolute left-0 top-1/2 -translate-y-1/2 w-[500px] h-[500px] pointer-events-none"
        style={{ background: 'radial-gradient(circle, rgba(182,0,248,0.06) 0%, transparent 70%)' }} />
      <div className="absolute right-0 top-1/4 w-[400px] h-[400px] pointer-events-none"
        style={{ background: 'radial-gradient(circle, rgba(0,220,229,0.05) 0%, transparent 70%)' }} />

      <div className="max-w-7xl mx-auto px-6">
        {/* Header */}
        <div ref={headerRef} className="text-center mb-16">
          <motion.p
            initial={{ opacity: 0 }}
            animate={inView ? { opacity: 1 } : {}}
            className="section-label mb-4"
          >
            // CAPABILITIES
          </motion.p>
          <motion.h2
            initial={{ opacity: 0, y: 30 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.8, delay: 0.1, ease: [0.22, 1, 0.36, 1] }}
            className="font-display font-black text-4xl md:text-6xl text-cyber-text mb-6"
          >
            Every attack vector.{' '}
            <span className="text-neon-cyan">Covered.</span>
          </motion.h2>
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.7, delay: 0.2 }}
            className="text-cyber-muted max-w-xl mx-auto text-lg font-display"
          >
            Six specialized modules work in parallel to give you complete
            security coverage — from discovery to remediation.
          </motion.p>
        </div>

        {/* Feature grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {FEATURES.map((feature, i) => (
            <FeatureCard key={feature.id} feature={feature} index={i} />
          ))}
        </div>
      </div>
    </section>
  )
}
