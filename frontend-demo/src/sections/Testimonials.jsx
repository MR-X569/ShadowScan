import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'
import { Star } from 'lucide-react'
import { TESTIMONIALS } from '@/utils/constants'

function TestimonialCard({ t }) {
  return (
    <div
      className="shrink-0 w-80 glass-card rounded-xl p-5 mx-3 cursor-default hover:border-cyber-cyan/15 transition-colors duration-300"
      style={{ boxShadow: '0 8px 32px rgba(0,0,0,0.3)' }}
    >
      {/* Stars */}
      <div className="flex gap-1 mb-4">
        {Array.from({ length: t.rating }).map((_, i) => (
          <Star key={i} className="w-3.5 h-3.5 fill-cyber-cyan text-cyber-cyan" />
        ))}
      </div>

      <p className="font-display text-sm text-cyber-muted leading-relaxed mb-5">"{t.quote}"</p>

      <div className="flex items-center gap-3">
        <div
          className="w-9 h-9 rounded-full flex items-center justify-center font-display font-bold text-xs shrink-0"
          style={{
            background: `${t.color}20`,
            border: `1px solid ${t.color}40`,
            color: t.color,
          }}
        >
          {t.avatar}
        </div>
        <div>
          <p className="font-display font-semibold text-sm text-cyber-text">{t.name}</p>
          <p className="font-mono text-[11px] text-cyber-muted">{t.role}</p>
        </div>
      </div>
    </div>
  )
}

function MarqueeRow({ items, reverse = false, speed = 30 }) {
  const doubled = [...items, ...items]
  return (
    <div className="overflow-hidden">
      <motion.div
        className="flex"
        animate={{ x: reverse ? ['0%', '50%'] : ['0%', '-50%'] }}
        transition={{ duration: speed, repeat: Infinity, ease: 'linear' }}
        style={{ width: 'max-content' }}
      >
        {doubled.map((t, i) => (
          <TestimonialCard key={i} t={t} />
        ))}
      </motion.div>
    </div>
  )
}

export function Testimonials() {
  const headerRef = useRef()
  const inView = useInView(headerRef, { once: true })

  return (
    <section id="testimonials" className="relative py-32 overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0"
        style={{ background: 'radial-gradient(ellipse 60% 80% at 50% 50%, rgba(0,220,229,0.04) 0%, transparent 70%)' }} />

      {/* Fade edges */}
      <div className="absolute inset-y-0 left-0 w-32 z-10 pointer-events-none"
        style={{ background: 'linear-gradient(to right, #050505, transparent)' }} />
      <div className="absolute inset-y-0 right-0 w-32 z-10 pointer-events-none"
        style={{ background: 'linear-gradient(to left, #050505, transparent)' }} />

      <div className="max-w-7xl mx-auto px-6 mb-16">
        <div ref={headerRef} className="text-center">
          <motion.p
            initial={{ opacity: 0 }}
            animate={inView ? { opacity: 1 } : {}}
            className="section-label mb-4"
          >
            // TESTIMONIALS
          </motion.p>
          <motion.h2
            initial={{ opacity: 0, y: 30 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.8, delay: 0.1 }}
            className="font-display font-black text-4xl md:text-6xl text-cyber-text mb-6"
          >
            Trusted by security{' '}
            <span className="text-neon-cyan">professionals.</span>
          </motion.h2>
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.7, delay: 0.2 }}
            className="text-cyber-muted max-w-xl mx-auto"
          >
            From solo pentesters to enterprise CISOs — ShadowScan is the tool
            the security community trusts most.
          </motion.p>
        </div>
      </div>

      {/* Marquee rows */}
      <div className="space-y-5">
        <MarqueeRow items={TESTIMONIALS} reverse={false} speed={35} />
        <MarqueeRow items={[...TESTIMONIALS].reverse()} reverse={true} speed={28} />
      </div>
    </section>
  )
}
