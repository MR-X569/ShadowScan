import { useRef, useState } from 'react'
import { motion, AnimatePresence, useInView } from 'framer-motion'
import { Plus, Minus } from 'lucide-react'
import { FAQS } from '@/utils/constants'

function FAQItem({ faq, index }) {
  const [open, setOpen] = useState(false)

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-40px' }}
      transition={{ duration: 0.5, delay: index * 0.06 }}
      className={`border rounded-xl overflow-hidden transition-all duration-300 ${
        open
          ? 'border-cyber-cyan/25 bg-cyber-cyan/[0.03]'
          : 'border-white/[0.06] bg-transparent hover:border-white/[0.1]'
      }`}
    >
      <button
        className="w-full flex items-center justify-between gap-4 px-6 py-5 text-left"
        onClick={() => setOpen(!open)}
        id={`faq-${index}`}
        aria-expanded={open}
      >
        <span className={`font-display font-semibold text-base transition-colors duration-300 ${
          open ? 'text-cyber-cyan' : 'text-cyber-text'
        }`}>
          {faq.q}
        </span>
        <div
          className={`shrink-0 w-7 h-7 rounded-lg flex items-center justify-center transition-all duration-300 ${
            open
              ? 'bg-cyber-cyan/15 border border-cyber-cyan/30'
              : 'bg-white/[0.05] border border-white/[0.08]'
          }`}
        >
          <motion.div animate={{ rotate: open ? 180 : 0 }} transition={{ duration: 0.3 }}>
            {open
              ? <Minus className="w-3.5 h-3.5 text-cyber-cyan" />
              : <Plus className="w-3.5 h-3.5 text-cyber-muted" />
            }
          </motion.div>
        </div>
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
          >
            <div className="px-6 pb-5">
              <div className="w-full h-px bg-cyber-cyan/10 mb-4" />
              <p className="font-display text-sm text-cyber-muted leading-relaxed">{faq.a}</p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

export function FAQ() {
  const headerRef = useRef()
  const inView = useInView(headerRef, { once: true })

  return (
    <section id="faq" className="relative py-32 overflow-hidden">
      <div className="absolute inset-0 grid-bg opacity-20" />
      <div className="absolute inset-0"
        style={{ background: 'radial-gradient(ellipse 60% 80% at 50% 100%, rgba(182,0,248,0.05) 0%, transparent 60%)' }} />

      <div className="max-w-4xl mx-auto px-6">
        {/* Header */}
        <div ref={headerRef} className="text-center mb-16">
          <motion.p
            initial={{ opacity: 0 }}
            animate={inView ? { opacity: 1 } : {}}
            className="section-label mb-4"
          >
            // FAQ
          </motion.p>
          <motion.h2
            initial={{ opacity: 0, y: 30 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.8, delay: 0.1 }}
            className="font-display font-black text-4xl md:text-5xl text-cyber-text mb-6"
          >
            Got{' '}
            <span className="text-neon-cyan">questions?</span>
          </motion.h2>
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.7, delay: 0.2 }}
            className="text-cyber-muted max-w-lg mx-auto"
          >
            Everything you need to know about ShadowScan. Can't find your answer?
            <span className="text-cyber-cyan"> Contact our security team.</span>
          </motion.p>
        </div>

        {/* Accordion */}
        <div className="space-y-3">
          {FAQS.map((faq, i) => (
            <FAQItem key={i} faq={faq} index={i} />
          ))}
        </div>
      </div>
    </section>
  )
}
