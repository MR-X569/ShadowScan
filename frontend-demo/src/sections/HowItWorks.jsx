import { useRef, useState } from 'react'
import { motion, useInView } from 'framer-motion'
import { Link, Globe, Fingerprint, Zap, Brain, Calculator, FileText } from 'lucide-react'
import { HOW_IT_WORKS_STEPS } from '@/utils/constants'

const ICON_MAP = {
  link: Link,
  globe: Globe,
  fingerprint: Fingerprint,
  zap: Zap,
  brain: Brain,
  calculator: Calculator,
  'file-text': FileText,
}

function PipelineStep({ step, index, isActive, onClick }) {
  const Icon = ICON_MAP[step.icon] ?? Zap

  return (
    <motion.div
      initial={{ opacity: 0, x: -40 }}
      whileInView={{ opacity: 1, x: 0 }}
      viewport={{ once: true, margin: '-60px' }}
      transition={{ duration: 0.6, delay: index * 0.08, ease: [0.22, 1, 0.36, 1] }}
      className="flex gap-5 cursor-pointer group"
      onClick={() => onClick(index)}
    >
      {/* Step node + connector */}
      <div className="flex flex-col items-center">
        <div
          className="relative w-12 h-12 rounded-xl flex items-center justify-center shrink-0 transition-all duration-400 border"
          style={{
            background: isActive ? 'rgba(0,220,229,0.15)' : 'rgba(13,13,13,0.8)',
            borderColor: isActive ? 'rgba(0,220,229,0.5)' : 'rgba(255,255,255,0.08)',
            boxShadow: isActive ? '0 0 20px rgba(0,220,229,0.3)' : 'none',
          }}
        >
          <Icon
            className="w-5 h-5 transition-colors duration-300"
            style={{ color: isActive ? '#00DCE5' : '#849495' }}
            strokeWidth={1.5}
          />
          {/* Step number */}
          <span
            className="absolute -top-2 -right-2 w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-mono font-bold border transition-all duration-300"
            style={{
              background: isActive ? '#00DCE5' : '#1a1a1a',
              borderColor: isActive ? '#00DCE5' : '#3a3a3a',
              color: isActive ? '#050505' : '#849495',
            }}
          >
            {step.step}
          </span>
        </div>

        {/* Connector line */}
        {index < HOW_IT_WORKS_STEPS.length - 1 && (
          <div className="w-px flex-1 mt-2 min-h-[32px]" style={{
            background: isActive
              ? 'linear-gradient(to bottom, rgba(0,220,229,0.5), rgba(0,220,229,0.1))'
              : 'rgba(255,255,255,0.06)',
          }} />
        )}
      </div>

      {/* Content */}
      <div className="pb-6">
        <h3
          className="font-display font-bold text-base mb-1 transition-colors duration-300"
          style={{ color: isActive ? '#E5E2E1' : '#849495' }}
        >
          {step.title}
        </h3>
        <p className="font-display text-sm text-cyber-muted leading-relaxed">{step.description}</p>
      </div>
    </motion.div>
  )
}

export function HowItWorks() {
  const [activeStep, setActiveStep] = useState(0)
  const headerRef = useRef()
  const inView = useInView(headerRef, { once: true, margin: '-80px' })

  return (
    <section id="how-it-works" className="relative py-32 overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 grid-bg opacity-15" />
      <div className="absolute right-0 top-0 bottom-0 w-1/2 pointer-events-none"
        style={{ background: 'radial-gradient(ellipse 60% 80% at 100% 50%, rgba(0,220,229,0.04) 0%, transparent 70%)' }} />

      <div className="max-w-7xl mx-auto px-6">
        {/* Header */}
        <div ref={headerRef} className="text-center mb-20">
          <motion.p
            initial={{ opacity: 0 }}
            animate={inView ? { opacity: 1 } : {}}
            className="section-label mb-4"
          >
            // HOW IT WORKS
          </motion.p>
          <motion.h2
            initial={{ opacity: 0, y: 30 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.8, delay: 0.1 }}
            className="font-display font-black text-4xl md:text-6xl text-cyber-text mb-6"
          >
            From URL to{' '}
            <span className="text-neon-cyan">Report</span> in 7 steps.
          </motion.h2>
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.7, delay: 0.2 }}
            className="text-cyber-muted max-w-xl mx-auto text-lg"
          >
            A multi-stage AI pipeline that goes deeper than any human tester can, 
            faster than any manual process could.
          </motion.p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-start">
          {/* Pipeline steps */}
          <div className="space-y-0">
            {HOW_IT_WORKS_STEPS.map((step, i) => (
              <PipelineStep
                key={step.step}
                step={step}
                index={i}
                isActive={activeStep === i}
                onClick={setActiveStep}
              />
            ))}
          </div>

          {/* Terminal window */}
          <div className="lg:sticky lg:top-28">
            <motion.div
              initial={{ opacity: 0, y: 40 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.8 }}
              className="glass rounded-xl overflow-hidden border border-white/[0.06]"
              style={{ boxShadow: '0 20px 60px rgba(0,0,0,0.5), 0 0 40px rgba(0,220,229,0.05)' }}
            >
              {/* Terminal chrome */}
              <div className="flex items-center gap-2 px-4 py-3 border-b border-white/[0.06] bg-white/[0.02]">
                <div className="w-3 h-3 rounded-full bg-red-500/60" />
                <div className="w-3 h-3 rounded-full bg-yellow-500/60" />
                <div className="w-3 h-3 rounded-full bg-green-500/60" />
                <span className="ml-3 text-xs text-cyber-muted font-mono flex-1">shadowscan.terminal</span>
                <div className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyber-cyan animate-pulse" />
                  <span className="text-[10px] font-mono text-cyber-cyan">LIVE</span>
                </div>
              </div>

              {/* Terminal content */}
              <div className="p-5 min-h-[280px] space-y-2">
                {HOW_IT_WORKS_STEPS.slice(0, activeStep + 1).map((step, i) => (
                  <motion.div
                    key={i}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.3 }}
                  >
                    <p className="font-mono text-xs leading-relaxed">
                      <span className="text-cyber-cyan/40 mr-2">$</span>
                      <span className={i === activeStep ? 'text-cyber-cyan' : 'text-cyber-muted'}>
                        {step.log}
                      </span>
                    </p>
                  </motion.div>
                ))}

                {/* Cursor */}
                <div className="flex items-center gap-1">
                  <span className="text-cyber-cyan/40 font-mono text-xs">$</span>
                  <span className="w-2 h-4 bg-cyber-cyan animate-[blink_1s_ease-in-out_infinite]" />
                </div>
              </div>

              {/* Step navigation */}
              <div className="px-5 pb-5">
                <div className="flex gap-1.5">
                  {HOW_IT_WORKS_STEPS.map((_, i) => (
                    <button
                      key={i}
                      onClick={() => setActiveStep(i)}
                      className="h-1 rounded-full transition-all duration-300 cursor-pointer"
                      style={{
                        width: activeStep === i ? '24px' : '8px',
                        background: activeStep === i ? '#00DCE5' : 'rgba(255,255,255,0.15)',
                      }}
                    />
                  ))}
                </div>
              </div>
            </motion.div>

            {/* Auto-advance hint */}
            <p className="text-center text-cyber-muted/50 text-xs font-mono mt-4">
              Click any step to inspect the pipeline
            </p>
          </div>
        </div>
      </div>
    </section>
  )
}
