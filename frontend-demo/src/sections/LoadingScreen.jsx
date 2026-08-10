import { useEffect, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import gsap from 'gsap'
import { Shield } from 'lucide-react'

const BOOT_LINES = [
  '[INIT] ShadowScan AI Engine v4.2.0',
  '[LOAD] Loading threat intelligence database...',
  '[LOAD] Initializing OWASP scanner modules...',
  '[LOAD] Calibrating AI neural networks...',
  '[LOAD] Connecting to global CVE feed...',
  '[INIT] Vulnerability detection engine: ONLINE',
  '[READY] All systems operational.',
]

export function LoadingScreen({ onComplete }) {
  const [progress, setProgress] = useState(0)
  const [lines, setLines] = useState([])
  const [done, setDone] = useState(false)
  const progressRef = useRef({ value: 0 })
  const barRef = useRef()
  const counterRef = useRef()

  useEffect(() => {
    // Animate progress counter with GSAP
    const tl = gsap.timeline({
      onUpdate: () => {
        setProgress(Math.round(progressRef.current.value))
      },
      onComplete: () => {
        onComplete?.()
        setTimeout(() => setDone(true), 300)
      },
    })

    tl.to(progressRef.current, {
      value: 100,
      duration: 2.8,
      ease: 'power2.inOut',
    })

    // Stagger boot lines
    let lineIndex = 0
    const lineInterval = setInterval(() => {
      if (lineIndex < BOOT_LINES.length) {
        setLines((prev) => [...prev, BOOT_LINES[lineIndex]])
        lineIndex++
      } else {
        clearInterval(lineInterval)
      }
    }, 330)

    return () => {
      tl.kill()
      clearInterval(lineInterval)
    }
  }, [])

  return (
    <AnimatePresence onExitComplete={onComplete}>
      {!done && (
        <motion.div
          key="loading"
          initial={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.6, ease: 'easeInOut' }}
          className="fixed inset-0 z-[100] bg-cyber-bg flex flex-col items-center justify-center overflow-hidden"
        >
          {/* Background grid */}
          <div className="absolute inset-0 grid-bg opacity-40" />

          {/* Radial glow */}
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <div className="w-[600px] h-[600px] rounded-full"
              style={{ background: 'radial-gradient(circle, rgba(0,220,229,0.08) 0%, transparent 70%)' }} />
          </div>

          {/* Logo */}
          <motion.div
            initial={{ opacity: 0, scale: 0.5 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
            className="flex flex-col items-center gap-4 mb-12"
          >
            <div className="relative">
              <div className="w-20 h-20 rounded-2xl border border-cyber-cyan/40 bg-cyber-cyan/10 flex items-center justify-center shadow-neon-cyan">
                <Shield className="w-10 h-10 text-cyber-cyan" strokeWidth={1} />
              </div>
              {/* Rotating ring */}
              <div className="absolute inset-[-8px] rounded-[28px] border border-cyber-cyan/20 animate-spin-slow" />
              <div className="absolute inset-[-16px] rounded-[36px] border border-cyber-purple/10 animate-spin-slow" style={{ animationDirection: 'reverse', animationDuration: '12s' }} />
            </div>
            <div className="text-center">
              <h1 className="text-3xl font-display font-bold tracking-tight">
                <span className="text-cyber-text">Shadow</span>
                <span className="text-cyber-cyan">Scan</span>
              </h1>
              <p className="text-cyber-muted font-mono text-xs mt-1 tracking-widest">AI SECURITY PLATFORM</p>
            </div>
          </motion.div>

          {/* Terminal boot sequence */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.3 }}
            className="w-full max-w-md mb-8 px-6"
          >
            <div className="glass rounded-lg p-4 border border-cyber-cyan/10">
              <div className="flex items-center gap-2 mb-3 pb-2 border-b border-white/[0.05]">
                <div className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
                <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/60" />
                <div className="w-2.5 h-2.5 rounded-full bg-green-500/60" />
                <span className="ml-2 text-xs text-cyber-muted font-mono">shadowscan.boot</span>
              </div>
              <div className="space-y-1 min-h-[140px]">
                {lines.map((line, i) => (
                  <motion.p
                    key={i}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.2 }}
                    className="font-mono text-[11px] leading-relaxed"
                  >
                    <span className={line.startsWith('[READY]') ? 'text-cyber-cyan' : line.startsWith('[INIT]') ? 'text-cyber-purple' : 'text-cyber-muted'}>
                      {line}
                    </span>
                  </motion.p>
                ))}
                <span className="inline-block w-2 h-3 bg-cyber-cyan animate-[blink_1s_ease-in-out_infinite]" />
              </div>
            </div>
          </motion.div>

          {/* Progress bar */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.4 }}
            className="w-full max-w-md px-6"
          >
            <div className="flex justify-between mb-2">
              <span className="font-mono text-xs text-cyber-muted">INITIALIZING</span>
              <span className="font-mono text-xs text-cyber-cyan" ref={counterRef}>{progress}%</span>
            </div>
            <div className="h-[2px] bg-white/5 rounded-full overflow-hidden">
              <motion.div
                className="h-full bg-gradient-to-r from-cyber-cyan to-cyber-purple rounded-full"
                style={{ width: `${progress}%`, boxShadow: '0 0 10px rgba(0,220,229,0.6)' }}
              />
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
