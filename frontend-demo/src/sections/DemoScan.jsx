import { useRef, useState, useEffect } from 'react'
import { motion, useInView, AnimatePresence } from 'framer-motion'
import { Search, Zap, AlertTriangle, CheckCircle, X } from 'lucide-react'
import { NeonButton } from '@/components/ui/NeonButton'
import { FAKE_VULNERABILITIES, SCAN_PHASES } from '@/utils/constants'
import { CyberBadge } from '@/components/ui/CyberBadge'

const SEVERITY_COLORS = {
  CRITICAL: { badge: 'red',    color: '#ef4444', bg: 'rgba(239,68,68,0.08)' },
  HIGH:     { badge: 'red',    color: '#f97316', bg: 'rgba(249,115,22,0.08)' },
  MEDIUM:   { badge: 'yellow', color: '#eab308', bg: 'rgba(234,179,8,0.08)' },
  LOW:      { badge: 'green',  color: '#22c55e', bg: 'rgba(34,197,94,0.08)' },
}

function RadarSweep() {
  return (
    <div className="relative w-full h-full flex items-center justify-center">
      {/* Rings */}
      {[60, 120, 180, 230].map((r, i) => (
        <div
          key={i}
          className="absolute rounded-full border border-cyber-cyan/10"
          style={{ width: r, height: r }}
        />
      ))}
      {/* Center dot */}
      <div className="absolute w-2 h-2 rounded-full bg-cyber-cyan shadow-neon-sm" />
      {/* Cross hairs */}
      <div className="absolute w-full h-px bg-cyber-cyan/10" />
      <div className="absolute w-px h-full bg-cyber-cyan/10" />
      {/* Sweep */}
      <div
        className="absolute w-full h-full animate-radar origin-center"
        style={{
          background: 'conic-gradient(from 0deg, transparent 80%, rgba(0,220,229,0.15) 95%, transparent 100%)',
        }}
      />
    </div>
  )
}

function SecurityScoreGauge({ score }) {
  const color = score >= 70 ? '#22c55e' : score >= 40 ? '#eab308' : '#ef4444'
  const label = score >= 70 ? 'GOOD' : score >= 40 ? 'AT RISK' : 'CRITICAL'
  const circumference = 2 * Math.PI * 45
  const dash = (score / 100) * circumference

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative">
        <svg width="120" height="120" viewBox="0 0 120 120" className="-rotate-90">
          <circle cx="60" cy="60" r="45" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="8" />
          <motion.circle
            cx="60" cy="60" r="45"
            fill="none"
            stroke={color}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: circumference - dash }}
            transition={{ duration: 1.5, ease: 'easeOut' }}
            style={{ filter: `drop-shadow(0 0 6px ${color})` }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <motion.span
            className="font-display font-black text-3xl"
            style={{ color }}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5 }}
          >
            {score}
          </motion.span>
          <span className="font-mono text-[10px] text-cyber-muted">/100</span>
        </div>
      </div>
      <div>
        <span className="font-mono text-xs" style={{ color }}>{label}</span>
      </div>
    </div>
  )
}

export function DemoScan() {
  const [url, setUrl] = useState('')
  const [phase, setPhase] = useState('idle') // idle | scanning | done
  const [scanProgress, setScanProgress] = useState(0)
  const [currentPhaseLabel, setCurrentPhaseLabel] = useState('')
  const [logs, setLogs] = useState([])
  const [vulns, setVulns] = useState([])
  const [score, setScore] = useState(0)
  const [phaseIndex, setPhaseIndex] = useState(0)
  const logRef = useRef()
  const headerRef = useRef()
  const inView = useInView(headerRef, { once: true })

  const appendLog = (text) => {
    setLogs((prev) => [...prev, { text, ts: new Date().toISOString().slice(11, 19) }])
    setTimeout(() => {
      if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
    }, 50)
  }

  const runScan = async () => {
    if (!url.trim() || phase === 'scanning') return

    const target = url.startsWith('http') ? url : `https://${url}`

    setPhase('scanning')
    setScanProgress(0)
    setLogs([])
    setVulns([])
    setScore(0)
    setPhaseIndex(0)

    appendLog(`[INIT] Target: ${target}`)
    appendLog(`[INIT] Starting AI scan engine...`)

    let progress = 0
    let phaseIdx = 0

    for (const p of SCAN_PHASES) {
      setCurrentPhaseLabel(p.label)
      appendLog(`[SCAN] ${p.label}`)
      await new Promise((r) => setTimeout(r, p.duration))
      progress += 100 / SCAN_PHASES.length
      setScanProgress(Math.min(Math.round(progress), 98))
      phaseIdx++
      setPhaseIndex(phaseIdx)
    }

    // Reveal vulnerabilities one by one
    appendLog('[ANALYSIS] Processing findings...')
    for (let i = 0; i < FAKE_VULNERABILITIES.length; i++) {
      const v = FAKE_VULNERABILITIES[i]
      await new Promise((r) => setTimeout(r, 400))
      appendLog(`[${v.severity}] ${v.name} at ${v.location}`)
      setVulns((prev) => [...prev, v])
    }

    await new Promise((r) => setTimeout(r, 500))
    setScanProgress(100)
    setScore(34)
    appendLog('[COMPLETE] Scan finished. 6 vulnerabilities found.')
    setPhase('done')
  }

  const reset = () => {
    setPhase('idle')
    setUrl('')
    setScanProgress(0)
    setLogs([])
    setVulns([])
    setScore(0)
  }

  return (
    <section id="demo" className="relative py-32 overflow-hidden">
      {/* Background radar */}
      <div className="absolute inset-0 flex items-center justify-end pointer-events-none overflow-hidden">
        <div className="w-[480px] h-[480px] opacity-15 mr-8">
          <RadarSweep />
        </div>
      </div>

      <div className="absolute inset-0 grid-bg opacity-20" />
      <div className="absolute inset-0"
        style={{ background: 'radial-gradient(ellipse 80% 60% at 50% 50%, rgba(0,220,229,0.04) 0%, transparent 70%)' }} />

      <div className="max-w-7xl mx-auto px-6">
        {/* Header */}
        <div ref={headerRef} className="text-center mb-16">
          <motion.p
            initial={{ opacity: 0 }}
            animate={inView ? { opacity: 1 } : {}}
            className="section-label mb-4"
          >
            // LIVE DEMO
          </motion.p>
          <motion.h2
            initial={{ opacity: 0, y: 30 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.8, delay: 0.1 }}
            className="font-display font-black text-4xl md:text-6xl text-cyber-text mb-4"
          >
            Try it{' '}
            <span className="text-neon-cyan">right now.</span>
          </motion.h2>
          <motion.p
            initial={{ opacity: 0 }}
            animate={inView ? { opacity: 1 } : {}}
            transition={{ delay: 0.2 }}
            className="text-cyber-muted font-mono text-sm"
          >
            ⚠ Demo mode — all findings are simulated for illustration purposes
          </motion.p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Left: Input + Progress */}
          <div className="space-y-5">
            {/* URL Input */}
            <div className="glass rounded-xl p-6 border border-white/[0.06]">
              <label className="block font-mono text-xs text-cyber-muted mb-3 tracking-widest">
                TARGET URL
              </label>
              <div className="flex gap-3">
                <div className="relative flex-1">
                  <div className="absolute left-3 top-1/2 -translate-y-1/2">
                    <Search className="w-4 h-4 text-cyber-muted" />
                  </div>
                  <input
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && runScan()}
                    placeholder="example.com"
                    disabled={phase === 'scanning'}
                    className="w-full bg-white/[0.03] border border-white/[0.08] rounded-lg pl-10 pr-4 py-3 text-cyber-text font-mono text-sm placeholder:text-cyber-muted/40 focus:outline-none focus:border-cyber-cyan/40 focus:bg-white/[0.05] transition-all disabled:opacity-50"
                    id="demo-url-input"
                  />
                </div>
                <NeonButton
                  variant={phase === 'done' ? 'ghost' : 'primary'}
                  onClick={phase === 'done' ? reset : runScan}
                  disabled={phase === 'scanning' || (!url.trim() && phase === 'idle')}
                  id="demo-scan-button"
                >
                  {phase === 'idle' && <><Zap className="w-4 h-4" /> Scan</>}
                  {phase === 'scanning' && <span className="font-mono text-xs">Scanning...</span>}
                  {phase === 'done' && <><X className="w-4 h-4" /> Reset</>}
                </NeonButton>
              </div>

              {/* Progress bar */}
              <AnimatePresence>
                {phase !== 'idle' && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="mt-4"
                  >
                    <div className="flex justify-between mb-1.5">
                      <span className="font-mono text-[11px] text-cyber-muted truncate pr-4">
                        {currentPhaseLabel || 'Complete'}
                      </span>
                      <span className="font-mono text-[11px] text-cyber-cyan shrink-0">{scanProgress}%</span>
                    </div>
                    <div className="h-[2px] bg-white/5 rounded-full overflow-hidden">
                      <motion.div
                        className="h-full rounded-full"
                        style={{
                          width: `${scanProgress}%`,
                          background: 'linear-gradient(to right, #00DCE5, #B600F8)',
                          boxShadow: '0 0 8px rgba(0,220,229,0.6)',
                        }}
                        transition={{ duration: 0.3 }}
                      />
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {/* Terminal log */}
            <div className="glass rounded-xl overflow-hidden border border-white/[0.06]">
              <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.02]">
                <div className="w-2.5 h-2.5 rounded-full bg-red-500/50" />
                <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/50" />
                <div className="w-2.5 h-2.5 rounded-full bg-green-500/50" />
                <span className="ml-2 text-[11px] text-cyber-muted font-mono">scan.log</span>
                {phase === 'scanning' && (
                  <span className="ml-auto text-[10px] font-mono text-cyber-cyan animate-pulse">● LIVE</span>
                )}
              </div>
              <div
                ref={logRef}
                className="p-4 h-48 overflow-y-auto space-y-1"
                style={{ scrollbarWidth: 'thin', scrollbarColor: '#00A8B0 #0D0D0D' }}
              >
                {logs.length === 0 ? (
                  <p className="font-mono text-xs text-cyber-muted/40">Waiting for scan target...</p>
                ) : (
                  logs.map((log, i) => (
                    <motion.p
                      key={i}
                      initial={{ opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      className="font-mono text-[11px] leading-relaxed"
                    >
                      <span className="text-cyber-muted/50 mr-2">{log.ts}</span>
                      <span className={
                        log.text.includes('[CRITICAL]') ? 'text-red-400' :
                        log.text.includes('[HIGH]') ? 'text-orange-400' :
                        log.text.includes('[COMPLETE]') ? 'text-cyber-cyan' :
                        log.text.includes('[INIT]') ? 'text-cyber-purple' :
                        'text-cyber-muted'
                      }>
                        {log.text}
                      </span>
                    </motion.p>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Right: Results */}
          <div className="space-y-5">
            {/* Score + vuln count */}
            <AnimatePresence>
              {phase === 'done' && (
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="glass rounded-xl p-6 border border-white/[0.06]"
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="font-mono text-xs text-cyber-muted mb-1">SECURITY SCORE</p>
                      <SecurityScoreGauge score={score} />
                    </div>
                    <div className="text-right space-y-3">
                      <div>
                        <p className="font-display font-black text-3xl text-red-400">1</p>
                        <p className="font-mono text-xs text-cyber-muted">CRITICAL</p>
                      </div>
                      <div>
                        <p className="font-display font-black text-2xl text-orange-400">2</p>
                        <p className="font-mono text-xs text-cyber-muted">HIGH</p>
                      </div>
                      <div>
                        <p className="font-display font-black text-xl text-yellow-400">2</p>
                        <p className="font-mono text-xs text-cyber-muted">MEDIUM</p>
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Vulnerability list */}
            <div className="glass rounded-xl overflow-hidden border border-white/[0.06]">
              <div className="px-5 py-3 border-b border-white/[0.04] flex items-center justify-between">
                <span className="font-mono text-xs text-cyber-muted">VULNERABILITIES</span>
                {vulns.length > 0 && (
                  <span className="font-mono text-xs text-red-400">{vulns.length} found</span>
                )}
              </div>
              <div className="divide-y divide-white/[0.04] max-h-72 overflow-y-auto">
                {vulns.length === 0 ? (
                  <div className="p-5 text-center">
                    <p className="font-mono text-xs text-cyber-muted/40">
                      {phase === 'idle' ? 'Enter a URL and start scanning' : 'Scanning...'}
                    </p>
                  </div>
                ) : (
                  vulns.map((v, i) => {
                    const sc = SEVERITY_COLORS[v.severity]
                    return (
                      <motion.div
                        key={i}
                        initial={{ opacity: 0, x: 20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.3 }}
                        className="flex items-start gap-3 px-5 py-3 hover:bg-white/[0.02] transition-colors"
                      >
                        <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" style={{ color: sc.color }} />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-0.5">
                            <span className="font-display font-semibold text-sm text-cyber-text truncate">
                              {v.name}
                            </span>
                            <CyberBadge color={sc.badge}>{v.severity}</CyberBadge>
                          </div>
                          <p className="font-mono text-[11px] text-cyber-muted truncate">{v.location}</p>
                        </div>
                        <span className="font-mono text-xs shrink-0" style={{ color: sc.color }}>
                          {v.score}
                        </span>
                      </motion.div>
                    )
                  })
                )}
              </div>
            </div>

            {/* Download CTA (after scan) */}
            <AnimatePresence>
              {phase === 'done' && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="flex gap-3"
                >
                  <NeonButton variant="primary" className="flex-1 justify-center" id="demo-download-report">
                    <CheckCircle className="w-4 h-4" />
                    Download Report (PDF)
                  </NeonButton>
                  <NeonButton variant="ghost" onClick={reset} id="demo-new-scan">
                    New Scan
                  </NeonButton>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </section>
  )
}
