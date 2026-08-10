import { useRef, useState } from 'react'
import { motion, useInView } from 'framer-motion'
import {
  BarChart2, Shield, AlertTriangle, Clock, ArrowUpRight,
  Download, TrendingUp, CheckCircle
} from 'lucide-react'
import { GlassCard } from '@/components/ui/GlassCard'
import { CyberBadge } from '@/components/ui/CyberBadge'
import { NeonButton } from '@/components/ui/NeonButton'

const RECENT_SCANS = [
  { domain: 'api.shopify.io',     score: 87, vulns: 3,  severity: 'LOW',      time: '2m ago' },
  { domain: 'portal.acme.com',   score: 34, vulns: 14, severity: 'CRITICAL', time: '18m ago' },
  { domain: 'app.startup.dev',   score: 62, vulns: 7,  severity: 'HIGH',     time: '1h ago' },
  { domain: 'dashboard.saas.io', score: 91, vulns: 1,  severity: 'LOW',      time: '3h ago' },
]

const SEVERITY_COLORS = {
  CRITICAL: 'red',
  HIGH:     'red',
  MEDIUM:   'yellow',
  LOW:      'green',
}

const SCORE_COLOR = (s) =>
  s >= 80 ? '#22c55e' : s >= 50 ? '#eab308' : '#ef4444'

function MiniBarChart() {
  const bars = [40, 65, 30, 80, 55, 70, 45, 90, 60, 75, 85, 50]
  return (
    <div className="flex items-end gap-1 h-16">
      {bars.map((h, i) => (
        <motion.div
          key={i}
          className="flex-1 rounded-sm"
          style={{ background: `rgba(0,220,229,${0.3 + (h / 100) * 0.5})` }}
          initial={{ height: 0 }}
          whileInView={{ height: `${h}%` }}
          viewport={{ once: true }}
          transition={{ duration: 0.5, delay: i * 0.04, ease: 'easeOut' }}
        />
      ))}
    </div>
  )
}

function DonutChart() {
  const data = [
    { label: 'Critical', value: 15, color: '#ef4444' },
    { label: 'High',     value: 28, color: '#f97316' },
    { label: 'Medium',   value: 35, color: '#eab308' },
    { label: 'Low',      value: 22, color: '#22c55e' },
  ]
  const total = data.reduce((s, d) => s + d.value, 0)
  const r = 36
  const circumference = 2 * Math.PI * r
  let cumulative = 0

  return (
    <div className="flex items-center gap-5">
      <div className="relative shrink-0">
        <svg width="96" height="96" viewBox="0 0 96 96" className="-rotate-90">
          <circle cx="48" cy="48" r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="10" />
          {data.map((d, i) => {
            const dash = (d.value / total) * circumference
            const offset = circumference - cumulative * (circumference / total)
            cumulative += d.value
            return (
              <motion.circle
                key={i}
                cx="48" cy="48" r={r}
                fill="none"
                stroke={d.color}
                strokeWidth="10"
                strokeLinecap="butt"
                strokeDasharray={`${dash} ${circumference - dash}`}
                strokeDashoffset={offset}
                initial={{ opacity: 0 }}
                whileInView={{ opacity: 1 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: i * 0.15 }}
              />
            )
          })}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-display font-black text-lg text-cyber-text">247</span>
          <span className="font-mono text-[9px] text-cyber-muted">TOTAL</span>
        </div>
      </div>
      <div className="space-y-1.5">
        {data.map((d) => (
          <div key={d.label} className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full" style={{ background: d.color }} />
            <span className="font-mono text-[11px] text-cyber-muted">{d.label}</span>
            <span className="font-mono text-[11px] text-cyber-text ml-auto">{d.value}%</span>
          </div>
        ))}
      </div>
    </div>
  )
}

export function DashboardPreview() {
  const [tilt, setTilt] = useState({ x: 0, y: 0 })
  const containerRef = useRef()
  const headerRef = useRef()
  const inView = useInView(headerRef, { once: true })

  const handleMouseMove = (e) => {
    if (!containerRef.current) return
    const rect = containerRef.current.getBoundingClientRect()
    const x = ((e.clientX - rect.left) / rect.width - 0.5) * 12
    const y = ((e.clientY - rect.top) / rect.height - 0.5) * -8
    setTilt({ x, y })
  }

  return (
    <section id="dashboard" className="relative py-32 overflow-hidden">
      <div className="absolute inset-0"
        style={{ background: 'radial-gradient(ellipse 80% 60% at 50% 80%, rgba(182,0,248,0.05) 0%, transparent 70%)' }} />
      <div className="absolute inset-0 dot-bg opacity-20" />

      <div className="max-w-7xl mx-auto px-6">
        {/* Header */}
        <div ref={headerRef} className="text-center mb-16">
          <motion.p
            initial={{ opacity: 0 }}
            animate={inView ? { opacity: 1 } : {}}
            className="section-label mb-4"
          >
            // DASHBOARD
          </motion.p>
          <motion.h2
            initial={{ opacity: 0, y: 30 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.8, delay: 0.1 }}
            className="font-display font-black text-4xl md:text-6xl text-cyber-text mb-6"
          >
            Command center for{' '}
            <span className="text-neon-cyan">your security.</span>
          </motion.h2>
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.7, delay: 0.2 }}
            className="text-cyber-muted max-w-xl mx-auto text-lg"
          >
            Track every scan, monitor trends, manage reports — all from one
            cinematic command interface.
          </motion.p>
        </div>

        {/* Floating dashboard */}
        <motion.div
          ref={containerRef}
          onMouseMove={handleMouseMove}
          onMouseLeave={() => setTilt({ x: 0, y: 0 })}
          initial={{ opacity: 0, y: 60 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 1, ease: [0.22, 1, 0.36, 1] }}
          style={{
            transform: `perspective(1200px) rotateX(${tilt.y}deg) rotateY(${tilt.x}deg)`,
            transition: 'transform 0.2s ease-out',
          }}
          className="relative"
        >
          {/* Ambient glow under dashboard */}
          <div className="absolute -inset-4 rounded-3xl blur-2xl opacity-20 pointer-events-none"
            style={{ background: 'linear-gradient(135deg, rgba(0,220,229,0.3), rgba(182,0,248,0.2))' }} />

          <div className="glass-card rounded-2xl overflow-hidden border border-white/[0.06] relative"
            style={{ boxShadow: '0 40px 80px rgba(0,0,0,0.6), 0 0 40px rgba(0,220,229,0.04)' }}>

            {/* Dashboard header bar */}
            <div className="flex items-center gap-3 px-6 py-4 border-b border-white/[0.06] bg-white/[0.02]">
              <div className="flex gap-1.5">
                <div className="w-3 h-3 rounded-full bg-red-500/60" />
                <div className="w-3 h-3 rounded-full bg-yellow-500/60" />
                <div className="w-3 h-3 rounded-full bg-green-500/60" />
              </div>
              <div className="flex-1 text-center">
                <span className="font-mono text-xs text-cyber-muted">ShadowScan Dashboard — Workspace</span>
              </div>
              <div className="flex items-center gap-1.5">
                <div className="w-1.5 h-1.5 rounded-full bg-cyber-cyan animate-pulse" />
                <span className="font-mono text-[10px] text-cyber-cyan">LIVE</span>
              </div>
            </div>

            {/* Dashboard content */}
            <div className="p-6 grid grid-cols-1 lg:grid-cols-3 gap-5">
              {/* Left column: stats */}
              <div className="space-y-4">
                {/* Stat cards */}
                {[
                  { label: 'Total Scans', value: '1,247', icon: Shield, color: '#00DCE5', trend: '+12%' },
                  { label: 'Vulnerabilities', value: '3,891', icon: AlertTriangle, color: '#ef4444', trend: '-8%' },
                  { label: 'Avg Score', value: '72/100', icon: TrendingUp, color: '#22c55e', trend: '+4pt' },
                ].map(({ label, value, icon: Icon, color, trend }) => (
                  <div key={label} className="glass rounded-xl p-4 flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
                      style={{ background: `${color}15`, border: `1px solid ${color}25` }}>
                      <Icon className="w-5 h-5" style={{ color }} strokeWidth={1.5} />
                    </div>
                    <div className="flex-1">
                      <p className="font-mono text-[11px] text-cyber-muted">{label}</p>
                      <p className="font-display font-bold text-cyber-text">{value}</p>
                    </div>
                    <span className="font-mono text-xs" style={{ color: trend.startsWith('-') ? '#ef4444' : '#22c55e' }}>
                      {trend}
                    </span>
                  </div>
                ))}

                {/* Mini bar chart */}
                <div className="glass rounded-xl p-4">
                  <div className="flex justify-between mb-3">
                    <span className="font-mono text-[11px] text-cyber-muted">SCAN ACTIVITY</span>
                    <span className="font-mono text-[11px] text-cyber-cyan">12mo</span>
                  </div>
                  <MiniBarChart />
                </div>
              </div>

              {/* Middle: Recent scans */}
              <div className="lg:col-span-2 space-y-4">
                <div className="glass rounded-xl overflow-hidden">
                  <div className="flex items-center justify-between px-5 py-3 border-b border-white/[0.04]">
                    <span className="font-mono text-xs text-cyber-muted">RECENT SCANS</span>
                    <button className="flex items-center gap-1 font-mono text-xs text-cyber-cyan hover:underline">
                      View all <ArrowUpRight className="w-3 h-3" />
                    </button>
                  </div>
                  <div className="divide-y divide-white/[0.04]">
                    {RECENT_SCANS.map((scan, i) => (
                      <motion.div
                        key={i}
                        initial={{ opacity: 0, x: 20 }}
                        whileInView={{ opacity: 1, x: 0 }}
                        viewport={{ once: true }}
                        transition={{ delay: i * 0.08 }}
                        className="flex items-center gap-4 px-5 py-3.5 hover:bg-white/[0.02] transition-colors"
                      >
                        <div className="w-8 h-8 rounded-lg bg-white/[0.04] flex items-center justify-center shrink-0">
                          <Shield className="w-4 h-4 text-cyber-muted" strokeWidth={1.5} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="font-display font-medium text-sm text-cyber-text truncate">{scan.domain}</p>
                          <p className="font-mono text-[11px] text-cyber-muted">{scan.time}</p>
                        </div>
                        <CyberBadge color={SEVERITY_COLORS[scan.severity]}>{scan.severity}</CyberBadge>
                        <div className="text-right shrink-0">
                          <p className="font-display font-bold text-sm" style={{ color: SCORE_COLOR(scan.score) }}>
                            {scan.score}
                          </p>
                          <p className="font-mono text-[10px] text-cyber-muted">{scan.vulns} vulns</p>
                        </div>
                        <button className="ml-1 text-cyber-muted hover:text-cyber-cyan transition-colors">
                          <Download className="w-4 h-4" />
                        </button>
                      </motion.div>
                    ))}
                  </div>
                </div>

                {/* Vuln breakdown donut */}
                <div className="glass rounded-xl p-5">
                  <div className="flex items-center justify-between mb-4">
                    <span className="font-mono text-xs text-cyber-muted">VULNERABILITY BREAKDOWN</span>
                    <CheckCircle className="w-4 h-4 text-cyber-cyan" />
                  </div>
                  <DonutChart />
                </div>
              </div>
            </div>
          </div>
        </motion.div>

        {/* CTA below dashboard */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ delay: 0.4 }}
          className="text-center mt-10"
        >
          <NeonButton size="lg" variant="ghost" id="dashboard-cta">
            Access Full Dashboard
            <ArrowUpRight className="w-5 h-5" />
          </NeonButton>
        </motion.div>
      </div>
    </section>
  )
}
