import { useRef, Suspense } from 'react'
import { Canvas } from '@react-three/fiber'
import { OrbitControls, Environment } from '@react-three/drei'
import { motion } from 'framer-motion'
import { ArrowDown, Zap, Shield, Play } from 'lucide-react'
import { Globe } from '@/three/Globe'
import { AICore } from '@/three/AICore'
import { ParticleSystem } from '@/three/ParticleSystem'
import { ScanRing } from '@/three/ScanRing'
import { GlitchText } from '@/components/ui/GlitchText'
import { NeonButton } from '@/components/ui/NeonButton'
import { useMouseParallax } from '@/hooks/useMouseParallax'

function HeroScene({ mouse }) {
  return (
    <>
      <ambientLight intensity={0.1} />
      <directionalLight position={[10, 10, 5]} intensity={0.5} color="#00DCE5" />

      <Suspense fallback={null}>
        <Globe mouse={mouse} radius={3.2} />
        <ScanRing radius={3.5} count={3} />
        <AICore mouse={mouse} position={[5, 1, -2]} />
        <ParticleSystem count={2500} spread={22} mouse={mouse} />
      </Suspense>
    </>
  )
}

export function Hero() {
  const mouse = useMouseParallax(0.6)
  const sectionRef = useRef()

  const scrollToNext = () => {
    const next = document.querySelector('#why')
    if (next) {
      window.__lenis?.scrollTo(next, { offset: -80, duration: 1.4 })
    }
  }

  return (
    <section
      id="hero"
      ref={sectionRef}
      className="relative w-full h-screen min-h-[700px] flex items-center overflow-hidden"
    >
      {/* 3D Canvas — full background */}
      <div className="absolute inset-0 z-0">
        <Canvas
          camera={{ position: [0, 0, 9], fov: 60 }}
          gl={{ antialias: true, alpha: true }}
          className="r3f"
          dpr={[1, 2]}
        >
          <HeroScene mouse={mouse} />
        </Canvas>
      </div>

      {/* Radial gradient overlays */}
      <div className="absolute inset-0 z-[1] pointer-events-none">
        {/* Left vignette for text readability */}
        <div className="absolute inset-0"
          style={{ background: 'radial-gradient(ellipse 60% 80% at 30% 50%, rgba(5,5,5,0) 0%, rgba(5,5,5,0.85) 100%)' }} />
        {/* Bottom fade */}
        <div className="absolute bottom-0 left-0 right-0 h-40"
          style={{ background: 'linear-gradient(to top, #050505 0%, transparent 100%)' }} />
        {/* Top fade */}
        <div className="absolute top-0 left-0 right-0 h-24"
          style={{ background: 'linear-gradient(to bottom, #050505 0%, transparent 100%)' }} />
      </div>

      {/* Grid overlay */}
      <div className="absolute inset-0 z-[1] grid-bg opacity-20 pointer-events-none" />

      {/* Content */}
      <div className="relative z-[2] max-w-7xl mx-auto px-6 pt-20 w-full">
        <div className="max-w-3xl">
          {/* Eyebrow badge */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.1 }}
            className="mb-6"
          >
            <span className="cyber-chip">
              <span className="w-1.5 h-1.5 rounded-full bg-cyber-cyan animate-pulse" />
              AI-Powered Vulnerability Scanner
            </span>
          </motion.div>

          {/* Main heading */}
          <motion.h1
            initial={{ opacity: 0, y: 40 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.9, delay: 0.2, ease: [0.22, 1, 0.36, 1] }}
            className="font-display font-black leading-[0.95] tracking-tight mb-6"
            style={{ fontSize: 'clamp(3rem, 8vw, 7rem)' }}
          >
            <span className="block text-cyber-text">Scan The</span>
            <GlitchText
              as="span"
              className="block text-neon-cyan"
              autoGlitch
              interval={4000}
            >
              Shadows.
            </GlitchText>
            <span className="block gradient-text">Secure The Future.</span>
          </motion.h1>

          {/* Subheading */}
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.4 }}
            className="text-cyber-muted text-lg font-display leading-relaxed mb-8 max-w-xl"
          >
            AI-powered website security scanner that detects{' '}
            <span className="text-cyber-cyan">OWASP Top 10</span> vulnerabilities,
            fingerprints your tech stack, and delivers a professional report
            in under{' '}
            <span className="text-cyber-cyan">2 minutes</span>.
          </motion.p>

          {/* CTAs */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.55 }}
            className="flex flex-wrap gap-4 mb-12"
          >
            <NeonButton
              size="lg"
              variant="primary"
              onClick={() => window.__lenis?.scrollTo('#demo', { offset: -80, duration: 1.4 })}
              className="group font-display"
              id="hero-cta-scan"
            >
              <Zap className="w-5 h-5 group-hover:animate-pulse" />
              Start Free Scan
            </NeonButton>
            <NeonButton
              size="lg"
              variant="ghost"
              onClick={() => window.__lenis?.scrollTo('#how-it-works', { offset: -80, duration: 1.4 })}
              id="hero-cta-demo"
            >
              <Play className="w-4 h-4" />
              See How It Works
            </NeonButton>
          </motion.div>

          {/* Trust stats */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.7, delay: 0.7 }}
            className="flex flex-wrap gap-6"
          >
            {[
              { value: '10K+', label: 'Sites Scanned' },
              { value: '99%', label: 'Accuracy' },
              { value: '<2min', label: 'Scan Time' },
              { value: '200+', label: 'CVE Types' },
            ].map(({ value, label }) => (
              <div key={label} className="flex flex-col">
                <span className="font-display font-bold text-xl text-cyber-cyan">{value}</span>
                <span className="font-mono text-xs text-cyber-muted tracking-wider">{label}</span>
              </div>
            ))}
          </motion.div>
        </div>
      </div>

      {/* Mouse parallax layer — subtle text shift */}
      <div
        className="absolute z-[2] right-0 top-0 w-1/2 h-full pointer-events-none hidden lg:block"
        style={{
          transform: `translate(${mouse.x * -15}px, ${mouse.y * -10}px)`,
          transition: 'transform 0.1s ease-out',
        }}
      >
        {/* HUD overlay text */}
        <div className="absolute top-1/3 right-16 text-right">
          {[
            'SCAN_ENGINE: ACTIVE',
            'THREAT_LEVEL: MONITORING',
            'AI_STATUS: ONLINE',
            'CVE_DB: UPDATED',
          ].map((line, i) => (
            <motion.p
              key={i}
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.8 + i * 0.1 }}
              className="font-mono text-[11px] text-cyber-cyan/30 mb-1"
            >
              {line}
            </motion.p>
          ))}
        </div>
      </div>

      {/* Scroll indicator */}
      <motion.button
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.2 }}
        onClick={scrollToNext}
        className="absolute bottom-8 left-1/2 -translate-x-1/2 z-[3] flex flex-col items-center gap-2 text-cyber-muted hover:text-cyber-cyan transition-colors group"
        aria-label="Scroll down"
      >
        <span className="font-mono text-[10px] tracking-widest">SCROLL</span>
        <motion.div
          animate={{ y: [0, 8, 0] }}
          transition={{ duration: 1.5, repeat: Infinity, ease: 'easeInOut' }}
        >
          <ArrowDown className="w-4 h-4 group-hover:text-cyber-cyan" />
        </motion.div>
      </motion.button>

      {/* Scan line effect */}
      <div className="absolute inset-0 z-[1] pointer-events-none overflow-hidden">
        <div className="absolute left-0 right-0 h-px bg-gradient-to-r from-transparent via-cyber-cyan/20 to-transparent animate-scan-v"
          style={{ top: 0, animationDuration: '8s' }} />
      </div>
    </section>
  )
}
