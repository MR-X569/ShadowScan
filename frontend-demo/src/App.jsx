import { useState, useEffect } from 'react'
import { useLenis } from '@/hooks/useLenis'

// Layout
import { Navbar } from '@/components/layout/Navbar'

// Sections
import { LoadingScreen } from '@/sections/LoadingScreen'
import { Hero } from '@/sections/Hero'
import { WhyShadowScan } from '@/sections/WhyShadowScan'
import { Features } from '@/sections/Features'
import { HowItWorks } from '@/sections/HowItWorks'
import { DemoScan } from '@/sections/DemoScan'
import { DashboardPreview } from '@/sections/DashboardPreview'
import { Testimonials } from '@/sections/Testimonials'
import { FAQ } from '@/sections/FAQ'
import { FooterSection } from '@/sections/FooterSection'

function App() {
  const [loaded, setLoaded] = useState(false)
  const lenisRef = useLenis()

  // Safety fallback: reveal site after 3.5s if loader callback was delayed
  useEffect(() => {
    const timer = setTimeout(() => setLoaded(true), 3500)
    return () => clearTimeout(timer)
  }, [])

  // Prevent scroll during loading
  useEffect(() => {
    if (!loaded) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = ''
    }
  }, [loaded])

  return (
    <>
      {/* Loading screen — shows until complete */}
      <LoadingScreen onComplete={() => setLoaded(true)} />

      {/* Main site — always in DOM but hidden behind loader */}
      <div
        style={{
          opacity: loaded ? 1 : 0,
          transition: 'opacity 0.5s ease',
          minHeight: '100vh',
          background: '#050505',
        }}
      >
        <Navbar />

        <main>
          <Hero />
          <WhyShadowScan />
          <Features />
          <HowItWorks />
          <DemoScan />
          <DashboardPreview />
          <Testimonials />
          <FAQ />
        </main>

        <FooterSection />
      </div>
    </>
  )
}

export default App
