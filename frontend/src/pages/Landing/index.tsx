import Navbar from '@/components/layout/Navbar';
import Footer from '@/components/layout/Footer';
import HeroSection from './HeroSection';
import AboutSection from './AboutSection';
import WhyChooseSection from './WhyChooseSection';
import CTASection from './CTASection';

export default function LandingPage() {
  return (
    <div className="flex min-h-screen flex-col bg-brand-bg">
      <Navbar />
      <main className="flex-1 pt-[65px]">
        <HeroSection />
        <AboutSection />
        <WhyChooseSection />
        <CTASection />
      </main>
      <Footer />
    </div>
  );
}
