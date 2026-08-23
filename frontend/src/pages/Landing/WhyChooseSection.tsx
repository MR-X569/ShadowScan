import { Zap, FileBarChart2, LayoutDashboard, KeyRound } from 'lucide-react';
import FeatureCard from '@/components/ui/FeatureCard';

const features = [
  {
    icon: <Zap size={20} />,
    title: 'Fast Analysis',
    description:
      'Get scan results quickly. Our engine is optimized to complete assessments without keeping you waiting.',
  },
  {
    icon: <FileBarChart2 size={20} />,
    title: 'Detailed Reports',
    description:
      'Every scan produces a structured report with categorized findings, severity ratings, and clear remediation steps.',
  },
  {
    icon: <LayoutDashboard size={20} />,
    title: 'Modern Dashboard',
    description:
      'Manage all your scans and results from a clean, well-organized dashboard built for clarity and efficiency.',
  },
  {
    icon: <KeyRound size={20} />,
    title: 'Secure Authentication',
    description:
      'Your account and scan data are protected with industry-standard authentication and secure session management.',
  },
];

export default function WhyChooseSection() {
  return (
    <section className="bg-brand-bg py-24">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="mx-auto mb-16 max-w-2xl text-center">
          <p className="mb-3 font-mono text-xs font-medium uppercase tracking-widest text-brand-cyan">
            Features
          </p>
          <h2 className="mb-4 text-3xl font-bold text-brand-text sm:text-4xl">
            Why Choose ShadowScan?
          </h2>
          <p className="text-base leading-relaxed text-brand-subtle">
            Built with security professionals and developers in mind — ShadowScan delivers
            everything you need to stay one step ahead of vulnerabilities.
          </p>
        </div>

        {/* Feature Cards Grid */}
        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {features.map((feature) => (
            <FeatureCard
              key={feature.title}
              icon={feature.icon}
              title={feature.title}
              description={feature.description}
            />
          ))}
        </div>
      </div>
    </section>
  );
}
