import { ShieldCheck, ScanLine, FileText, MousePointerClick } from 'lucide-react';

const pillars = [
  {
    icon: <ShieldCheck size={22} />,
    title: 'Website Security',
    description:
      'ShadowScan proactively checks your website for known security weaknesses and common vulnerabilities before attackers can exploit them.',
  },
  {
    icon: <ScanLine size={22} />,
    title: 'Automated Analysis',
    description:
      'Run comprehensive security assessments with a single click. Our automated engine handles the heavy lifting so you can focus on fixing issues.',
  },
  {
    icon: <FileText size={22} />,
    title: 'Detailed Reports',
    description:
      'Receive clear, structured security reports that highlight findings, severity levels, and recommended actions — all in one place.',
  },
  {
    icon: <MousePointerClick size={22} />,
    title: 'Easy-to-use Interface',
    description:
      'Designed for developers, security teams, and non-technical users alike. No complex setup. No steep learning curve.',
  },
];

export default function AboutSection() {
  return (
    <section id="about" className="bg-brand-surface py-24">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="mx-auto mb-16 max-w-2xl text-center">
          <p className="mb-3 font-mono text-xs font-medium uppercase tracking-widest text-brand-cyan">
            About ShadowScan
          </p>
          <h2 className="mb-4 text-3xl font-bold text-brand-text sm:text-4xl">
            What is ShadowScan?
          </h2>
          <p className="text-base leading-relaxed text-brand-subtle">
            ShadowScan is a professional-grade web security platform designed to help individuals
            and teams identify vulnerabilities in their websites through automated assessments and
            comprehensive reporting — without requiring deep security expertise.
          </p>
        </div>

        {/* Pillars Grid */}
        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {pillars.map((pillar) => (
            <div
              key={pillar.title}
              className="rounded-xl border border-brand-border bg-brand-card p-6 transition-all duration-300 hover:border-brand-cyan/30 hover:-translate-y-1 hover:shadow-card-hover"
            >
              <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-lg border border-brand-border bg-brand-surface text-brand-cyan">
                {pillar.icon}
              </div>
              <h3 className="mb-2 text-sm font-semibold text-brand-text">{pillar.title}</h3>
              <p className="text-sm leading-relaxed text-brand-subtle">{pillar.description}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
