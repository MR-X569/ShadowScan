import type { ReactNode } from 'react';

interface FeatureCardProps {
  icon: ReactNode;
  title: string;
  description: string;
}

export default function FeatureCard({ icon, title, description }: FeatureCardProps) {
  return (
    <div className="group flex flex-col gap-4 rounded-xl border border-brand-border bg-brand-card p-6 shadow-card transition-all duration-300 hover:shadow-card-hover hover:border-brand-cyan/30 hover:-translate-y-1">
      <div className="flex h-11 w-11 items-center justify-center rounded-lg border border-brand-border bg-brand-surface text-brand-cyan transition-colors duration-300 group-hover:border-brand-cyan/40 group-hover:bg-brand-cyan/10">
        {icon}
      </div>
      <div>
        <h3 className="mb-2 text-base font-semibold text-brand-text">{title}</h3>
        <p className="text-sm leading-relaxed text-brand-subtle">{description}</p>
      </div>
    </div>
  );
}
