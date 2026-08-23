import type { ReactNode } from 'react';

interface StatCardProps {
  label: string;
  value: number;
  icon: ReactNode;
  accent?: 'cyan' | 'blue' | 'green' | 'red';
}

const accentMap = {
  cyan:  { icon: 'bg-brand-cyan/10 text-brand-cyan ring-brand-cyan/20',   value: 'text-brand-cyan' },
  blue:  { icon: 'bg-brand-blue/10 text-brand-blue ring-brand-blue/20',   value: 'text-brand-blue' },
  green: { icon: 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/20', value: 'text-emerald-400' },
  red:   { icon: 'bg-red-500/10 text-red-400 ring-red-500/20',            value: 'text-red-400' },
};

export default function StatCard({ label, value, icon, accent = 'cyan' }: StatCardProps) {
  const colors = accentMap[accent];

  return (
    <div className="flex items-center gap-4 rounded-xl border border-brand-border bg-brand-card p-5 shadow-card transition-all duration-300 hover:border-brand-cyan/20 hover:shadow-card-hover">
      <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-lg ring-1 ${colors.icon}`}>
        {icon}
      </div>
      <div>
        <p className="text-xs font-medium uppercase tracking-wide text-brand-muted">{label}</p>
        <p className={`mt-0.5 text-2xl font-bold tabular-nums ${colors.value}`}>{value}</p>
      </div>
    </div>
  );
}
