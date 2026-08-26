import React, { isValidElement, type ReactNode } from 'react';

interface StatCardProps {
  label: string;
  value: number;
  icon: ReactNode | React.ComponentType<{ size?: number; className?: string }>;
  accent?: 'cyan' | 'blue' | 'green' | 'emerald' | 'red';
  color?: 'cyan' | 'blue' | 'green' | 'emerald' | 'red';
  description?: string;
}

const accentMap: Record<string, { icon: string; value: string }> = {
  cyan: { icon: 'bg-brand-cyan/10 text-brand-cyan ring-brand-cyan/20', value: 'text-brand-cyan' },
  blue: { icon: 'bg-blue-500/10 text-blue-400 ring-blue-500/20', value: 'text-blue-400' },
  green: { icon: 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/20', value: 'text-emerald-400' },
  emerald: { icon: 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/20', value: 'text-emerald-400' },
  red: { icon: 'bg-red-500/10 text-red-400 ring-red-500/20', value: 'text-red-400' },
};

export default function StatCard({ label, value, icon, accent, color = 'cyan', description }: StatCardProps) {
  const chosenAccent = accent || color || 'cyan';
  const colors = accentMap[chosenAccent] || accentMap.cyan;

  const renderIcon = () => {
    if (isValidElement(icon)) {
      return icon;
    }
    if (typeof icon === 'function' || (typeof icon === 'object' && icon !== null)) {
      const IconComponent = icon as React.ComponentType<{ size?: number }>;
      return <IconComponent size={20} />;
    }
    return null;
  };

  return (
    <div className="flex items-center gap-4 rounded-xl border border-brand-border bg-brand-card p-5 shadow-card transition-all duration-300 hover:border-brand-cyan/20 hover:shadow-card-hover">
      <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-lg ring-1 ${colors.icon}`}>
        {renderIcon()}
      </div>
      <div>
        <p className="text-xs font-medium uppercase tracking-wide text-brand-muted">{label}</p>
        <p className={`mt-0.5 text-2xl font-bold tabular-nums ${colors.value}`}>{value}</p>
        {description && <p className="mt-0.5 text-[11px] text-brand-muted">{description}</p>}
      </div>
    </div>
  );
}

