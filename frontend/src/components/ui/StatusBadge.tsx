import type { ScanStatus } from '@/types/scan';

interface StatusBadgeProps {
  status: ScanStatus;
}

const statusConfig: Record<ScanStatus, { label: string; classes: string }> = {
  PENDING:   { label: 'Pending',   classes: 'bg-yellow-500/10 text-yellow-400 ring-yellow-500/20' },
  RUNNING:   { label: 'Running',   classes: 'bg-brand-blue/10 text-brand-blue ring-brand-blue/20' },
  COMPLETED: { label: 'Completed', classes: 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/20' },
  FAILED:    { label: 'Failed',    classes: 'bg-red-500/10 text-red-400 ring-red-500/20' },
};

export default function StatusBadge({ status }: StatusBadgeProps) {
  const { label, classes } = statusConfig[status] ?? {
    label: status,
    classes: 'bg-brand-surface text-brand-subtle ring-brand-border',
  };

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ${classes}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current opacity-80" aria-hidden="true" />
      {label}
    </span>
  );
}
