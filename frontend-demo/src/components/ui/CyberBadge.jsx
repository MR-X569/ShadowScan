import { cn } from '@/utils/cn'

/**
 * Small badge/chip for labels like "CORE", "AI", "NEW"
 */
export function CyberBadge({ children, className, color = 'cyan' }) {
  const colors = {
    cyan:   'border-cyber-cyan/30 bg-cyber-cyan/10 text-cyber-cyan',
    purple: 'border-cyber-purple/30 bg-cyber-purple/10 text-cyber-purple',
    green:  'border-green-400/30 bg-green-400/10 text-green-400',
    red:    'border-red-400/30 bg-red-400/10 text-red-400',
    yellow: 'border-yellow-400/30 bg-yellow-400/10 text-yellow-400',
    white:  'border-white/20 bg-white/5 text-cyber-muted',
  }

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 px-2 py-0.5 rounded-full border font-mono text-[10px] tracking-widest uppercase',
        colors[color] ?? colors.cyan,
        className
      )}
    >
      <span className="w-1 h-1 rounded-full bg-current opacity-80" />
      {children}
    </span>
  )
}
