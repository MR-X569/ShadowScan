import { cn } from '@/utils/cn'

/**
 * Glassmorphism card component with optional neon border trace.
 */
export function GlassCard({ children, className, hover = true, glowing = false, ...props }) {
  return (
    <div
      className={cn(
        'glass-card rounded-xl transition-all duration-500',
        hover && 'hover:border-[rgba(0,220,229,0.2)] hover:shadow-[0_20px_60px_rgba(0,0,0,0.5),0_0_30px_rgba(0,220,229,0.08)]',
        glowing && 'animate-pulse-glow border-[rgba(0,220,229,0.2)]',
        className
      )}
      {...props}
    >
      {children}
    </div>
  )
}
