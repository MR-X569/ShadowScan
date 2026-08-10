import { motion } from 'framer-motion'
import { cn } from '@/utils/cn'

/**
 * Neon CTA button with shimmer + glow effect.
 * Variants: primary (cyan), secondary (ghost), purple
 */
export function NeonButton({
  children,
  variant = 'primary',
  size = 'md',
  className,
  onClick,
  disabled = false,
  ...props
}) {
  const base = 'relative inline-flex items-center justify-center gap-2 font-display font-semibold rounded-lg overflow-hidden transition-all duration-300 cursor-pointer select-none'

  const sizes = {
    sm: 'px-4 py-2 text-sm',
    md: 'px-6 py-3 text-base',
    lg: 'px-8 py-4 text-lg',
  }

  const variants = {
    primary: 'bg-cyber-cyan text-cyber-bg hover:shadow-neon-cyan hover:scale-[1.02] active:scale-[0.98]',
    ghost:   'border border-[rgba(0,220,229,0.3)] text-cyber-cyan hover:bg-[rgba(0,220,229,0.08)] hover:border-cyber-cyan hover:shadow-neon-sm',
    purple:  'bg-cyber-purple text-white hover:shadow-neon-purple hover:scale-[1.02] active:scale-[0.98]',
    dark:    'bg-[rgba(255,255,255,0.05)] border border-[rgba(255,255,255,0.1)] text-cyber-text hover:border-[rgba(0,220,229,0.3)] hover:bg-[rgba(0,220,229,0.05)]',
  }

  return (
    <motion.button
      whileHover={{ scale: disabled ? 1 : 1.02 }}
      whileTap={{ scale: disabled ? 1 : 0.97 }}
      onClick={onClick}
      disabled={disabled}
      className={cn(base, sizes[size], variants[variant], disabled && 'opacity-50 cursor-not-allowed', className)}
      {...props}
    >
      {/* Shimmer overlay */}
      {variant === 'primary' && (
        <span
          className="absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-white/20 to-transparent
                     group-hover:translate-x-full transition-transform duration-700 skew-x-12"
          aria-hidden="true"
        />
      )}
      {children}
    </motion.button>
  )
}
