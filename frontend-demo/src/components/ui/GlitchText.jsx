import { useEffect, useRef, useState } from 'react'
import { cn } from '@/utils/cn'

/**
 * Text with glitch animation effect.
 * Triggers on hover or on a timer.
 */
export function GlitchText({
  children,
  className,
  as: Tag = 'span',
  autoGlitch = false,
  interval = 3000,
}) {
  const [glitching, setGlitching] = useState(false)
  const timerRef = useRef(null)

  const triggerGlitch = () => {
    setGlitching(true)
    setTimeout(() => setGlitching(false), 400)
  }

  useEffect(() => {
    if (!autoGlitch) return
    timerRef.current = setInterval(triggerGlitch, interval)
    return () => clearInterval(timerRef.current)
  }, [autoGlitch, interval])

  return (
    <Tag
      className={cn('relative inline-block cursor-default', className)}
      onMouseEnter={triggerGlitch}
    >
      {/* Main text */}
      <span className="relative z-10">{children}</span>

      {/* Glitch layer 1 — cyan offset */}
      <span
        aria-hidden="true"
        className={cn(
          'absolute inset-0 text-cyber-cyan pointer-events-none transition-all duration-75',
          glitching ? 'opacity-80 translate-x-[3px] translate-y-[-2px]' : 'opacity-0'
        )}
        style={{ clipPath: glitching ? 'inset(10% 0 60% 0)' : 'inset(0)' }}
      >
        {children}
      </span>

      {/* Glitch layer 2 — purple offset */}
      <span
        aria-hidden="true"
        className={cn(
          'absolute inset-0 text-cyber-purple pointer-events-none transition-all duration-75',
          glitching ? 'opacity-60 translate-x-[-3px] translate-y-[2px]' : 'opacity-0'
        )}
        style={{ clipPath: glitching ? 'inset(60% 0 10% 0)' : 'inset(0)' }}
      >
        {children}
      </span>
    </Tag>
  )
}
