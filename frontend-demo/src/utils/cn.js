import { clsx } from 'clsx'

/**
 * Utility for merging Tailwind class names conditionally.
 * Wraps clsx for use across all components.
 */
export function cn(...inputs) {
  return clsx(...inputs)
}
