import { useEffect, useRef } from 'react'
import gsap from 'gsap'
import ScrollTrigger from 'gsap/ScrollTrigger'

gsap.registerPlugin(ScrollTrigger)

/**
 * Hook to safely use GSAP inside React components.
 * Handles cleanup automatically.
 * 
 * @param {Function} callback - Receives (gsap, ScrollTrigger) and returns cleanup or array of animations
 * @param {Array} deps - React dependency array
 */
export function useGSAP(callback, deps = []) {
  const ctx = useRef(null)

  useEffect(() => {
    ctx.current = gsap.context(() => {
      callback(gsap, ScrollTrigger)
    })

    return () => {
      ctx.current?.revert()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  return ctx
}

export { gsap, ScrollTrigger }
