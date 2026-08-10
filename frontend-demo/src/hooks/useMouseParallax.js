import { useEffect, useRef, useState } from 'react'

/**
 * Tracks mouse position and returns normalized [-1, 1] x/y values
 * for parallax effects. Optionally accepts a strength multiplier.
 */
export function useMouseParallax(strength = 1) {
  const [mouse, setMouse] = useState({ x: 0, y: 0 })
  const animRef = useRef(null)
  const targetRef = useRef({ x: 0, y: 0 })
  const currentRef = useRef({ x: 0, y: 0 })

  useEffect(() => {
    const handleMove = (e) => {
      targetRef.current = {
        x: ((e.clientX / window.innerWidth) * 2 - 1) * strength,
        y: ((e.clientY / window.innerHeight) * 2 - 1) * strength,
      }
    }

    const lerp = (a, b, t) => a + (b - a) * t

    const animate = () => {
      currentRef.current.x = lerp(currentRef.current.x, targetRef.current.x, 0.06)
      currentRef.current.y = lerp(currentRef.current.y, targetRef.current.y, 0.06)
      setMouse({ ...currentRef.current })
      animRef.current = requestAnimationFrame(animate)
    }

    window.addEventListener('mousemove', handleMove)
    animRef.current = requestAnimationFrame(animate)

    return () => {
      window.removeEventListener('mousemove', handleMove)
      cancelAnimationFrame(animRef.current)
    }
  }, [strength])

  return mouse
}
