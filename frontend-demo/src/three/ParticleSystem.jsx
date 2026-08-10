import { useRef, useMemo } from 'react'
import { useFrame } from '@react-three/fiber'
import * as THREE from 'three'

/**
 * Dense particle field for the hero background.
 * GPU-friendly: single Points geometry, custom shader material.
 */
export function ParticleSystem({ count = 2000, spread = 20, mouse }) {
  const pointsRef = useRef()
  const timeRef = useRef(0)

  const { positions, colors } = useMemo(() => {
    const positions = new Float32Array(count * 3)
    const colors    = new Float32Array(count * 3)
    const cCyan   = new THREE.Color('#00DCE5')
    const cPurple = new THREE.Color('#B600F8')
    const cWhite  = new THREE.Color('#E5E2E1')

    for (let i = 0; i < count; i++) {
      // Spherical distribution
      const r     = Math.random() * spread
      const theta = Math.random() * Math.PI * 2
      const phi   = Math.acos(2 * Math.random() - 1)

      positions[i * 3]     = r * Math.sin(phi) * Math.cos(theta)
      positions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta)
      positions[i * 3 + 2] = r * Math.cos(phi) - 5

      // Color blend
      const t = Math.random()
      const c = t < 0.4 ? cCyan : t < 0.7 ? cPurple : cWhite
      colors[i * 3]     = c.r
      colors[i * 3 + 1] = c.g
      colors[i * 3 + 2] = c.b
    }
    return { positions, colors }
  }, [count, spread])

  useFrame((state) => {
    if (!pointsRef.current) return
    timeRef.current += 0.001
    pointsRef.current.rotation.y = timeRef.current * 0.3
    pointsRef.current.rotation.x = timeRef.current * 0.1

    if (mouse) {
      pointsRef.current.rotation.y += mouse.x * 0.002
      pointsRef.current.rotation.x += mouse.y * 0.002
    }
  })

  return (
    <points ref={pointsRef}>
      <bufferGeometry>
        <bufferAttribute
          attach="attributes-position"
          count={count}
          array={positions}
          itemSize={3}
        />
        <bufferAttribute
          attach="attributes-color"
          count={count}
          array={colors}
          itemSize={3}
        />
      </bufferGeometry>
      <pointsMaterial
        size={0.04}
        vertexColors
        transparent
        opacity={0.6}
        sizeAttenuation
        depthWrite={false}
      />
    </points>
  )
}
