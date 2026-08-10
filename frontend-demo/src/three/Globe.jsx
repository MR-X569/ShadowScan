import { useRef, useMemo } from 'react'
import { useFrame } from '@react-three/fiber'
import * as THREE from 'three'

/**
 * Wireframe globe with latitude/longitude lines.
 * Glows cyan. Rotates slowly. Responds to mouse.
 */
export function Globe({ mouse, radius = 3.2 }) {
  const groupRef = useRef()
  const innerRef = useRef()

  const { lineSegments } = useMemo(() => {
    const segments = []
    const latLines  = 18
    const lonLines  = 24

    // Latitude rings
    for (let i = 1; i < latLines; i++) {
      const phi   = (Math.PI * i) / latLines
      const y     = radius * Math.cos(phi)
      const r     = radius * Math.sin(phi)
      const pts   = []
      for (let j = 0; j <= 64; j++) {
        const theta = (2 * Math.PI * j) / 64
        pts.push(new THREE.Vector3(r * Math.cos(theta), y, r * Math.sin(theta)))
      }
      segments.push(pts)
    }

    // Longitude meridians
    for (let i = 0; i < lonLines; i++) {
      const theta = (2 * Math.PI * i) / lonLines
      const pts   = []
      for (let j = 0; j <= 64; j++) {
        const phi = (Math.PI * j) / 64
        pts.push(new THREE.Vector3(
          radius * Math.sin(phi) * Math.cos(theta),
          radius * Math.cos(phi),
          radius * Math.sin(phi) * Math.sin(theta)
        ))
      }
      segments.push(pts)
    }

    return { lineSegments: segments }
  }, [radius])

  useFrame((state) => {
    if (!groupRef.current) return
    const t = state.clock.elapsedTime

    groupRef.current.rotation.y += 0.001
    if (mouse) {
      groupRef.current.rotation.y += mouse.x * 0.005
      groupRef.current.rotation.x += (mouse.y * 0.3 - groupRef.current.rotation.x) * 0.05
    }

    // Pulse effect on inner sphere
    if (innerRef.current) {
      innerRef.current.material.opacity = 0.03 + Math.sin(t * 1.5) * 0.015
    }
  })

  return (
    <group ref={groupRef}>
      {/* Outer Wireframe Globe */}
      <mesh>
        <sphereGeometry args={[radius, 36, 24]} />
        <meshBasicMaterial
          color="#00DCE5"
          wireframe
          transparent
          opacity={0.22}
          depthWrite={false}
        />
      </mesh>

      {/* Second Lat/Long Ring Layer */}
      <mesh rotation={[Math.PI / 6, 0, 0]}>
        <sphereGeometry args={[radius + 0.02, 18, 12]} />
        <meshBasicMaterial
          color="#00F5FF"
          wireframe
          transparent
          opacity={0.12}
          depthWrite={false}
        />
      </mesh>

      {/* Inner glowing sphere */}
      <mesh ref={innerRef}>
        <sphereGeometry args={[radius - 0.02, 32, 32]} />
        <meshBasicMaterial color="#00DCE5" transparent opacity={0.04} side={THREE.BackSide} />
      </mesh>

      {/* Outer glow shell */}
      <mesh>
        <sphereGeometry args={[radius + 0.3, 32, 32]} />
        <meshBasicMaterial color="#00DCE5" transparent opacity={0.015} side={THREE.BackSide} depthWrite={false} />
      </mesh>
    </group>
  )
}
