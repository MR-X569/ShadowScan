import { useRef, useMemo } from 'react'
import { useFrame } from '@react-three/fiber'
import * as THREE from 'three'

/**
 * Floating AI Core — a pulsing icosahedron + orbital rings.
 * Represents the AI intelligence of ShadowScan.
 */
export function AICore({ mouse, position = [0, 0, 0] }) {
  const coreRef    = useRef()
  const ring1Ref   = useRef()
  const ring2Ref   = useRef()
  const ring3Ref   = useRef()
  const glowRef    = useRef()

  useFrame((state) => {
    const t = state.clock.elapsedTime

    if (coreRef.current) {
      coreRef.current.rotation.x = t * 0.5
      coreRef.current.rotation.y = t * 0.7
      // Breathe
      const scale = 1 + Math.sin(t * 2) * 0.05
      coreRef.current.scale.setScalar(scale)
    }

    if (ring1Ref.current) {
      ring1Ref.current.rotation.x = t * 0.8
      ring1Ref.current.rotation.z = t * 0.4
    }
    if (ring2Ref.current) {
      ring2Ref.current.rotation.y = -t * 0.6
      ring2Ref.current.rotation.z = t * 0.3
    }
    if (ring3Ref.current) {
      ring3Ref.current.rotation.x = -t * 0.4
      ring3Ref.current.rotation.y = t * 0.5
    }

    if (glowRef.current && mouse) {
      glowRef.current.rotation.y += mouse.x * 0.01
      glowRef.current.rotation.x += mouse.y * 0.01
    }
  })

  return (
    <group position={position} ref={glowRef}>
      {/* Core icosahedron */}
      <mesh ref={coreRef}>
        <icosahedronGeometry args={[0.6, 1]} />
        <meshStandardMaterial
          color="#00DCE5"
          emissive="#00DCE5"
          emissiveIntensity={2}
          wireframe
          transparent
          opacity={0.9}
        />
      </mesh>

      {/* Inner solid */}
      <mesh>
        <icosahedronGeometry args={[0.4, 0]} />
        <meshStandardMaterial
          color="#001A1E"
          emissive="#00A8B0"
          emissiveIntensity={0.5}
          metalness={0.8}
          roughness={0.2}
        />
      </mesh>

      {/* Orbital ring 1 */}
      <mesh ref={ring1Ref}>
        <torusGeometry args={[1.1, 0.008, 8, 80]} />
        <meshBasicMaterial color="#00DCE5" transparent opacity={0.6} />
      </mesh>

      {/* Orbital ring 2 */}
      <mesh ref={ring2Ref} rotation={[Math.PI / 3, 0, 0]}>
        <torusGeometry args={[1.4, 0.005, 8, 80]} />
        <meshBasicMaterial color="#B600F8" transparent opacity={0.5} />
      </mesh>

      {/* Orbital ring 3 */}
      <mesh ref={ring3Ref} rotation={[0, Math.PI / 4, Math.PI / 3]}>
        <torusGeometry args={[1.7, 0.004, 8, 80]} />
        <meshBasicMaterial color="#00F5FF" transparent opacity={0.35} />
      </mesh>

      {/* Point lights for glow effect */}
      <pointLight color="#00DCE5" intensity={3} distance={4} decay={2} />
      <pointLight color="#B600F8" intensity={1} distance={3} decay={2} position={[2, 0, 0]} />
    </group>
  )
}
