import { useRef } from 'react'
import { useFrame } from '@react-three/fiber'

function SingleRing({ radius, phase }) {
  const ref = useRef()

  useFrame((state) => {
    if (!ref.current) return
    const t = state.clock.elapsedTime
    const progress = ((t * 0.3 + phase / (Math.PI * 2)) % 1)
    const scale = radius + progress * 3
    ref.current.scale.setScalar(scale / radius)
    ref.current.material.opacity = (1 - progress) * 0.4
  })

  return (
    <mesh ref={ref} rotation={[Math.PI / 2, 0, 0]}>
      <torusGeometry args={[radius, 0.012, 4, 80]} />
      <meshBasicMaterial color="#00DCE5" transparent opacity={0.4} depthWrite={false} />
    </mesh>
  )
}

export function ScanRing({ radius = 3.5, count = 3 }) {
  const phases = Array.from({ length: count }, (_, i) => (i / count) * Math.PI * 2)

  return (
    <>
      {phases.map((phase, i) => (
        <SingleRing key={i} radius={radius} phase={phase} />
      ))}
    </>
  )
}
