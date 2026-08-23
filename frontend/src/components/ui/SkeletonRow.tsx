interface SkeletonRowProps {
  cols?: number;
}

function SkeletonCell({ wide = false }: { wide?: boolean }) {
  return (
    <td className="px-4 py-3">
      <div className={`h-4 animate-pulse rounded bg-brand-border ${wide ? 'w-3/4' : 'w-1/2'}`} />
    </td>
  );
}

export default function SkeletonRow({ cols = 5 }: SkeletonRowProps) {
  return (
    <tr className="border-b border-brand-border">
      {Array.from({ length: cols }).map((_, i) => (
        <SkeletonCell key={i} wide={i === 0} />
      ))}
    </tr>
  );
}
