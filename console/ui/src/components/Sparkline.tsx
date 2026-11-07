export function Sparkline({
  points,
  className,
  stroke = "#4ec9b0",
}: {
  points: number[];
  className?: string;
  stroke?: string;
}) {
  const width = 160;
  const height = 34;
  if (points.length < 2) {
    return <svg className={className} width={width} height={height} aria-hidden="true" />;
  }

  const max = Math.max(1, ...points);
  const step = width / (points.length - 1);
  const coords = points.map((value, index) => [
    index * step,
    height - (value / max) * (height - 4) - 2,
  ]);
  const line = coords.map(([x, y]) => `${x!.toFixed(1)},${y!.toFixed(1)}`).join(" ");
  const area = `0,${height} ${line} ${width},${height}`;

  return (
    <svg
      className={className}
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label={`Recent rate, peak ${max.toFixed(1)} per second`}
    >
      <polygon points={area} fill={stroke} opacity="0.14" />
      <polyline points={line} fill="none" stroke={stroke} strokeWidth="1.5" />
    </svg>
  );
}
