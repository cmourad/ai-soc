import type { VpnStatus } from "@aisoc/shared";
import { useMemo } from "react";
import { cn, riskColor } from "@/lib/utils";

/**
 * Coarse landmass outlines in [lon, lat] pairs. They are rasterised onto a dot
 * grid rather than drawn as filled paths — at this size a dot matrix reads as a
 * world map, stays legible on a dark panel, and costs a few kilobytes instead of
 * shipping a topology file.
 */
const LAND: [number, number][][] = [
  [
    [-168, 65],
    [-141, 70],
    [-128, 70],
    [-110, 68],
    [-95, 70],
    [-85, 73],
    [-75, 68],
    [-60, 58],
    [-53, 47],
    [-66, 44],
    [-70, 41],
    [-76, 35],
    [-81, 25],
    [-97, 25],
    [-107, 23],
    [-114, 31],
    [-124, 40],
    [-125, 49],
    [-133, 55],
    [-141, 60],
    [-155, 58],
    [-165, 60],
  ],
  [
    [-92, 18],
    [-84, 16],
    [-77, 9],
    [-79, 7],
    [-88, 13],
    [-95, 16],
  ],
  [
    [-81, 8],
    [-72, 11],
    [-60, 11],
    [-50, 5],
    [-35, -5],
    [-38, -13],
    [-48, -25],
    [-58, -35],
    [-62, -40],
    [-65, -46],
    [-68, -53],
    [-73, -52],
    [-72, -40],
    [-71, -30],
    [-70, -18],
    [-77, -5],
    [-80, 0],
  ],
  [
    [-45, 60],
    [-20, 70],
    [-20, 82],
    [-45, 83],
    [-58, 76],
    [-55, 66],
  ],
  [
    [-10, 37],
    [-10, 44],
    [-5, 48],
    [2, 51],
    [8, 54],
    [13, 54],
    [20, 54],
    [28, 55],
    [30, 45],
    [24, 40],
    [15, 38],
    [10, 44],
    [3, 42],
    [-3, 36],
  ],
  [
    [5, 58],
    [10, 64],
    [18, 70],
    [28, 71],
    [31, 62],
    [22, 59],
    [12, 56],
  ],
  [
    [-6, 50],
    [-6, 58],
    [-2, 58],
    [0, 53],
    [-2, 50],
  ],
  [
    [-17, 15],
    [-17, 21],
    [-10, 27],
    [0, 32],
    [10, 34],
    [20, 32],
    [32, 31],
    [35, 23],
    [38, 15],
    [43, 11],
    [51, 12],
    [42, -1],
    [40, -10],
    [35, -20],
    [32, -26],
    [27, -33],
    [20, -34],
    [15, -25],
    [12, -16],
    [9, -1],
    [5, 5],
    [-5, 5],
    [-13, 9],
  ],
  [
    [35, 45],
    [45, 42],
    [55, 40],
    [60, 30],
    [68, 24],
    [70, 20],
    [73, 17],
    [77, 8],
    [80, 10],
    [85, 20],
    [90, 22],
    [95, 16],
    [99, 10],
    [103, 1],
    [106, 10],
    [110, 20],
    [117, 23],
    [122, 30],
    [122, 40],
    [128, 42],
    [130, 48],
    [135, 55],
    [142, 60],
    [160, 62],
    [170, 68],
    [178, 70],
    [160, 72],
    [140, 73],
    [120, 74],
    [100, 77],
    [80, 74],
    [65, 70],
    [60, 66],
    [50, 66],
    [40, 66],
    [32, 62],
    [30, 52],
  ],
  [
    [95, 5],
    [105, -2],
    [115, -4],
    [125, -2],
    [135, -3],
    [140, -8],
    [130, -9],
    [118, -9],
    [105, -7],
    [97, 2],
  ],
  [
    [113, -22],
    [114, -33],
    [118, -35],
    [130, -32],
    [138, -35],
    [145, -38],
    [150, -37],
    [153, -28],
    [146, -18],
    [140, -17],
    [135, -12],
    [130, -12],
    [125, -14],
    [118, -20],
  ],
  [
    [166, -46],
    [168, -44],
    [174, -41],
    [178, -38],
    [174, -36],
    [170, -42],
  ],
  [
    [130, 32],
    [135, 34],
    [140, 36],
    [142, 41],
    [145, 44],
    [141, 45],
    [138, 37],
    [133, 34],
  ],
  [
    [43, -13],
    [50, -16],
    [48, -25],
    [44, -22],
  ],
];

function inside(lon: number, lat: number, polygon: [number, number][]): boolean {
  let hit = false;
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
    const [xi, yi] = polygon[i]!;
    const [xj, yj] = polygon[j]!;
    if (yi > lat !== yj > lat && lon < ((xj - xi) * (lat - yi)) / (yj - yi) + xi) hit = !hit;
  }
  return hit;
}

const WIDTH = 720;
const HEIGHT = 340;
const STEP = 3.2;

const project = (lon: number, lat: number): [number, number] => [
  ((lon + 180) / 360) * WIDTH,
  ((90 - lat) / 165) * HEIGHT,
];

/** Lift the control point off the chord so overlapping routes stay distinct. */
function arc([x, y]: [number, number], [toX, toY]: [number, number]): string {
  const midX = (x + toX) / 2;
  const midY = (y + toY) / 2 - Math.abs(x - toX) * 0.22 - 12;
  return `M ${x} ${y} Q ${midX} ${midY} ${toX} ${toY}`;
}

export interface ThreatOrigin {
  id: string;
  lat: number;
  lon: number;
  label: string;
  country: string | null;
  asn: string | null;
  reputation: number;
  count: number;
}

/**
 * Where our traffic leaves from. An imported provider profile carries no
 * coordinates, so it can be named without being placed — hence nullable coords
 * rather than dropping the exit from the map entirely.
 */
export interface MapExit {
  coords: [lat: number, lon: number] | null;
  label: string;
  status: VpnStatus;
  /** Country-level guess from a profile name rather than a known exit position. */
  approximate: boolean;
}

const EXIT_STYLE: Record<VpnStatus, { stroke: string; fill: string; dot: string; march: boolean }> =
  {
    connected: { stroke: "stroke-ignore", fill: "fill-ignore", dot: "bg-ignore", march: false },
    connecting: { stroke: "stroke-watch", fill: "fill-watch", dot: "bg-watch", march: true },
    reconnecting: { stroke: "stroke-watch", fill: "fill-watch", dot: "bg-watch", march: true },
    error: { stroke: "stroke-block", fill: "fill-block", dot: "bg-block", march: true },
    disconnected: {
      stroke: "stroke-ink-dim",
      fill: "fill-ink-dim",
      dot: "bg-ink-dim",
      march: false,
    },
  };

export function ThreatMap({
  origins,
  home,
  exit,
  egressHeld,
  className,
}: {
  origins: ThreatOrigin[];
  home: { lat: number; lon: number; name: string };
  exit: MapExit | null;
  /** Kill switch is holding egress down: nothing is leaving, so nothing is drawn. */
  egressHeld: boolean;
  className?: string;
}) {
  const dots = useMemo(() => {
    const points: [number, number][] = [];
    for (let lat = 78; lat >= -56; lat -= STEP) {
      for (let lon = -180; lon <= 180; lon += STEP) {
        if (LAND.some((polygon) => inside(lon, lat, polygon))) points.push(project(lon, lat));
      }
    }
    return points;
  }, []);

  const homePoint = project(home.lon, home.lat);
  const [homeX, homeY] = homePoint;
  const maxCount = Math.max(1, ...origins.map((origin) => origin.count));

  const exitStyle = exit ? EXIT_STYLE[exit.status] : null;
  const exitPoint = exit?.coords ? project(exit.coords[1], exit.coords[0]) : null;
  const caption = exit ? `${home.name}, leaving via ${exit.label}` : `${home.name}, no tunnel`;

  // With the tunnel up the world reaches our exit, not our door — so routes
  // land there and the trunk carries the last leg home.
  const landing = exitPoint && exit?.status === "connected" ? exitPoint : homePoint;

  return (
    <div
      className={cn("relative overflow-hidden rounded-sm border border-edge bg-shell", className)}
    >
      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        className="h-full w-full"
        role="img"
        aria-label={caption}
      >
        <title>{caption}</title>

        {dots.map(([x, y]) => (
          <circle key={`${x}-${y}`} cx={x} cy={y} r={0.9} className="fill-[#3a3d41]" />
        ))}

        {/* Nothing is reaching the internet while the kill switch holds, so the
            routes fade out and only the held home node stays lit. */}
        <g opacity={egressHeld ? 0.15 : 1}>
          {origins.map((origin) => {
            const point = project(origin.lon, origin.lat);
            const weight = 0.6 + (origin.count / maxCount) * 1.6;
            return (
              <g key={origin.id}>
                <path
                  d={arc(point, landing)}
                  fill="none"
                  strokeWidth={weight}
                  className={origin.reputation >= 70 ? "stroke-block/50" : "stroke-watch/40"}
                />
                <circle
                  cx={point[0]}
                  cy={point[1]}
                  r={3 + Math.min(4, origin.count * 0.4)}
                  className={cn(
                    "pulse",
                    origin.reputation >= 70 ? "fill-block/70" : "fill-watch/60",
                  )}
                />
                <circle cx={point[0]} cy={point[1]} r={1.6} className="fill-white" />
              </g>
            );
          })}

          {exitPoint && exitStyle ? (
            <g>
              <path
                d={arc(homePoint, exitPoint)}
                fill="none"
                strokeWidth={5}
                className={cn(exitStyle.stroke, "opacity-15")}
              />
              <path
                d={arc(homePoint, exitPoint)}
                fill="none"
                strokeWidth={1.8}
                className={cn(exitStyle.stroke, exitStyle.march && "dash-march")}
              />
              <circle
                cx={exitPoint[0]}
                cy={exitPoint[1]}
                r={8}
                className={cn(exitStyle.fill, "opacity-20", exitStyle.march && "pulse")}
              />
              {/* A country guess gets a hollow ring: it marks a region, not a point. */}
              {exit?.approximate ? (
                <circle
                  cx={exitPoint[0]}
                  cy={exitPoint[1]}
                  r={3.4}
                  fill="none"
                  strokeWidth={1.4}
                  className={exitStyle.stroke}
                />
              ) : (
                <circle cx={exitPoint[0]} cy={exitPoint[1]} r={3.4} className={exitStyle.fill} />
              )}
            </g>
          ) : null}
        </g>

        <circle cx={homeX} cy={homeY} r={7} className="fill-status/25" />
        <circle cx={homeX} cy={homeY} r={3} className="fill-status" />
        {egressHeld ? (
          <circle
            cx={homeX}
            cy={homeY}
            r={11}
            fill="none"
            strokeWidth={1.2}
            className="stroke-block"
          />
        ) : null}
      </svg>

      <div className="pointer-events-none absolute inset-x-0 bottom-0 flex flex-wrap gap-x-4 gap-y-1 bg-gradient-to-t from-shell to-transparent px-3 py-2 text-[10px] text-ink-dim">
        <span className="flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-status" />
          {home.name}
          {egressHeld ? <span className="text-block">egress held</span> : null}
        </span>
        {exit && exitStyle ? (
          <span className="flex items-center gap-1.5">
            <span className={cn("h-1.5 w-1.5 rounded-full", exitStyle.dot)} />
            <span className="text-ink">{exit.label}</span>
            <span>
              {exit.coords === null
                ? "exit · location unknown"
                : exit.approximate
                  ? "exit · country only"
                  : "exit"}
            </span>
          </span>
        ) : (
          <span className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-ink-dim" />
            direct — no tunnel
          </span>
        )}
        {origins.slice(0, 5).map((origin) => (
          <span key={origin.id} className="flex items-center gap-1.5">
            <span
              className={cn(
                "h-1.5 w-1.5 rounded-full",
                origin.reputation >= 70 ? "bg-block" : "bg-watch",
              )}
            />
            <span className="font-mono text-ink">{origin.label}</span>
            {origin.country ? <span>{origin.country}</span> : null}
            {origin.asn ? <span className="font-mono">{origin.asn}</span> : null}
            <span className={riskColor(origin.reputation)}>{origin.count}×</span>
          </span>
        ))}
        {origins.length === 0 ? <span>No geolocated attack origins yet.</span> : null}
      </div>
    </div>
  );
}
