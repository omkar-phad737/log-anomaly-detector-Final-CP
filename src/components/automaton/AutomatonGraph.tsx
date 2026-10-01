import { Fragment } from "react";
import { DELTA, STATES, ACCEPTING_STATES, START_STATE } from "@/lib/automaton";

/**
 * Hand-laid-out SVG visualisation of the DFA.
 *
 * Nodes = states Q, arrows = transitions δ, double circles = accepting
 * states F. When an anomaly is selected the offending transition (or the
 * state with no valid transition) is highlighted.
 */

const R = 27; // node radius

type NodeName = keyof typeof NODE_POS;

const NODE_POS: Record<string, { x: number; y: number }> = {
  q0: { x: 90, y: 285 },
  q1: { x: 250, y: 285 },
  q1f1: { x: 345, y: 465 },
  q1f2: { x: 480, y: 465 },
  q1f3: { x: 615, y: 465 },
  q2: { x: 470, y: 205 },
  q3: { x: 735, y: 515 },
  q4: { x: 695, y: 285 },
  q5: { x: 900, y: 285 },
};

interface EdgeSpec {
  from: string;
  to: string;
  events: string[];
  /** Perpendicular bend of the curve (positive = left of travel). */
  bend?: number;
  /** Explicit cubic controls (overrides bend). */
  c1?: [number, number];
  c2?: [number, number];
  /** Self-loop direction. */
  loop?: "up" | "down";
  /** Where along the curve to place the label (0..1). */
  labelT?: number;
}

const EDGES: EdgeSpec[] = [
  { from: "q0", to: "q1", events: ["LOGIN"] },
  { from: "q1", to: "q2", events: ["AUTH_SUCCESS"], bend: -18 },
  { from: "q1", to: "q1f1", events: ["AUTH_FAILURE"] },
  { from: "q1f1", to: "q1f2", events: ["AUTH_FAILURE"] },
  { from: "q1f2", to: "q1f3", events: ["AUTH_FAILURE"] },
  { from: "q1f1", to: "q2", events: ["AUTH_SUCCESS"], bend: 30, labelT: 0.35 },
  { from: "q1f2", to: "q2", events: ["AUTH_SUCCESS"] },
  { from: "q1f3", to: "q2", events: ["AUTH_SUCCESS"], bend: -30, labelT: 0.35 },
  { from: "q1", to: "q3", events: ["LOGOUT", "SESSION_TIMEOUT"], bend: -34 },
  { from: "q1f1", to: "q3", events: ["LOGOUT", "SESSION_TIMEOUT"], bend: 26 },
  { from: "q1f2", to: "q3", events: ["LOGOUT", "SESSION_TIMEOUT"], bend: 14 },
  { from: "q1f3", to: "q3", events: ["LOGOUT", "SESSION_TIMEOUT"], bend: 6 },
  {
    from: "q2",
    to: "q2",
    loop: "up",
    events: [
      "FILE_ACCESS",
      "FILE_DELETE",
      "PASSWORD_CHANGE",
      "USER_ACCESS",
      "API_ACCESS",
    ],
  },
  { from: "q2", to: "q3", events: ["LOGOUT", "SESSION_TIMEOUT"], bend: 18 },
  { from: "q2", to: "q4", events: ["PRIVILEGE_CHANGE"], bend: -14 },
  {
    from: "q3",
    to: "q1",
    events: ["LOGIN"],
    c1: [640, 600],
    c2: [230, 560],
  },
  { from: "q4", to: "q5", events: ["ADMIN_ACCESS"], bend: 12 },
  {
    from: "q4",
    to: "q4",
    loop: "down",
    events: [
      "FILE_ACCESS",
      "FILE_DELETE",
      "CONFIG_CHANGE",
      "PASSWORD_CHANGE",
      "USER_ACCESS",
    ],
  },
  { from: "q4", to: "q3", events: ["LOGOUT", "SESSION_TIMEOUT"], bend: -22 },
  {
    from: "q5",
    to: "q5",
    loop: "up",
    events: [
      "DATABASE_ACCESS",
      "FILE_ACCESS",
      "FILE_DELETE",
      "CONFIG_CHANGE",
      "API_ACCESS",
      "PASSWORD_CHANGE",
      "USER_ACCESS",
    ],
  },
  { from: "q5", to: "q3", events: ["LOGOUT", "SESSION_TIMEOUT"], bend: 24 },
];

// ---------- small geometry helpers ----------

const sub = (a: { x: number; y: number }, b: { x: number; y: number }) => ({
  x: a.x - b.x,
  y: a.y - b.y,
});
const add = (a: { x: number; y: number }, b: { x: number; y: number }) => ({
  x: a.x + b.x,
  y: a.y + b.y,
});
const mul = (a: { x: number; y: number }, k: number) => ({
  x: a.x * k,
  y: a.y * k,
});
const len = (a: { x: number; y: number }) => Math.hypot(a.x, a.y);
const unit = (a: { x: number; y: number }) => mul(a, 1 / len(a));
const normal = (a: { x: number; y: number }) => ({ x: -a.y, y: a.x });

/** Point on the node border towards `dir`. */
function border(p: { x: number; y: number }, dir: { x: number; y: number }, pad = 0) {
  const u = unit(dir);
  return { x: p.x + u.x * (R + 2 + pad), y: p.y + u.y * (R + 2 + pad) };
}

function pathFor(edge: EdgeSpec): { d: string; label: { x: number; y: number } } {
  const p1 = NODE_POS[edge.from as NodeName];
  const p2 = NODE_POS[edge.to as NodeName];

  if (edge.loop) {
    // Outward self-loop drawn as a cubic bump.
    const a = edge.loop === "up" ? -Math.PI / 2 : Math.PI / 2;
    const u = (t: number) => ({ x: Math.cos(t), y: Math.sin(t) });
    const s = add(p1, mul(u(a - 0.55), R + 2));
    const e = add(p1, mul(u(a + 0.55), R + 2));
    const c1 = add(p1, mul(u(a - 1.0), R + 34));
    const c2 = add(p1, mul(u(a + 1.0), R + 34));
    const label = add(p1, mul(u(a), R + 52));
    return { d: `M ${s.x} ${s.y} C ${c1.x} ${c1.y}, ${c2.x} ${c2.y}, ${e.x} ${e.y}`, label };
  }

  const s = border(p1, sub(p2, p1), 4);
  const e = border(p2, sub(p1, p2), 8); // leave room for arrowhead
  let c: { x: number; y: number };
  let cubic = false;
  let c2pt = e;
  if (edge.c1 && edge.c2) {
    c = { x: edge.c1[0], y: edge.c1[1] };
    c2pt = { x: edge.c2[0], y: edge.c2[1] };
    cubic = true;
  } else {
    const m = mul(add(s, e), 0.5);
    c = add(m, mul(normal(unit(sub(e, s))), edge.bend ?? 0));
  }
  const t = edge.labelT ?? 0.5;
  const pt = cubic
    ? {
        x:
          (1 - t) ** 3 * s.x + 3 * (1 - t) ** 2 * t * c.x + 3 * (1 - t) * t ** 2 * c2pt.x + t ** 3 * e.x,
        y:
          (1 - t) ** 3 * s.y + 3 * (1 - t) ** 2 * t * c.y + 3 * (1 - t) * t ** 2 * c2pt.y + t ** 3 * e.y,
      }
    : {
        x: (1 - t) ** 2 * s.x + 2 * (1 - t) * t * c.x + t ** 2 * e.x,
        y: (1 - t) ** 2 * s.y + 2 * (1 - t) * t * c.y + t ** 2 * e.y,
      };
  const n = cubic ? { x: 0, y: 0 } : normal(unit(sub(e, s)));
  const label = cubic ? { x: pt.x, y: pt.y + 10 } : add(pt, mul(n, edge.bend && edge.bend < 0 ? -11 : 11));
  const d = cubic
    ? `M ${s.x} ${s.y} C ${c.x} ${c.y}, ${c2pt.x} ${c2pt.y}, ${e.x} ${e.y}`
    : `M ${s.x} ${s.y} Q ${c.x} ${c.y}, ${e.x} ${e.y}`;
  return { d, label };
}

/** Split edge events into ≤2-per-line label rows. */
function labelLines(events: string[]): string[] {
  const lines: string[] = [];
  for (let i = 0; i < events.length; i += 2) {
    lines.push(events.slice(i, i + 2).join(" · "));
  }
  return lines;
}

// ---------- component ----------

export interface GraphHighlight {
  from: string;
  event: string;
  to: string;
  kind: "invalid" | "policy";
}

const RED = "#ef4444";
const CYAN = "#22d3ee";

export function AutomatonGraph({
  highlight,
  currentState,
}: {
  highlight?: GraphHighlight | null;
  currentState?: string | null;
}) {
  const highlightEdgeIdx = highlight
    ? EDGES.findIndex(
        (e) =>
          e.from === highlight.from &&
          e.to === highlight.to &&
          e.events.includes(highlight.event),
      )
    : -1;

  return (
    <div className="overflow-x-auto rounded-lg border border-border/60 bg-background/40 p-2">
      <svg
        viewBox="0 0 1000 600"
        className="mx-auto block h-auto w-full min-w-[720px]"
        role="img"
        aria-label="DFA state diagram"
      >
        <defs>
          <marker
            id="arrow"
            viewBox="0 0 10 10"
            refX="9"
            refY="5"
            markerWidth="7"
            markerHeight="7"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" fill="oklch(0.55 0.02 260)" />
          </marker>
          <marker
            id="arrow-red"
            viewBox="0 0 10 10"
            refX="9"
            refY="5"
            markerWidth="8"
            markerHeight="8"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" fill={RED} />
          </marker>
        </defs>

        {/* start-state arrow into q0 */}
        <line
          x1={NODE_POS.q0.x - R - 34}
          y1={NODE_POS.q0.y}
          x2={NODE_POS.q0.x - R - 6}
          y2={NODE_POS.q0.y}
          stroke="oklch(0.55 0.02 260)"
          strokeWidth="1.6"
          markerEnd="url(#arrow)"
        />
        <text
          x={NODE_POS.q0.x - R - 40}
          y={NODE_POS.q0.y + 4}
          textAnchor="end"
          fontSize="10"
          fill="oklch(0.6 0.02 260)"
        >
          start
        </text>

        {/* base edges */}
        {EDGES.map((e, i) => {
          const { d, label } = pathFor(e);
          const dimmed = highlightEdgeIdx >= 0 && highlightEdgeIdx !== i;
          return (
            <g key={i} opacity={dimmed ? 0.35 : 1}>
              <path
                d={d}
                fill="none"
                stroke="oklch(0.55 0.02 260 / 0.75)"
                strokeWidth="1.4"
                markerEnd="url(#arrow)"
              />
              <text
                x={label.x}
                y={label.y}
                textAnchor="middle"
                fontSize="9.5"
                className="font-mono"
                fill="oklch(0.62 0.02 260)"
                stroke="var(--background)"
                strokeWidth="4"
                paintOrder="stroke"
              >
                {labelLines(e.events).map((line, li) => (
                  <tspan key={li} x={label.x} dy={li === 0 ? 0 : 11}>
                    {line}
                  </tspan>
                ))}
              </text>
            </g>
          );
        })}

        {/* highlighted policy-flagged transition (valid but suspicious) */}
        {highlight && highlight.kind === "policy" && highlightEdgeIdx >= 0 && (
          <path
            d={pathFor(EDGES[highlightEdgeIdx]).d}
            fill="none"
            stroke={RED}
            strokeWidth="2.6"
            markerEnd="url(#arrow-red)"
            className="animate-pulse"
          />
        )}

        {/* invalid transition: ring the state that rejected the event */}
        {highlight && highlight.kind === "invalid" && (
          <g>
            <circle
              cx={NODE_POS[highlight.from]?.x}
              cy={NODE_POS[highlight.from]?.y}
              r={R + 7}
              fill="none"
              stroke={RED}
              strokeWidth="2.5"
              strokeDasharray="5 4"
              className="animate-pulse"
            />
            <text
              x={NODE_POS[highlight.from]?.x}
              y={NODE_POS[highlight.from]?.y - R - 14}
              textAnchor="middle"
              fontSize="10.5"
              className="font-mono"
              fill={RED}
              stroke="var(--background)"
              strokeWidth="4"
              paintOrder="stroke"
            >
              ✗ {highlight.event}
            </text>
          </g>
        )}

        {/* nodes */}
        {Object.entries(NODE_POS).map(([name, p]) => {
          const st = STATES[name];
          const accepting = ACCEPTING_STATES.includes(name);
          const isCurrent = currentState === name;
          const isRejected = highlight?.kind === "invalid" && highlight.from === name;
          const isFlagged = highlight?.kind === "policy" && highlight.to === name;
          return (
            <g key={name}>
              {isCurrent && (
                <circle
                  cx={p.x}
                  cy={p.y}
                  r={R + 9}
                  fill={CYAN}
                  opacity={0.18}
                  className="animate-pulse"
                />
              )}
              {accepting && (
                <circle
                  cx={p.x}
                  cy={p.y}
                  r={R + 5}
                  fill="none"
                  stroke="oklch(0.55 0.02 260)"
                  strokeWidth="1.3"
                />
              )}
              <circle
                cx={p.x}
                cy={p.y}
                r={R}
                fill={
                  isRejected || isFlagged
                    ? "oklch(0.3 0.12 25)"
                    : isCurrent
                      ? "oklch(0.35 0.07 220)"
                      : "oklch(0.24 0.03 262)"
                }
                stroke={
                  isRejected || isFlagged
                    ? RED
                    : isCurrent
                      ? CYAN
                      : "oklch(0.5 0.03 260)"
                }
                strokeWidth={isCurrent || isRejected || isFlagged ? 2.4 : 1.5}
              />
              <text
                x={p.x}
                y={p.y + 4}
                textAnchor="middle"
                fontSize="13"
                fontWeight={700}
                className="font-mono"
                fill="var(--foreground)"
              >
                {name}
              </text>
              <text
                x={p.x}
                y={p.y + R + 16}
                textAnchor="middle"
                fontSize="9.5"
                className="font-mono"
                fill="oklch(0.6 0.02 260)"
                stroke="var(--background)"
                strokeWidth="4"
                paintOrder="stroke"
              >
                {st?.label ?? name}
              </text>
            </g>
          );
        })}
      </svg>

      {/* legend */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 px-2 pb-1 pt-2 text-[11px] text-muted-foreground">
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full border border-[oklch(0.5_0.03_260)] bg-[oklch(0.24_0.03_262)]" />
          state
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full border-2 border-[oklch(0.5_0.03_260)] bg-[oklch(0.24_0.03_262)]" />
          accepting state (F)
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full border-2 border-cyan-400 bg-cyan-400/20" />
          current state
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full border-2 border-dashed border-red-500 bg-red-500/20" />
          invalid transition
        </span>
        <span className="flex items-center gap-1.5">
          <span className="font-mono text-red-400">✗ EVENT</span>
          no transition defined for that symbol
        </span>
      </div>
    </div>
  );}

/** The full δ table, state by state — the precise reference for the graph. */
export function TransitionTable() {
  return (
    <div className="overflow-hidden rounded-lg border">
      <div className="max-h-72 overflow-y-auto">
        <table className="w-full text-left text-xs">
          <thead className="sticky top-0 bg-muted/70 backdrop-blur">
            <tr className="text-muted-foreground">
              <th className="px-3 py-2 font-medium">Current state</th>
              <th className="px-3 py-2 font-medium">Event (symbol)</th>
              <th className="px-3 py-2 font-medium">Next state</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(DELTA).map(([state, table]) => (
              <Fragment key={state}>
                <tr className="border-t bg-muted/30">
                  <td colSpan={3} className="px-3 py-1.5 font-mono text-[11px] font-semibold">
                    {state} · {STATES[state]?.label}
                    {ACCEPTING_STATES.includes(state) && (
                      <span className="ml-2 text-[10px] font-normal text-muted-foreground">
                        (accepting)
                      </span>
                    )}
                    {state === START_STATE && (
                      <span className="ml-2 text-[10px] font-normal text-muted-foreground">
                        (start)
                      </span>
                    )}
                  </td>
                </tr>
                {Object.entries(table).map(([event, to]) => (
                  <tr key={`${state}-${event}`} className="border-t border-border/40">
                    <td className="px-3 py-1.5 text-muted-foreground">{state}</td>
                    <td className="px-3 py-1.5 font-mono text-[11px]">{event}</td>
                    <td className="px-3 py-1.5 font-mono text-[11px]">
                      → {to}
                      <span className="ml-2 text-[10px] text-muted-foreground">
                        {STATES[to]?.label}
                      </span>
                    </td>
                  </tr>
                ))}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
