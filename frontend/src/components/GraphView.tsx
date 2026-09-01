import { useMemo, useRef, useState, type PointerEvent, type WheelEvent } from 'react';
import type { GraphEdge, GraphNode } from '../api/types';

// A bounded SVG rendering of BACKEND graph data (§6/§23). This is ONLY a renderer
// — it constructs no second canonical graph, computes no analytical truth, and
// never fabricates edges. Layout is deterministic (type-clustered radial keyed by
// node id order). Rendering is bounded by `maxNodes`; excess is shown as TRUNCATED,
// never silently dropped. An UNKNOWN edge is drawn dashed and labelled, never as a
// confirmed relationship.

// Distinct visual class per node type (color + shape via CSS). Text label always
// present — never color alone.
function typeClass(type: string): string {
  return 'gt-' + type.toLowerCase().replace(/[^a-z0-9]+/g, '-');
}

interface Positioned extends GraphNode {
  x: number;
  y: number;
}

function layout(nodes: GraphNode[]): Positioned[] {
  const byType = new Map<string, GraphNode[]>();
  for (const n of nodes) {
    const arr = byType.get(n.type) ?? [];
    arr.push(n);
    byType.set(n.type, arr);
  }
  const types = [...byType.keys()].sort();
  const R = 420;
  const out: Positioned[] = [];
  types.forEach((t, ti) => {
    const cluster = byType.get(t)!.slice().sort((a, b) => (a.id < b.id ? -1 : 1));
    const ca = (2 * Math.PI * ti) / Math.max(1, types.length);
    const cx = 500 + R * Math.cos(ca);
    const cy = 400 + R * Math.sin(ca);
    const cr = 30 + Math.min(160, cluster.length * 7);
    cluster.forEach((n, ni) => {
      const a = (2 * Math.PI * ni) / Math.max(1, cluster.length);
      out.push({ ...n, x: cx + cr * Math.cos(a), y: cy + cr * Math.sin(a) });
    });
  });
  return out;
}

export function GraphView({
  nodes,
  edges,
  selectedId,
  onSelectNode,
  onSelectEdge,
  maxNodes = 400,
}: {
  nodes: GraphNode[];
  edges: GraphEdge[];
  selectedId?: string | null;
  onSelectNode?: (n: GraphNode) => void;
  onSelectEdge?: (e: GraphEdge) => void;
  maxNodes?: number;
}) {
  const [view, setView] = useState({ x: 0, y: 0, scale: 1 });
  const drag = useRef<{ x: number; y: number } | null>(null);

  const shown = nodes.slice(0, maxNodes);
  const truncatedNodes = Math.max(0, nodes.length - maxNodes);
  const positioned = useMemo(() => layout(shown), [shown]);
  const pos = useMemo(() => new Map(positioned.map((p) => [p.id, p])), [positioned]);
  const visibleEdges = edges.filter((e) => pos.has(e.source) && pos.has(e.target));

  function onWheel(e: WheelEvent) {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.1 : 0.9;
    setView((v) => ({ ...v, scale: Math.max(0.15, Math.min(4, v.scale * factor)) }));
  }
  function onPointerDown(e: PointerEvent) {
    drag.current = { x: e.clientX - view.x, y: e.clientY - view.y };
    (e.target as Element).setPointerCapture?.(e.pointerId);
  }
  function onPointerMove(e: PointerEvent) {
    if (!drag.current) return;
    setView((v) => ({ ...v, x: e.clientX - drag.current!.x, y: e.clientY - drag.current!.y }));
  }
  function onPointerUp() {
    drag.current = null;
  }

  return (
    <div className="graph">
      {truncatedNodes > 0 && (
        <div className="graph__truncated tone-attention" role="status">
          TRUNCATED — showing {shown.length} of {nodes.length} nodes. Use filters / bounded expansion to refine.
        </div>
      )}
      <div className="graph__controls">
        <button className="btn" onClick={() => setView((v) => ({ ...v, scale: Math.min(4, v.scale * 1.2) }))} aria-label="Zoom in">+</button>
        <button className="btn" onClick={() => setView((v) => ({ ...v, scale: Math.max(0.15, v.scale * 0.8) }))} aria-label="Zoom out">−</button>
        <button className="btn" onClick={() => setView({ x: 0, y: 0, scale: 1 })} aria-label="Reset view">Reset</button>
        <span className="muted">{shown.length} nodes · {visibleEdges.length} edges</span>
      </div>
      <svg
        className="graph__svg"
        viewBox="0 0 1000 800"
        role="img"
        aria-label={`Knowledge graph, ${shown.length} nodes`}
        onWheel={onWheel}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerLeave={onPointerUp}
      >
        <g transform={`translate(${view.x} ${view.y}) scale(${view.scale})`}>
          {visibleEdges.map((e) => {
            const a = pos.get(e.source)!;
            const b = pos.get(e.target)!;
            const unknown = String(e.type).toUpperCase().includes('UNKNOWN') || (e.confidence ?? '').toUpperCase() === 'UNKNOWN';
            return (
              <line
                key={e.id}
                x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                className={`graph-edge ${unknown ? 'graph-edge--unknown' : ''}`}
                strokeDasharray={unknown ? '4 4' : undefined}
                onClick={() => onSelectEdge?.(e)}
              >
                <title>{`${e.type}${unknown ? ' (UNKNOWN — not a confirmed relationship)' : ''}`}</title>
              </line>
            );
          })}
          {positioned.map((n) => (
            <g key={n.id} className={`graph-node ${typeClass(n.type)} ${selectedId === n.id ? 'is-selected' : ''}`}
               transform={`translate(${n.x} ${n.y})`}
               onClick={() => onSelectNode?.(n)}
               tabIndex={0}
               role="button"
               aria-label={`${n.type}: ${n.label}`}
               onKeyDown={(e) => { if (e.key === 'Enter') onSelectNode?.(n); }}>
              <circle r={selectedId === n.id ? 9 : 6} />
              <text x={10} y={4}>{n.label?.slice(0, 22)}</text>
              <title>{`${n.type}: ${n.label}`}</title>
            </g>
          ))}
        </g>
      </svg>
    </div>
  );
}
