import { useEffect, useMemo, useRef, useState } from 'react';
import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from 'd3-force';
import type { NetworkEvent, Severity } from '../../core/types';
import { groupByDomain } from '../../core/session';
import { isThirdParty } from '../../core/url';
import { formatBytes } from '../../core/timings';
import { usePanelStore } from '../store';
import { EmptyState } from '../components/EmptyState';
import { displayHost } from '../lib/severity';

interface GraphNode extends SimulationNodeDatum {
  id: string;
  host: string;
  isPage: boolean;
  thirdParty: boolean;
  bytes: number;
  requests: number;
  severity: Severity | null;
}

interface GraphLink extends SimulationLinkDatum<GraphNode> {
  bytes: number;
}

const RISK_COLORS: Record<Severity, string> = {
  high: '#f43f5e',
  medium: '#f59e0b',
  low: '#0ea5e9',
  info: '#94a3b8',
};
const SAFE_COLOR = '#38e1c6';

export function MapView() {
  const events = usePanelStore((state) => state.events);
  const findings = usePanelStore((state) => state.findings);
  const pageUrl = usePanelStore((state) => state.pageUrl);
  const selectEvent = usePanelStore((state) => state.selectEvent);
  const containerRef = useRef<HTMLDivElement>(null);
  const [, setTick] = useState(0);
  const [size, setSize] = useState({ width: 800, height: 480 });
  const [hovered, setHovered] = useState<string | null>(null);

  useEffect(() => {
    const element = containerRef.current;
    if (!element) return;
    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (entry) setSize({ width: entry.contentRect.width, height: entry.contentRect.height });
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const severityByHost = useMemo(() => {
    const map = new Map<string, Severity>();
    const order: Record<Severity, number> = { high: 3, medium: 2, low: 1, info: 0 };
    for (const finding of findings) {
      const host = finding.domain;
      if (!host) continue;
      const current = map.get(host);
      if (!current || order[finding.severity] > order[current]) map.set(host, finding.severity);
    }
    return map;
  }, [findings]);

  const graph = useMemo(() => {
    const groups = groupByDomain(events);
    const pageHost = (() => {
      try {
        return new URL(pageUrl || events[0]?.pageUrl || '').hostname;
      } catch {
        return 'page';
      }
    })();
    const nodes: GraphNode[] = [
      {
        id: 'page',
        host: pageHost || 'page',
        isPage: true,
        thirdParty: false,
        bytes: 0,
        requests: 0,
        severity: severityByHost.get(pageHost) ?? null,
      },
    ];
    const links: GraphLink[] = [];
    for (const [host, hostEvents] of groups) {
      const bytes = hostEvents.reduce((sum, event) => sum + event.sizes.total, 0);
      nodes.push({
        id: host,
        host,
        isPage: false,
        thirdParty: isThirdParty(hostEvents[0]?.url ?? '', pageUrl || hostEvents[0]?.pageOrigin || ''),
        bytes,
        requests: hostEvents.length,
        severity: severityByHost.get(host) ?? null,
      });
      links.push({ source: 'page', target: host, bytes });
    }
    return { nodes, links };
  }, [events, pageUrl, severityByHost]);

  useEffect(() => {
    if (graph.nodes.length === 0) return;
    const simulation = forceSimulation<GraphNode>(graph.nodes)
      .force(
        'link',
        forceLink<GraphNode, GraphLink>(graph.links)
          .id((node) => node.id)
          .distance(130)
          .strength(0.5),
      )
      .force('charge', forceManyBody().strength(-420))
      .force('center', forceCenter(size.width / 2, size.height / 2))
      .force('collide', forceCollide<GraphNode>().radius((node) => radiusFor(node) + 18))
      .alphaDecay(0.035);
    simulation.on('tick', () => setTick((value) => value + 1));
    return () => {
      simulation.stop();
    };
  }, [graph, size.width, size.height]);

  const maxBytes = useMemo(
    () => graph.nodes.reduce((max, node) => Math.max(max, node.bytes), 1),
    [graph.nodes],
  );

  const openDomain = (host: string) => {
    const event = events.find((candidate: NetworkEvent) => displayHost(candidate.url) === host);
    if (event) selectEvent(event.id);
  };

  if (events.length === 0) {
    return (
      <EmptyState title="No domains mapped yet">
        <p>Capture a page load and this view draws every domain it talks to, first-party and third-party.</p>
      </EmptyState>
    );
  }

  return (
    <div className="flex h-full min-h-0">
      <div ref={containerRef} className="relative min-w-0 flex-1 grid-bg">
        <svg width={size.width} height={size.height} role="img" aria-label="Domain connection map">
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="18" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="rgba(148,163,184,0.5)" />
            </marker>
          </defs>
          {graph.links.map((link) => {
            const source = link.source as GraphNode;
            const target = link.target as GraphNode;
            if (!source || !target || source.x == null || target.x == null) return null;
            return (
              <line
                key={`${source.id}->${target.id}`}
                x1={source.x}
                y1={source.y}
                x2={target.x}
                y2={target.y}
                stroke={target.severity ? RISK_COLORS[target.severity] : 'rgba(148,163,184,0.45)'}
                strokeWidth={1 + Math.log2(1 + (link.bytes / maxBytes) * 15)}
                strokeOpacity={hovered === target.id ? 0.95 : 0.45}
                markerEnd="url(#arrow)"
              />
            );
          })}
          {graph.nodes.map((node) => {
            if (node.x == null || node.y == null) return null;
            const color = node.severity ? RISK_COLORS[node.severity] : SAFE_COLOR;
            const radius = radiusFor(node);
            return (
              <g
                key={node.id}
                transform={`translate(${node.x},${node.y})`}
                onMouseEnter={() => setHovered(node.id)}
                onMouseLeave={() => setHovered(null)}
                onClick={() => !node.isPage && openDomain(node.host)}
                className={node.isPage ? '' : 'cursor-pointer'}
                role={node.isPage ? undefined : 'button'}
                tabIndex={node.isPage ? undefined : 0}
                onKeyDown={(event) => {
                  if ((event.key === 'Enter' || event.key === ' ') && !node.isPage) openDomain(node.host);
                }}
              >
                <circle r={radius} fill={`${color}22`} stroke={color} strokeWidth={node.isPage ? 3 : 2} />
                <circle r={2.5} fill={color} />
                <text
                  y={radius + 13}
                  textAnchor="middle"
                  className="fill-slate-600 text-[10px] dark:fill-slate-300"
                  style={{ fontSize: 10 }}
                >
                  {node.host}
                </text>
                {node.thirdParty ? (
                  <text y={radius + 24} textAnchor="middle" style={{ fontSize: 8, fill: '#94a3b8' }}>
                    third-party · {node.requests} req
                  </text>
                ) : null}
                <title>
                  {node.host} · {node.requests} requests, {formatBytes(node.bytes)}
                  {node.severity ? `, worst finding: ${node.severity}` : ', no findings'}
                </title>
              </g>
            );
          })}
        </svg>
        <div className="pointer-events-none absolute left-3 top-3 rounded-md border border-slate-200 bg-white/85 px-2 py-1.5 text-[10px] text-slate-600 backdrop-blur dark:border-ink-700 dark:bg-ink-900/85 dark:text-slate-300">
          <div className="mb-1 font-semibold uppercase tracking-wider text-slate-400">Risk</div>
          <div className="flex flex-wrap gap-2">
            {(['high', 'medium', 'low'] as Severity[]).map((severity) => (
              <span key={severity} className="inline-flex items-center gap-1">
                <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: RISK_COLORS[severity] }} />
                {severity}
              </span>
            ))}
            <span className="inline-flex items-center gap-1">
              <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: SAFE_COLOR }} />
              clean
            </span>
          </div>
        </div>
      </div>

      <aside className="hidden w-64 shrink-0 overflow-y-auto border-l border-slate-200 p-2 dark:border-ink-700 lg:block">
        <h3 className="mb-1 px-1 text-[10px] font-bold uppercase tracking-wider text-slate-500">Domains by volume</h3>
        <ul className="space-y-0.5">
          {[...graph.nodes]
            .filter((node) => !node.isPage)
            .sort((a, b) => b.bytes - a.bytes)
            .map((node) => (
              <li key={node.id}>
                <button
                  type="button"
                  onClick={() => openDomain(node.host)}
                  className="w-full rounded px-1.5 py-1 text-left hover:bg-slate-100 dark:hover:bg-ink-800"
                >
                  <span className="flex items-center gap-1.5">
                    <span
                      aria-hidden="true"
                      className="h-1.5 w-1.5 shrink-0 rounded-full"
                      style={{ backgroundColor: node.severity ? RISK_COLORS[node.severity] : SAFE_COLOR }}
                    />
                    <span className="truncate text-[11px] text-slate-700 dark:text-slate-200">{node.host}</span>
                  </span>
                  <span className="ml-3 block text-[9px] text-slate-400">
                    {node.requests} req · {formatBytes(node.bytes)}
                    {node.thirdParty ? ' · third-party' : ''}
                  </span>
                </button>
              </li>
            ))}
        </ul>
      </aside>
    </div>
  );
}

function radiusFor(node: GraphNode): number {
  if (node.isPage) return 22;
  return Math.min(26, 8 + Math.log2(1 + node.bytes / 1024) * 1.8);
}
