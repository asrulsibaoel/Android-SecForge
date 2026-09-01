import { useMemo, useState } from 'react';
import { useParams } from 'react-router-dom';
import { getGraphSnapshot, getKnowledgeGraph, graphExportUrl, runGraphQuery } from '../api';
import type { GraphEdge, GraphNode, KnowledgeGraph } from '../api/types';
import { useApi } from '../hooks/useApi';
import { ResultGate } from '../components/States';
import { GraphView } from '../components/GraphView';
import { StatusBadge } from '../components/StatusBadge';
import { EvidenceDrawer } from '../components/EvidenceDrawer';

const CONF_RANK: Record<string, number> = { HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
const PRESET_QUERIES = ['exported-components', 'anti-analysis', 'analysis-uncertainty', 'unresolved-reflection', 'dynamic-load-paths', 'native-indirection', 'cve-reachable'];

function NodePanel({ node, edges, onClose, onFocus }: { node: GraphNode; edges: GraphEdge[]; onClose: () => void; onFocus: (id: string) => void }) {
  const related = edges.filter((e) => e.source === node.id || e.target === node.id);
  const prov = (node.provenance || []) as any[];
  return (
    <EvidenceDrawer title={`${node.type}: ${node.label}`} onClose={onClose}>
      <section>
        <dl className="kv">
          <dt>id</dt><dd>{node.id}</dd>
          <dt>type</dt><dd>{node.type}</dd>
          <dt>status</dt><dd><StatusBadge value={node.status} /></dd>
          <dt>confidence</dt><dd>{node.confidence || 'UNKNOWN'}</dd>
        </dl>
        <button className="btn" onClick={() => onFocus(node.id)}>Focus bounded neighborhood</button>
      </section>
      {prov.length > 0 && (
        <section><h3>Provenance</h3>
          <ul className="ev-list">{prov.map((p, i) => (
            <li key={i} className="ev-item">
              <span className="pill">{p.source_type}</span> {p.location || p.source_artifact || ''}
              {p.confidence && <span className="pill"> conf {p.confidence}</span>}
              {p.timestamp && <span className="muted"> · {p.timestamp}</span>}
            </li>
          ))}</ul>
        </section>
      )}
      <section><h3>Relationships ({related.length})</h3>
        <ul>{related.slice(0, 40).map((e) => (
          <li key={e.id}>
            {e.source === node.id ? '→' : '←'} <span className="pill">{e.type}</span> {e.source === node.id ? e.target : e.source}
            {(e.confidence ?? '').toUpperCase() === 'UNKNOWN' && <StatusBadge value="UNKNOWN" />}
          </li>
        ))}</ul>
      </section>
    </EvidenceDrawer>
  );
}

function GraphBody({ analysisId, kg }: { analysisId: string; kg: KnowledgeGraph }) {
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);
  const [typeFilter, setTypeFilter] = useState('');
  const [edgeFilter, setEdgeFilter] = useState('');
  const [minConf, setMinConf] = useState('');
  const [search, setSearch] = useState('');
  const [focus, setFocus] = useState<string | null>(null);
  const snapshot = useApi(() => getGraphSnapshot(analysisId), [analysisId]);
  const [query, setQuery] = useState(PRESET_QUERIES[0]);
  const [queryResult, setQueryResult] = useState<any | null>(null);
  const [queryError, setQueryError] = useState<string | null>(null);

  const nodeTypes = useMemo(() => [...new Set(kg.nodes.map((n) => n.type))].sort(), [kg]);
  const edgeTypes = useMemo(() => [...new Set(kg.edges.map((e) => e.type))].sort(), [kg]);

  const focusSet = useMemo(() => {
    if (!focus) return null;
    const s = new Set<string>([focus]);
    for (const e of kg.edges) {
      if (e.source === focus) s.add(e.target);
      if (e.target === focus) s.add(e.source);
    }
    return s;
  }, [focus, kg]);

  const nodes = kg.nodes.filter((n) =>
    (!typeFilter || n.type === typeFilter) &&
    (!minConf || (CONF_RANK[(n.confidence ?? 'UNKNOWN').toUpperCase()] ?? 0) >= CONF_RANK[minConf]) &&
    (!search || `${n.type} ${n.label} ${n.id}`.toLowerCase().includes(search.toLowerCase())) &&
    (!focusSet || focusSet.has(n.id)),
  );
  const nodeIds = new Set(nodes.map((n) => n.id));
  const edges = kg.edges.filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target) && (!edgeFilter || e.type === edgeFilter));

  async function runQuery() {
    setQueryError(null);
    setQueryResult(null);
    const r = await runGraphQuery(analysisId, query);
    if (r.status === 'success' || r.status === 'empty') setQueryResult(r.data ?? {});
    else setQueryError(r.error || r.status);
  }

  return (
    <div>
      <div className="pagehead">
        <h1>Knowledge Graph</h1>
        <div className="tag-row">
          <a className="btn" href={graphExportUrl(analysisId, 'graphml')}>GraphML</a>
          <a className="btn" href={graphExportUrl(analysisId, 'dot')}>DOT</a>
          <a className="btn" href={graphExportUrl(analysisId, 'json')}>JSON</a>
        </div>
      </div>
      <ResultGate result={snapshot.result} loadingLabel="Snapshot…">
        {(s: any) => (
          <div className="notice" style={{ marginBottom: '1rem' }}>
            Deterministic snapshot digest: <code>{s.digest || kg.digest}</code> · nodes {s.node_count ?? kg.nodes.length} · edges {s.edge_count ?? kg.edges.length}
            {kg.truncated && <span className="tone-attention"> · TRUNCATED projection</span>}
          </div>
        )}
      </ResultGate>

      <div className="filters">
        <label>node type<select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}><option value="">all</option>{nodeTypes.map((t) => <option key={t}>{t}</option>)}</select></label>
        <label>edge type<select value={edgeFilter} onChange={(e) => setEdgeFilter(e.target.value)}><option value="">all</option>{edgeTypes.map((t) => <option key={t}>{t}</option>)}</select></label>
        <label>min confidence<select value={minConf} onChange={(e) => setMinConf(e.target.value)}><option value="">any</option><option>LOW</option><option>MEDIUM</option><option>HIGH</option></select></label>
        <label>search<input type="search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="type / label / id" /></label>
        {focus && <button className="btn" onClick={() => setFocus(null)}>Clear focus</button>}
      </div>

      <GraphView nodes={nodes} edges={edges} selectedId={selected?.id} onSelectNode={setSelected} onSelectEdge={setSelectedEdge} />

      <div className="panel">
        <h3>Path / named query investigation</h3>
        <div className="filters">
          <label>query<select value={query} onChange={(e) => setQuery(e.target.value)}>{PRESET_QUERIES.map((q) => <option key={q}>{q}</option>)}</select></label>
          <button className="btn btn--primary" onClick={runQuery}>Run bounded query</button>
        </div>
        {queryError && <div className="state state--error">Query failed: {queryError}</div>}
        {queryResult && (
          <div>
            <p className="muted">count: {queryResult.count ?? (Array.isArray(queryResult.rows) ? queryResult.rows.length : '—')}
              {queryResult.truncated && <strong className="tone-attention"> · TRUNCATED</strong>}</p>
            <pre style={{ maxHeight: 240, overflow: 'auto', fontSize: '.78rem' }}>{JSON.stringify(queryResult, null, 1).slice(0, 4000)}</pre>
          </div>
        )}
      </div>

      {selected && <NodePanel node={selected} edges={kg.edges} onClose={() => setSelected(null)} onFocus={(id) => { setFocus(id); setSelected(null); }} />}
      {selectedEdge && (
        <EvidenceDrawer title={`Edge: ${selectedEdge.type}`} onClose={() => setSelectedEdge(null)}>
          <dl className="kv">
            <dt>type</dt><dd>{selectedEdge.type}</dd>
            <dt>source</dt><dd>{selectedEdge.source}</dd>
            <dt>target</dt><dd>{selectedEdge.target}</dd>
            <dt>confidence</dt><dd><StatusBadge value={selectedEdge.confidence} /></dd>
          </dl>
          {String(selectedEdge.confidence).toUpperCase() === 'UNKNOWN' && <p className="tone-unknown">UNKNOWN — not a confirmed relationship.</p>}
        </EvidenceDrawer>
      )}
    </div>
  );
}

export function GraphPage() {
  const { analysisId } = useParams();
  const { result } = useApi(() => getKnowledgeGraph(analysisId!), [analysisId]);
  return <ResultGate result={result} loadingLabel="Loading graph…" emptyTitle="NO GRAPH DATA">{(kg) => <GraphBody analysisId={analysisId!} kg={kg} />}</ResultGate>;
}
