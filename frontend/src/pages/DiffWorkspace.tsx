import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { getComparison, getComparisonChanges, getComparisonSummary } from '../api';
import { useApi } from '../hooks/useApi';
import { ResultGate } from '../components/States';
import { StatusBadge } from '../components/StatusBadge';
import { DataTable, type Column } from '../components/DataTable';

export function DiffWorkspace() {
  const { comparisonId } = useParams();
  const detail = useApi(() => getComparison(comparisonId!), [comparisonId]);
  const summary = useApi(() => getComparisonSummary(comparisonId!), [comparisonId]);
  const changes = useApi(() => getComparisonChanges(comparisonId!), [comparisonId]);
  const [category, setCategory] = useState('');

  const changeCols: Column<any>[] = [
    { key: 'category', header: 'Category', render: (r) => <span className="pill">{r.category}</span>, sortValue: (r) => r.category },
    { key: 'entity', header: 'Entity', render: (r) => <span className="muted" title={r.entity_identity}>{r.entity_type}: {String(r.entity_identity ?? '').slice(0, 40)}</span>, sortValue: (r) => `${r.category}:${r.entity_type}` },
    { key: 'change', header: 'Change', render: (r) => <StatusBadge value={r.change_type} />, sortValue: (r) => r.change_type },
    { key: 'transition', header: 'Transition', render: (r) => <StatusBadge value={r.evidence?.transition} />, sortValue: (r) => r.evidence?.transition ?? '' },
    { key: 'security', header: 'Security-relevant', render: (r) => (r.security_relevant ? <span className="tone-attention">yes</span> : <span className="muted">no</span>), sortValue: (r) => (r.security_relevant ? 1 : 0) },
    { key: 'confidence', header: 'Confidence', render: (r) => r.confidence, sortValue: (r) => r.confidence },
  ];

  return (
    <div>
      <div className="pagehead"><h1>APK Diff (A → B)</h1></div>
      <ResultGate result={summary.result} loadingLabel="Loading comparison…">
        {(s: any) => (
          <div className="grid grid-4">
            <div className="stat"><div className="stat__label">Status</div><div className="stat__value" style={{ fontSize: '1rem' }}><StatusBadge value={s.status} /></div></div>
            <div className="stat"><div className="stat__label">Security impact</div><div className="stat__value" style={{ fontSize: '.95rem' }}><StatusBadge value={s.security_impact} /></div></div>
            <div className="stat"><div className="stat__label">Impact confidence</div><div className="stat__value" style={{ fontSize: '1rem' }}><StatusBadge value={s.impact_confidence} /></div></div>
            <div className="stat"><div className="stat__label">Snapshot mode</div><div className="stat__value" style={{ fontSize: '1rem' }}>{s.snapshot_mode}</div></div>
          </div>
        )}
      </ResultGate>

      <ResultGate result={detail.result} emptyTitle="NO COMPARISON DATA">
        {(d: any) => (
          <div className="notice" style={{ marginBottom: '1rem' }}>
            baseline <code>{String(d.baseline_id ?? d.baseline ?? '').slice(0, 8)}</code> → candidate <code>{String(d.candidate_id ?? d.candidate ?? '').slice(0, 8)}</code>
            {' · '}risk delta {d.risk_delta?.delta ?? d.summary?.risk_delta ?? 'UNKNOWN'}
          </div>
        )}
      </ResultGate>

      <div className="panel">
        <h3>Changes</h3>
        <p className="muted">A REMOVED finding is NO_LONGER_DETECTED — never FIXED. A new finding is never EXPLOITABLE.</p>
        <ResultGate result={changes.result} emptyTitle="NO CHANGES" emptyHint="No differences detected between A and B in the persisted categories.">
          {(rows: any[]) => {
            const cats = [...new Set(rows.map((r) => r.category))].sort();
            const filtered = category ? rows.filter((r) => r.category === category) : rows;
            return (
              <>
                <div className="filters">
                  <label>category<select value={category} onChange={(e) => setCategory(e.target.value)}><option value="">all</option>{cats.map((c) => <option key={c}>{c}</option>)}</select></label>
                </div>
                <DataTable rows={filtered} columns={changeCols} rowKey={(r) => `${r.category}:${r.entity_type}:${r.entity_identity}:${r.change_type}`} initialSort={{ key: 'category', dir: 'asc' }} />
              </>
            );
          }}
        </ResultGate>
      </div>
    </div>
  );
}
