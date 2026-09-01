import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { explainRemediation, getRemediation } from '../api';
import type { RemediationItem } from '../api/types';
import { useApi } from '../hooks/useApi';
import { ResultGate } from '../components/States';
import { DataTable, type Column } from '../components/DataTable';
import { StatusBadge } from '../components/StatusBadge';
import { EvidenceDrawer } from '../components/EvidenceDrawer';
import { ExplanationView } from '../components/ExplanationView';

const PRIO: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1, UNDETERMINED: 0 };

function ItemDrawer({ analysisId, item, onClose }: { analysisId: string; item: RemediationItem; onClose: () => void }) {
  const explain = useApi(() => explainRemediation(analysisId, item.id), [analysisId, item.id]);
  return (
    <EvidenceDrawer title={item.action} evidence={item.evidence} onClose={onClose}>
      <section>
        <div className="tag-row" style={{ marginBottom: '.6rem' }}>
          <StatusBadge value={item.priority} kind="priority" />
          <StatusBadge value={item.status} />
          <span className="pill">fixability: {item.fixability}</span>
          <span className="pill">confidence: {item.confidence}</span>
        </div>
        <h3>{item.title}</h3>
        {item.description && <p>{item.description}</p>}
        <dl className="kv">
          <dt>target</dt><dd>{item.target || 'UNKNOWN'}</dd>
          <dt>current state</dt><dd>{item.current_state || 'UNKNOWN'}</dd>
          <dt>recommended state</dt><dd>{item.recommended_state || 'UNKNOWN'}</dd>
        </dl>
        {item.priority_factors && item.priority_factors.length > 0 && (
          <><h4>Priority factors (separate axis from severity)</h4>
            <ul>{item.priority_factors.map((f, i) => <li key={i}>{f.name} ({f.weight > 0 ? '+' : ''}{f.weight}) — {f.reason}</li>)}</ul></>
        )}
        {item.uncertainties && item.uncertainties.length > 0 && (
          <ul className="tone-unknown">{item.uncertainties.map((u, i) => <li key={i}>⚠ {u}</li>)}</ul>
        )}
      </section>
      <section>
        <h3>Why this recommendation exists</h3>
        <ResultGate result={explain.result} emptyTitle="NO EXPLANATION AVAILABLE">{(p) => <ExplanationView payload={p} />}</ResultGate>
      </section>
      <p className="muted" style={{ fontSize: '.8rem' }}>
        Recommendation only — there is no automatic fix or “Apply Patch”. HIGH priority does not mean a confirmed
        vulnerability; priority is separate from severity and risk.
      </p>
    </EvidenceDrawer>
  );
}

export function Remediation() {
  const { analysisId } = useParams();
  const { result } = useApi(() => getRemediation(analysisId!), [analysisId]);
  const [selected, setSelected] = useState<RemediationItem | null>(null);
  const columns: Column<RemediationItem>[] = [
    { key: 'action', header: 'Action', render: (r) => <strong>{r.action}</strong>, sortValue: (r) => r.action },
    { key: 'target', header: 'Target', render: (r) => <span className="muted">{r.target || '—'}</span>, sortValue: (r) => r.target ?? '' },
    { key: 'status', header: 'Status', render: (r) => <StatusBadge value={r.status} />, sortValue: (r) => r.status },
    { key: 'priority', header: 'Priority', render: (r) => <StatusBadge value={r.priority} kind="priority" />, sortValue: (r) => PRIO[r.priority] ?? 0 },
    { key: 'fixability', header: 'Fixability', render: (r) => <span className="pill">{r.fixability}</span>, sortValue: (r) => r.fixability },
    { key: 'confidence', header: 'Confidence', render: (r) => r.confidence, sortValue: (r) => r.confidence },
  ];
  return (
    <div>
      <div className="pagehead"><h1>Remediation</h1></div>
      <p className="muted">Priority is a separate axis from vulnerability severity. HIGH priority ≠ confirmed vulnerability. No automatic patching.</p>
      <ResultGate result={result} emptyTitle="NO REMEDIATION ITEMS">
        {(data) => (
          <>
            <DataTable rows={data.items || []} columns={columns} rowKey={(r) => r.id} onRowClick={setSelected} initialSort={{ key: 'priority', dir: 'desc' }} />
            {selected && <ItemDrawer analysisId={analysisId!} item={selected} onClose={() => setSelected(null)} />}
          </>
        )}
      </ResultGate>
    </div>
  );
}
