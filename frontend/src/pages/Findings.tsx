import { useMemo, useState } from 'react';
import { useParams } from 'react-router-dom';
import { explainFinding, findingEvidenceChain, getFindings } from '../api';
import type { Finding } from '../api/types';
import { useApi } from '../hooks/useApi';
import { ResultGate } from '../components/States';
import { DataTable, type Column } from '../components/DataTable';
import { StatusBadge } from '../components/StatusBadge';
import { EvidenceDrawer } from '../components/EvidenceDrawer';
import { ExplanationView } from '../components/ExplanationView';

const SEV_ORDER: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function FindingDrawer({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  const explain = useApi(() => explainFinding(finding.id), [finding.id]);
  const chain = useApi(() => findingEvidenceChain(finding.id), [finding.id]);
  return (
    <EvidenceDrawer title={finding.rule_id} evidence={finding.evidence} onClose={onClose}>
      <section>
        <h3>{finding.title}</h3>
        <div className="tag-row" style={{ marginBottom: '.6rem' }}>
          <StatusBadge value={finding.severity} kind="severity" />
          <span className="pill">confidence: {finding.confidence}</span>
          <StatusBadge value={finding.status} />
          <StatusBadge value={finding.runtime_validation_state} />
          {finding.validation && <StatusBadge value={finding.validation.state} />}
        </div>
        {finding.description && <p>{finding.description}</p>}
        <dl className="kv">
          <dt>component</dt><dd>{finding.component || 'UNKNOWN'}</dd>
          <dt>category</dt><dd>{finding.category}</dd>
          <dt>runtime status</dt><dd>{finding.runtime_status || 'UNKNOWN'}</dd>
          <dt>remediation</dt><dd>{finding.remediation || 'UNKNOWN'}</dd>
          <dt>evidence count</dt><dd>{finding.evidence_count}</dd>
        </dl>
      </section>
      <section>
        <h3>Why is this a finding?</h3>
        <ResultGate result={explain.result} emptyTitle="NO EXPLANATION AVAILABLE">
          {(p) => <ExplanationView payload={p} />}
        </ResultGate>
      </section>
      <section>
        <h3>Evidence chain</h3>
        <ResultGate result={chain.result} emptyTitle="NO EVIDENCE CHAIN AVAILABLE">
          {(p) => <ExplanationView payload={p} />}
        </ResultGate>
      </section>
      <p className="muted" style={{ fontSize: '.8rem' }} data-testid="no-exploitable-note">
        No exploitability is asserted. Severity, confidence, validation, and runtime state are distinct axes.
      </p>
    </EvidenceDrawer>
  );
}

function FindingsBody({ rows }: { rows: Finding[] }) {
  const [selected, setSelected] = useState<Finding | null>(null);
  const [f, setF] = useState({ severity: '', status: '', validation: '', runtime: '', component: '', category: '', confidence: '' });

  const opts = useMemo(() => ({
    severity: [...new Set(rows.map((r) => r.severity))].sort(),
    status: [...new Set(rows.map((r) => r.status))].sort(),
    validation: [...new Set(rows.map((r) => r.validation?.state ?? ''))].filter(Boolean).sort(),
    runtime: [...new Set(rows.map((r) => r.runtime_validation_state))].sort(),
    component: [...new Set(rows.map((r) => r.component ?? '').filter(Boolean))].sort(),
    category: [...new Set(rows.map((r) => r.category))].sort(),
    confidence: [...new Set(rows.map((r) => r.confidence))].sort(),
  }), [rows]);

  const filtered = rows.filter((r) =>
    (!f.severity || r.severity === f.severity) &&
    (!f.status || r.status === f.status) &&
    (!f.validation || r.validation?.state === f.validation) &&
    (!f.runtime || r.runtime_validation_state === f.runtime) &&
    (!f.component || r.component === f.component) &&
    (!f.category || r.category === f.category) &&
    (!f.confidence || r.confidence === f.confidence),
  );

  const columns: Column<Finding>[] = [
    { key: 'rule', header: 'Finding', render: (r) => <span title={r.title}><strong>{r.rule_id}</strong><br /><span className="muted">{r.title.slice(0, 48)}</span></span>, sortValue: (r) => r.rule_id },
    { key: 'severity', header: 'Severity', render: (r) => <StatusBadge value={r.severity} kind="severity" />, sortValue: (r) => SEV_ORDER[r.severity] ?? 0 },
    { key: 'confidence', header: 'Confidence', render: (r) => <span className="pill">{r.confidence}</span>, sortValue: (r) => r.confidence },
    { key: 'status', header: 'Status', render: (r) => <StatusBadge value={r.status} />, sortValue: (r) => r.status },
    { key: 'runtime', header: 'Runtime', render: (r) => <StatusBadge value={r.runtime_validation_state} />, sortValue: (r) => r.runtime_validation_state },
    { key: 'validation', header: 'Validation', render: (r) => <StatusBadge value={r.validation?.state} />, sortValue: (r) => r.validation?.state ?? '' },
    { key: 'cve', header: 'CVE', render: (r) => (r.category === 'cve' ? <StatusBadge value="POSSIBLY_AFFECTED" /> : <span className="muted">—</span>), sortValue: (r) => (r.category === 'cve' ? 1 : 0) },
    { key: 'component', header: 'Component', render: (r) => <span className="muted">{r.component || '—'}</span>, sortValue: (r) => r.component ?? '' },
    { key: 'root', header: 'Root cause', render: (r) => (r.root_cause_id ? <span className="pill">linked</span> : <span className="muted">—</span>), sortValue: (r) => (r.root_cause_id ? 1 : 0) },
    { key: 'evidence', header: 'Evidence', render: (r) => r.evidence_count, sortValue: (r) => r.evidence_count },
  ];

  return (
    <div>
      <div className="pagehead"><h1>Findings</h1><span className="muted">{filtered.length} of {rows.length}</span></div>
      <div className="filters">
        {(['severity', 'status', 'validation', 'runtime', 'component', 'category', 'confidence'] as const).map((key) => (
          <label key={key}>
            {key}
            <select value={(f as any)[key]} onChange={(e) => setF({ ...f, [key]: e.target.value })}>
              <option value="">all</option>
              {(opts as any)[key].map((o: string) => <option key={o} value={o}>{o}</option>)}
            </select>
          </label>
        ))}
      </div>
      <DataTable rows={filtered} columns={columns} rowKey={(r) => r.id} onRowClick={setSelected}
        initialSort={{ key: 'severity', dir: 'desc' }} emptyLabel="NO FINDINGS MATCH FILTERS" />
      {selected && <FindingDrawer finding={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

export function Findings() {
  const { analysisId } = useParams();
  const { result } = useApi(() => getFindings(analysisId!), [analysisId]);
  return (
    <ResultGate result={result} emptyTitle="NO FINDINGS" emptyHint="This analysis produced no findings. This is not a safety verdict.">
      {(rows) => <FindingsBody rows={rows} />}
    </ResultGate>
  );
}
