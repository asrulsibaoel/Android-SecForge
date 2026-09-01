import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { explainClaim, getValidationClaims } from '../api';
import type { ValidationClaim } from '../api/types';
import { useApi } from '../hooks/useApi';
import { ResultGate } from '../components/States';
import { DataTable, type Column } from '../components/DataTable';
import { StatusBadge } from '../components/StatusBadge';
import { EvidenceDrawer } from '../components/EvidenceDrawer';
import { ExplanationView } from '../components/ExplanationView';

function ClaimDrawer({ analysisId, claim, onClose }: { analysisId: string; claim: ValidationClaim; onClose: () => void }) {
  const explain = useApi(() => explainClaim(analysisId, claim.id), [analysisId, claim.id]);
  return (
    <EvidenceDrawer title={claim.claim_type} evidence={claim.evidence} onClose={onClose}>
      <section>
        <div className="tag-row" style={{ marginBottom: '.6rem' }}>
          <StatusBadge value={claim.validation_state} />
          <span className="pill">confidence: {claim.confidence}</span>
          <span className="pill">sources: {claim.independent_source_count}</span>
        </div>
        <dl className="kv">
          <dt>target</dt><dd>{claim.target}</dd>
          <dt>required</dt><dd>{claim.required_capabilities?.join(', ') || 'UNKNOWN'}</dd>
        </dl>
        {claim.requirements && claim.requirements.length > 0 && (
          <>
            <h4>Requirements</h4>
            <ul>{claim.requirements.map((r, i) => <li key={i}>{r.satisfied ? '✓' : '✗'} {r.requirement}{r.hard ? ' (required)' : ''}</li>)}</ul>
          </>
        )}
        {claim.blockers && claim.blockers.length > 0 && (
          <>
            <h4>Blockers — what is still required</h4>
            <ul>{claim.blockers.map((b, i) => <li key={i}><StatusBadge value={b.blocker} /> <span className="muted">{b.reason}</span></li>)}</ul>
          </>
        )}
        {claim.uncertainty && claim.uncertainty.length > 0 && (
          <ul className="tone-unknown">{claim.uncertainty.map((u, i) => <li key={i}>⚠ {u}</li>)}</ul>
        )}
      </section>
      <section>
        <h3>Why is this claim supported / unverified?</h3>
        <ResultGate result={explain.result} emptyTitle="NO EXPLANATION AVAILABLE">{(p) => <ExplanationView payload={p} />}</ResultGate>
      </section>
    </EvidenceDrawer>
  );
}

export function Validation() {
  const { analysisId } = useParams();
  const { result } = useApi(() => getValidationClaims(analysisId!), [analysisId]);
  const [selected, setSelected] = useState<ValidationClaim | null>(null);
  const columns: Column<ValidationClaim>[] = [
    { key: 'claim', header: 'Claim', render: (r) => <strong>{r.claim_type}</strong>, sortValue: (r) => r.claim_type },
    { key: 'target', header: 'Target', render: (r) => <span className="muted" title={r.target}>{r.target?.slice(0, 40)}</span>, sortValue: (r) => r.target },
    { key: 'state', header: 'State', render: (r) => <StatusBadge value={r.validation_state} />, sortValue: (r) => r.validation_state },
    { key: 'confidence', header: 'Confidence', render: (r) => r.confidence, sortValue: (r) => r.confidence },
    { key: 'sources', header: 'Sources', render: (r) => r.independent_source_count, sortValue: (r) => r.independent_source_count },
    { key: 'requirements', header: 'Requirements', render: (r) => r.requirements?.length ?? 0, sortValue: (r) => r.requirements?.length ?? 0 },
    { key: 'blockers', header: 'Blockers', render: (r) => (r.blockers && r.blockers.length > 0 ? <span className="tone-attention">{r.blockers.map((b) => b.blocker).join(', ')}</span> : <span className="muted">—</span>), sortValue: (r) => r.blockers?.length ?? 0 },
    { key: 'evidence', header: 'Evidence', render: (r) => r.evidence_count, sortValue: (r) => r.evidence_count },
  ];
  return (
    <div>
      <div className="pagehead"><h1>Security Validation</h1></div>
      <p className="muted">Validation ≠ exploitability (which does not exist here). Blockers show what is still required to validate a claim.</p>
      <ResultGate result={result} emptyTitle="NO VALIDATION CLAIMS">
        {(rows) => (
          <>
            <DataTable rows={rows} columns={columns} rowKey={(r) => r.id} onRowClick={setSelected} initialSort={{ key: 'state', dir: 'asc' }} />
            {selected && <ClaimDrawer analysisId={analysisId!} claim={selected} onClose={() => setSelected(null)} />}
          </>
        )}
      </ResultGate>
    </div>
  );
}
