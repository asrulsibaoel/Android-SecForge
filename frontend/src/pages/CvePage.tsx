import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { explainAnalysisCve, getCve } from '../api';
import { useApi } from '../hooks/useApi';
import { ResultGate } from '../components/States';
import { DataTable, type Column } from '../components/DataTable';
import { StatusBadge } from '../components/StatusBadge';
import { EvidenceDrawer } from '../components/EvidenceDrawer';
import { ExplanationView } from '../components/ExplanationView';

function CveDrawer({ analysisId, match, onClose }: { analysisId: string; match: any; onClose: () => void }) {
  const explain = useApi(() => explainAnalysisCve(analysisId, match.match_id || match.id || match.cve_id), [analysisId, match]);
  return (
    <EvidenceDrawer title={match.cve_id} onClose={onClose}>
      <section>
        <div className="tag-row" style={{ marginBottom: '.6rem' }}>
          <StatusBadge value={match.version_state} />
          <StatusBadge value={match.correlation_state} />
          {match.reachability_state && <StatusBadge value={match.reachability_state} />}
        </div>
        <dl className="kv">
          <dt>package</dt><dd>{match.dependency || match.product || 'UNKNOWN'}</dd>
          <dt>installed version</dt><dd>{match.version || 'UNKNOWN'}</dd>
          <dt>fixed version</dt><dd>{match.earliest_fixed_version || 'UNKNOWN'}</dd>
          <dt>identity</dt><dd>{match.identity_confidence || 'UNKNOWN'}</dd>
          <dt>providers</dt><dd>{(match.providers || []).join(', ') || 'UNKNOWN'}</dd>
          <dt>KEV</dt><dd>{match.known_exploited ? 'yes' : 'UNKNOWN/no'}</dd>
          <dt>EPSS</dt><dd>{match.epss_score ?? 'UNKNOWN'}</dd>
        </dl>
      </section>
      <section>
        <h3>Evidence chain</h3>
        <ResultGate result={explain.result} emptyTitle="NO EXPLANATION AVAILABLE">{(p) => <ExplanationView payload={p} />}</ResultGate>
      </section>
      <p className="muted" style={{ fontSize: '.8rem' }}>
        AFFECTED / NOT_AFFECTED / POSSIBLY_AFFECTED / UNKNOWN / PRESENT_UNKNOWN_VERSION are distinct — never a binary
        vulnerable/not-vulnerable verdict.
      </p>
    </EvidenceDrawer>
  );
}

export function CvePage() {
  const { analysisId } = useParams();
  const { result } = useApi(() => getCve(analysisId!), [analysisId]);
  const [selected, setSelected] = useState<any | null>(null);
  const columns: Column<any>[] = [
    { key: 'cve', header: 'CVE', render: (r) => <strong>{r.cve_id}</strong>, sortValue: (r) => r.cve_id },
    { key: 'package', header: 'Package', render: (r) => r.dependency || r.product || '—', sortValue: (r) => r.dependency ?? r.product ?? '' },
    { key: 'version', header: 'Installed', render: (r) => r.version || <StatusBadge value="UNKNOWN" />, sortValue: (r) => r.version ?? '' },
    { key: 'state', header: 'Affected state', render: (r) => <StatusBadge value={r.version_state} />, sortValue: (r) => r.version_state ?? '' },
    { key: 'fixed', header: 'Fixed', render: (r) => r.earliest_fixed_version || <span className="muted">UNKNOWN</span>, sortValue: (r) => r.earliest_fixed_version ?? '' },
    { key: 'reach', header: 'Reachability', render: (r) => <StatusBadge value={r.reachability_state} />, sortValue: (r) => r.reachability_state ?? '' },
    { key: 'sev', header: 'Severity', render: (r) => <StatusBadge value={r.severity} kind="severity" />, sortValue: (r) => r.severity ?? '' },
  ];
  return (
    <div>
      <div className="pagehead"><h1>CVE Intelligence</h1></div>
      <ResultGate result={result}
        emptyTitle="NO CVE MATCHES — STATE UNKNOWN"
        emptyHint="No CVE matches for this analysis. This is not '0 vulnerabilities'; correlation depends on populated intelligence (OFFLINE INTELLIGENCE MODE when no provider data is loaded).">
        {(rows) => (
          <>
            <DataTable rows={rows as any[]} columns={columns} rowKey={(r) => `${r.cve_id}:${r.dependency ?? ''}`} onRowClick={setSelected} />
            {selected && <CveDrawer analysisId={analysisId!} match={selected} onClose={() => setSelected(null)} />}
          </>
        )}
      </ResultGate>
    </div>
  );
}
